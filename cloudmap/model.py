"""Provider-neutral model of a cloud environment: resources (nodes) and edges.

Every provider (AWS, Azure, GCP, ...) emits a ``Graph``. The renderers only ever
see a ``Graph``, so adding a new cloud never touches the diagram code.

Placement is expressed with ``Resource.parent``: containers (account, region,
VPC, subnet, resource group, project ...) hold other resources, which is what
produces the nested "boxes inside boxes" architecture picture.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# Categories drive colour in the renderer; keep the list provider-neutral.
CATEGORIES = (
    "compute", "network", "storage", "database",
    "integration", "edge", "security", "container", "other",
)


_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value: Any) -> str | None:
    """Normalise whatever a cloud API returns for 'created' into a UTC ISO string, or None.

    Accepts datetimes, ISO-8601 / RFC-3339 strings (any fractional precision, with or without a
    zone; naive values are taken as UTC) and epoch numbers (seconds or milliseconds).
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        if isinstance(value, datetime):
            dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        elif isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip())):
            n = float(value)
            if n <= 0:
                return None
            dt = datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
        elif isinstance(value, str):
            m = _ISO.match(value.strip())
            if not m:
                return None
            y, mo, d, hh, mm, ss, tz = m.groups()
            dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0), int(ss or 0), tzinfo=timezone.utc)
            if tz and tz != "Z":
                sign = 1 if tz[0] == "+" else -1
                digits = tz[1:].replace(":", "")
                dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        else:
            return None
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return None


def _json_safe(v: Any) -> Any:
    """Make boto3-style values (datetime, Decimal, bytes ...) JSON friendly."""
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, dict):
        return {str(k): _json_safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_json_safe(x) for x in v]
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


def to_iso(v: Any) -> str | None:
    """Normalize any provider's timestamp to a UTC ISO-8601 string (or None).

    Thin alias of :func:`parse_time`, kept because providers and ``Resource`` call it by this name.
    ``parse_time`` copes with nanosecond fractions and 'Z' suffixes on every supported Python.
    """
    return parse_time(v)


@dataclass
class Resource:
    id: str
    type: str                      # e.g. "aws.ec2.instance"
    name: str
    parent: str | None = None      # id of the containing resource
    category: str = "other"
    region: str | None = None
    container: bool = False        # True => drawn as a box that holds children
    arn: str | None = None         # native global identifier, used to resolve edges
    prune_empty: bool = False      # drop this container if nothing ended up inside
    created: Any = None            # creation time (any format; normalized to ISO UTC)
    props: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.created = to_iso(self.created)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "name": self.name,
            "parent": self.parent, "category": self.category,
            "region": self.region, "container": self.container,
            "created": self.created,
            "props": {k: _json_safe(v) for k, v in self.props.items() if v not in (None, "", [], {})},
            "tags": {str(k): str(v) for k, v in self.tags.items()},
        }


@dataclass(frozen=True)
class Edge:
    source: str   # a resource id *or* an ARN; resolved in Graph.finalize()
    target: str
    kind: str = "link"
    label: str = ""


class Graph:
    """Thread-safe collection of resources and edges."""

    def __init__(self, provider: str, account: str = "", type_info: dict | None = None,
                 account_label: str = "Account"):
        self.provider = provider
        self.account = account
        self.account_label = account_label     # "Account" (AWS), "Tenant" (Azure), "Project" (GCP)
        self.resources: dict[str, Resource] = {}
        self.edges: list[Edge] = []
        self.arn_index: dict[str, str] = {}   # arn / alias -> resource id
        self.dns_index: dict[str, str] = {}   # dns name -> resource id
        self.warnings: list[str] = []
        self.type_info: dict[str, dict[str, str]] = dict(type_info or {})
        self.generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._lock = threading.RLock()

    # -- building ---------------------------------------------------------
    def add(self, res: Resource) -> Resource:
        with self._lock:
            info = self.type_info.get(res.type)
            if info and res.category == "other":
                res.category = info["category"]
            self.resources[res.id] = res
            if res.arn:
                self.arn_index[res.arn] = res.id
            return res

    def alias(self, native_id: str, resource_id: str) -> None:
        with self._lock:
            self.arn_index[native_id] = resource_id

    def link(self, source: str, target: str, kind: str = "link", label: str = "") -> None:
        with self._lock:
            self.edges.append(Edge(source, target, kind, label))

    def warn(self, message: str) -> None:
        with self._lock:
            if message not in self.warnings:
                self.warnings.append(message)

    def remove(self, ids) -> None:
        """Delete resources; edges that touched them are dropped in finalize()."""
        with self._lock:
            for rid in ids:
                self.resources.pop(rid, None)

    def snapshot(self) -> list[Resource]:
        with self._lock:
            return list(self.resources.values())

    # -- finishing --------------------------------------------------------
    def finalize(self) -> "Graph":
        with self._lock:
            # 1. resolve ARN/alias endpoints, drop dangling + duplicate edges
            seen: set[Edge] = set()
            clean: list[Edge] = []
            for e in self.edges:
                s = e.source if e.source in self.resources else self.arn_index.get(e.source)
                t = e.target if e.target in self.resources else self.arn_index.get(e.target)
                if not s or not t or s == t:
                    continue
                edge = Edge(s, t, e.kind, e.label)
                if edge not in seen:
                    seen.add(edge)
                    clean.append(edge)
            self.edges = clean

            # 2. orphaned parents become roots
            for r in self.resources.values():
                if r.parent and r.parent not in self.resources:
                    r.parent = None

            # 3. prune containers (e.g. regions) with nothing inside, repeat to fixpoint
            while True:
                has_child = {r.parent for r in self.resources.values() if r.parent}
                doomed = [r.id for r in self.resources.values()
                          if r.prune_empty and r.id not in has_child]
                if not doomed:
                    break
                for rid in doomed:
                    del self.resources[rid]
            live = set(self.resources)
            self.edges = [e for e in self.edges if e.source in live and e.target in live]
        return self

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            used = {r.type for r in self.resources.values()}
            return {
                "provider": self.provider,
                "account": self.account,
                "account_label": self.account_label,
                "generated": self.generated,
                "resources": [r.to_dict() for r in self.resources.values()],
                "edges": [
                    {"source": e.source, "target": e.target, "kind": e.kind, "label": e.label}
                    for e in self.edges
                ],
                "types": {t: self.type_info[t] for t in used if t in self.type_info},
                "warnings": list(self.warnings),
            }
