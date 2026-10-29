"""GCP identity & security layer: service accounts, IAM bindings, Cloud KMS, Secret Manager.

``add_identity()`` is a pure function over Cloud Asset Inventory dicts. Two kinds of asset feed it:
  * RESOURCE assets  - service accounts (and their keys), KMS key rings/keys, secrets, plus every other
                       resource, scanned for CMEK / secret / service-account references
  * IAM_POLICY assets - who holds which role on which resource (``policies``; fetched by a second call)

What is drawn
    member   --access--> resource   an IAM binding (role + level); members are users, groups, domains,
                                    service accounts, allUsers / allAuthenticatedUsers
    resource --identity--> SA       runs as this service account (VM, function, Cloud Run, GKE nodes)
    key      --encrypts--> resource customer-managed encryption key (CMEK) referenced by the resource
    resource --uses--> secret       Secret Manager secret referenced by the resource

Secret *values* are never read (Cloud Asset returns metadata only), and service-account key material is
never present. Like AWS and Azure this shows what is *granted*: IAM deny policies, conditions and group
membership are not evaluated.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable

from ..model import Graph, Resource

TYPES = {
    "gcp.iam":                             {"label": "Identity & Access (IAM)", "short": "IAM", "category": "container"},
    "iam.googleapis.com/ServiceAccount":   {"label": "Service Account", "short": "SA", "category": "security"},
    "gcp.iam.user":                        {"label": "Google User", "short": "USR", "category": "security"},
    "gcp.iam.group":                       {"label": "Google Group", "short": "GRP", "category": "security"},
    "gcp.iam.domain":                      {"label": "Domain", "short": "DOM", "category": "security"},
    "gcp.iam.sa-external":                 {"label": "Service Account (other project / Google-managed)", "short": "SA", "category": "security"},
    "gcp.iam.public":                      {"label": "Public (anyone)", "short": "ALL", "category": "security"},
    "gcp.iam.other":                       {"label": "Principal", "short": "PRN", "category": "security"},
    "cloudkms.googleapis.com/KeyRing":     {"label": "KMS Key Ring", "short": "KR", "category": "container"},
    "cloudkms.googleapis.com/CryptoKey":   {"label": "KMS Key", "short": "KEY", "category": "security"},
    "secretmanager.googleapis.com/Secret": {"label": "Secret", "short": "SEC", "category": "security"},
}
ASSET_TYPES = ["iam.googleapis.com/ServiceAccount", "iam.googleapis.com/ServiceAccountKey",
               "cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey", "secretmanager.googleapis.com/Secret"]
# asset types that can carry IAM policies we want, beyond the ones already in the scan
POLICY_EXTRA_TYPES = ["cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Organization"]
MAX_BINDING_EDGES = 6000
# identity-layer assets that are never the *subject* of a CMEK / secret / runs-as reference
_NO_SCAN = {"iam.googleapis.com/ServiceAccount", "iam.googleapis.com/ServiceAccountKey",
            "cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey"}
PUBLIC = ("allusers", "allauthenticatedusers")

_KMS_KEY = re.compile(r"projects/[^/\s\"]+/locations/[^/\s\"]+/keyRings/[^/\s\"]+/cryptoKeys/[^/\s\"]+", re.I)
_SECRET = re.compile(r"projects/([^/\s\"]+)/secrets/([^/\s\"]+)", re.I)


def _norm(url: Any) -> str:
    s = str(url or "")
    i = s.find("projects/")
    return s[i:] if i >= 0 else s.rstrip("/")


def _last(url: Any) -> str:
    return str(url or "").rstrip("/").split("/")[-1]


def _data(a: dict) -> dict:
    return (a.get("resource") or {}).get("data") or {}


def role_level(role: str) -> str | None:
    """full / permissions / write / read - from the role's name. Custom roles can't be judged: None."""
    r = role.lower()
    if r.startswith(("projects/", "organizations/")):
        return None
    short = r.removeprefix("roles/")
    last = short.rsplit(".", 1)[-1]
    if short in ("owner",) or last == "owner":
        return "full"
    if short.startswith("iam.") and not last.endswith(("viewer", "reader")) or last in ("projectiamadmin", "organizationadmin", "securityadmin"):
        return "permissions"                       # who-can-do-what, incl. impersonation (serviceAccountUser/TokenCreator)
    if last.endswith("admin") or last == "admin":
        return "full"
    if short == "editor":
        return "write"
    if short == "viewer" or last.endswith(("viewer", "reader", "accessor", "lister", "getter", "decrypter", "verifier", "client", "browser")):
        return "read"
    return "write"


def add_identity(g: Graph, assets: list[dict], policies: list[dict] | None, *, proj_of: Callable[[dict], str],
                 project_ids: dict[str, str], ensure_project: Callable[[str], str],
                 ensure_region: Callable[[str, str | None], str], skip_types: set[str]) -> None:
    g.type_info.update(TYPES)
    by_type: dict[str, list[dict]] = {}
    for a in assets:
        by_type.setdefault(a.get("asset_type", ""), []).append(a)

    boxes: dict[str, str] = {}

    def iam_box(proj: str | None) -> str | None:
        key = proj or "*"
        if key not in boxes:
            bid = f"iam:{proj}" if proj else "iam:principals"
            g.add(Resource(id=bid, type="gcp.iam", name="Identity & Access (IAM)" if proj else "Principals (users, groups, domains)",
                           parent=ensure_project(proj) if proj else None, container=True, prune_empty=True))
            boxes[key] = bid
        return boxes[key]

    # ---- service accounts (+ count of user-managed keys, a classic audit item) -------------------------
    sa_by_email: dict[str, str] = {}
    key_ident: dict[str, str] = {}                       # email or unique id -> email
    for a in by_type.get("iam.googleapis.com/ServiceAccount", []):
        d, rid = _data(a), _norm(a["name"])
        email = d.get("email") or _last(rid)
        proj = proj_of(a)
        g.add(Resource(id=rid, type="iam.googleapis.com/ServiceAccount", name=email.split("@")[0], parent=iam_box(proj),
                       arn=f"projects/{proj}/serviceAccounts/{email}",
                       props={k: v for k, v in {"email": email, "display_name": d.get("displayName"), "description": d.get("description"),
                                                "disabled": d.get("disabled") or None, "unique_id": d.get("uniqueId")}.items() if v}))
        sa_by_email[email.lower()] = rid
        key_ident[email.lower()] = email.lower()
        if d.get("uniqueId"):
            key_ident[str(d["uniqueId"])] = email.lower()
    keys: dict[str, list[str]] = {}
    for a in by_type.get("iam.googleapis.com/ServiceAccountKey", []):
        d = _data(a)
        if str(d.get("keyType", "")).upper() != "USER_MANAGED":
            continue
        m = re.search(r"serviceAccounts/([^/]+)/keys/", _norm(a["name"]) or d.get("name", ""))
        email = key_ident.get((m.group(1) if m else "").lower())
        if email and d.get("validAfterTime"):
            keys.setdefault(email, []).append(str(d["validAfterTime"]))
        elif email:
            keys.setdefault(email, [])
    for email, created in keys.items():
        res = g.resources.get(sa_by_email.get(email, ""))
        if res is not None:
            res.props["user_managed_keys"] = len(keys[email]) or 1
            if created:
                res.props["oldest_key_created"] = min(created)

    # ---- Cloud KMS ---------------------------------------------------------------------------------
    for a in by_type.get("cloudkms.googleapis.com/KeyRing", []):
        d, rid = _data(a), _norm(a["name"])
        loc = (re.search(r"/locations/([^/]+)/", "/" + rid) or [None, "global"])[1]
        g.add(Resource(id=rid, type="cloudkms.googleapis.com/KeyRing", name=_last(rid), region=loc, container=True,
                       parent=ensure_region(proj_of(a), loc), created=d.get("createTime"), prune_empty=True))
    for a in by_type.get("cloudkms.googleapis.com/CryptoKey", []):
        d, rid = _data(a), _norm(a["name"])
        ring = rid.split("/cryptoKeys/")[0]
        loc = (re.search(r"/locations/([^/]+)/", "/" + rid) or [None, "global"])[1]
        tmpl = d.get("versionTemplate") or {}
        rot = d.get("rotationPeriod")
        props = {"purpose": d.get("purpose"), "algorithm": tmpl.get("algorithm"), "protection": tmpl.get("protectionLevel"),
                 "state": (d.get("primary") or {}).get("state"),
                 "rotation": f"every {int(str(rot).rstrip('s')) // 86400} days" if rot else "no automatic rotation",
                 "next_rotation": d.get("nextRotationTime"), "key_ring": _last(ring)}
        g.add(Resource(id=rid, type="cloudkms.googleapis.com/CryptoKey", name=_last(rid), region=loc,
                       parent=ring if ring in g.resources else ensure_region(proj_of(a), loc), created=d.get("createTime"),
                       tags={k: str(v) for k, v in (d.get("labels") or {}).items()},
                       props={k: v for k, v in props.items() if v is not None}))

    # ---- Secret Manager (metadata only) ----------------------------------------------------------------
    for a in by_type.get("secretmanager.googleapis.com/Secret", []):
        d, rid = _data(a), _norm(a["name"])
        proj = proj_of(a)
        repl = d.get("replication") or {}
        if "userManaged" in repl:
            where = [(r.get("location") or "") for r in (repl["userManaged"].get("replicas") or [])]
            loc, repl_text = (where[0] if len(where) == 1 else "global"), "user-managed: " + ", ".join(where)
        else:
            loc, repl_text = "global", "automatic"
        g.add(Resource(id=rid, type="secretmanager.googleapis.com/Secret", name=_last(rid), region=loc,
                       parent=ensure_region(proj, loc), created=d.get("createTime"), arn=f"projects/{proj}/secrets/{_last(rid)}",
                       tags={k: str(v) for k, v in (d.get("labels") or {}).items()},
                       props={k: v for k, v in {"replication": repl_text, "rotation": "scheduled" if d.get("rotation") else "none",
                                                "expires": d.get("expireTime"), "ttl": d.get("ttl")}.items() if v}))

    # ---- references found inside other resources ---------------------------------------------------------
    for a in assets:
        atype = a.get("asset_type", "")
        rid = _norm(a["name"])
        if atype in _NO_SCAN or rid not in g.resources or atype in skip_types:
            continue
        d = _data(a)
        proj = proj_of(a)
        blob = json.dumps(d, default=str)
        if "cryptoKeys/" in blob:
            for kref in {m.group(0) for m in _KMS_KEY.finditer(blob)}:
                g.link(_norm(kref), rid, "encrypts", "customer-managed key (CMEK)")
        for secret in _secret_refs(d, proj, _SECRET.findall(blob) if "/secrets/" in blob else []):
            g.link(rid, secret, "uses", "secret")
        for email in _service_accounts(atype, d):
            node = sa_by_email.get(email.lower())
            if node:
                g.link(rid, node, "identity", "runs as")

    # ---- IAM policy bindings ------------------------------------------------------------------------------
    if policies:
        _bindings(g, policies, sa_by_email=sa_by_email, proj_ids=project_ids, iam_box=iam_box)


def _secret_refs(d: dict, proj: str, regex_hits: list[tuple[str, str]]) -> set[str]:
    """Secret Manager references: full 'projects/x/secrets/y' paths, Cloud Functions' {secret, projectId} pairs,
    and Cloud Run's secretKeyRef {name} (same project)."""
    out = {f"projects/{p}/secrets/{s}" for p, s in regex_hits}

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            if isinstance(o.get("secret"), str) and (o.get("projectId") or o.get("project")):
                out.add(f"projects/{o.get('projectId') or o.get('project')}/secrets/{_last(o['secret'])}")
            ref = o.get("secretKeyRef")
            if isinstance(ref, dict) and ref.get("name"):
                out.add(f"projects/{proj}/secrets/{_last(ref['name'])}")
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(d)
    return out


def _service_accounts(atype: str, d: dict) -> list[str]:
    emails: list[str] = []
    if atype == "compute.googleapis.com/Instance":
        emails += [s.get("email") for s in d.get("serviceAccounts") or []]
    elif atype.startswith("cloudfunctions.googleapis.com/"):
        emails += [d.get("serviceAccountEmail"), (d.get("serviceConfig") or {}).get("serviceAccountEmail")]
    elif atype == "run.googleapis.com/Service":
        emails += [(((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("serviceAccountName"),
                   ((d.get("template") or {}).get("serviceAccount"))]
    elif atype == "container.googleapis.com/Cluster":
        emails += [(d.get("nodeConfig") or {}).get("serviceAccount")]
        emails += [(p.get("config") or {}).get("serviceAccount") for p in d.get("nodePools") or []]
    return [e for e in dict.fromkeys(emails) if isinstance(e, str) and "@" in e]


def _bindings(g: Graph, policies: Iterable[dict], *, sa_by_email: dict[str, str], proj_ids: dict[str, str],
              iam_box: Callable[[str | None], str | None]) -> None:
    members: dict[str, str] = {}

    def member_node(raw: str) -> tuple[str, dict]:
        deleted = raw.startswith("deleted:")
        m = raw.removeprefix("deleted:").split("?uid=")[0]
        kind, _, ident = m.partition(":")
        k = kind.lower()
        extra: dict = {"deleted": True} if deleted else {}
        if k == "serviceaccount" and ident.lower() in sa_by_email and not deleted:
            return sa_by_email[ident.lower()], {}
        if m.lower() in PUBLIC:
            return members.setdefault(m.lower(), _mk(m.lower(), "gcp.iam.public", "Anyone on the internet" if m.lower() == "allusers" else "Anyone with a Google account",
                                                       {"public": True})), {}
        tp = {"user": "gcp.iam.user", "group": "gcp.iam.group", "domain": "gcp.iam.domain",
              "serviceaccount": "gcp.iam.sa-external"}.get(k, "gcp.iam.other")
        name = ident or m
        if k == "serviceaccount":
            name = ident.split("@")[0] + " (" + ident.split("@")[-1].split(".")[0] + ")"
        key = ("deleted:" if deleted else "") + m.lower()
        if key not in members:
            members[key] = _mk(key, tp, name + (" [deleted]" if deleted else ""), {"identity": ident or m, **extra})
        return members[key], {}

    def _mk(key: str, tp: str, name: str, props: dict) -> str:
        nid = f"member:{key}"
        g.add(Resource(id=nid, type=tp, name=name, parent=iam_box(None), props=props))
        return nid

    n = 0
    for pol in policies:
        name = str(pol.get("name", ""))
        bindings = (pol.get("iam_policy") or {}).get("bindings") or []
        target, label = _policy_target(name, proj_ids)
        for b in bindings:
            role = b.get("role", "")
            level = role_level(role)
            cond = bool(b.get("condition"))
            for raw in b.get("members") or []:
                node, _ = member_node(str(raw))
                res = g.resources[node]
                text = f"{role} on {label}"
                roles = res.props.setdefault("roles", [])
                if text not in roles:
                    roles.append(text)
                if level == "full" and role.lower() in ("roles/owner",) and (target is None or target.startswith("proj:")):
                    res.props["admin_access"] = True
                if str(raw).lower() in PUBLIC and target:
                    tgt = g.resources.get(target) or g.resources.get(g.arn_index.get(target, ""))
                    if tgt is not None:
                        tgt.props.setdefault("public_access", [])
                        if role not in tgt.props["public_access"]:
                            tgt.props["public_access"].append(role)
                if not target:
                    continue
                if n >= MAX_BINDING_EDGES:
                    g.warn(f"More than {MAX_BINDING_EDGES} IAM bindings - the rest are listed on the members but not drawn.")
                    continue
                n += 1
                g.link(node, target, "access", f"{role}" + (f" ({level})" if level else "") + (" [conditional]" if cond else ""))


def _policy_target(name: str, proj_ids: dict[str, str]) -> tuple[str | None, str]:
    """IAM_POLICY asset name -> (graph node id / alias, human label). Organisation and folder policies have no node."""
    m = re.search(r"cloudresourcemanager\.googleapis\.com/projects/([^/]+)$", name)
    if m:
        pid = proj_ids.get(m.group(1), m.group(1))
        return f"proj:{pid}", f"project {pid}"
    if "/organizations/" in name:
        return None, "organization"
    if "/folders/" in name:
        return None, "folder"
    return _norm(name), _last(name)
