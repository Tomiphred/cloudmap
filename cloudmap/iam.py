"""Cloud-neutral helpers for reading IAM-style policy documents (AWS today; the same shapes recur
in resource policies on other clouds).

What this module deliberately is *not*: a policy simulator. Only ``Allow`` statements are turned into
access. ``Deny`` statements, permission boundaries, SCPs and session policies are not evaluated, so what
the diagram shows is what a policy *grants* - an upper bound of effective access.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import unquote

# Order matters: it is the order levels are printed in a label (strongest first).
LEVEL_ORDER = ("full", "permissions", "write", "read")

_READ_PREFIXES = ("get", "list", "describe", "batchget", "batchdescribe", "query", "scan", "head", "select",
                  "lookup", "search", "view", "read", "preview", "check", "test",
                  "decrypt", "encrypt", "reencrypt", "generatedatakey", "verify")
# Actions that change who can do what (privilege escalation / policy edits), beyond the whole iam:/sts: services.
_PERMISSION_ACTIONS = {
    "kms:creategrant", "kms:putkeypolicy", "kms:retiregrant", "kms:revokegrant",
    "s3:putbucketpolicy", "s3:putbucketacl", "s3:putobjectacl", "s3:deletebucketpolicy",
    "secretsmanager:putresourcepolicy", "secretsmanager:deleteresourcepolicy",
    "lambda:addpermission", "lambda:removepermission", "sqs:setqueueattributes", "sns:settopicattributes",
    "ec2:modifyinstanceattribute", "ssm:sendcommand", "ssm:startsession",
}


def as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def load_doc(doc: Any) -> dict:
    """Accept a dict, a JSON string, or a URL-encoded JSON string (how IAM returns some documents)."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, (bytes, bytearray)):
        doc = doc.decode("utf-8", "replace")
    if isinstance(doc, str) and doc.strip():
        text = doc.strip()
        if text.startswith("%7B") or text.startswith("%7b"):
            text = unquote(text)
        try:
            out = json.loads(text)
            return out if isinstance(out, dict) else {}
        except ValueError:
            return {}
    return {}


def statements(doc: Any) -> list[dict]:
    """Normalise a policy document into plain dicts:
    effect, actions, resources, not_action, not_resource, conditional, principals ({type: [values]})."""
    out: list[dict] = []
    for st in as_list(load_doc(doc).get("Statement")):
        if not isinstance(st, dict):
            continue
        principal = st.get("Principal")
        if principal == "*":
            principals = {"AWS": ["*"]}
        elif isinstance(principal, dict):
            principals = {str(k): [str(x) for x in as_list(v)] for k, v in principal.items()}
        else:
            principals = {}
        out.append({
            "effect": str(st.get("Effect", "Allow")),
            "actions": [str(a) for a in as_list(st.get("Action") if "Action" in st else st.get("NotAction"))],
            "not_action": "NotAction" in st,
            "resources": [str(r) for r in as_list(st.get("Resource") if "Resource" in st else st.get("NotResource"))],
            "not_resource": "NotResource" in st,
            "conditional": bool(st.get("Condition")),
            "principals": principals,
        })
    return out


def service_of(action: str) -> str:
    a = action.strip().lower()
    return "*" if a == "*" else a.split(":", 1)[0]


def level_of(actions: Iterable[str]) -> list[str]:
    """Classify actions into full / permissions / write / read (strongest first)."""
    levels: set[str] = set()
    for raw in actions:
        a = raw.strip().lower()
        if a == "*" or a.endswith(":*"):
            levels.add("full")
            continue
        service, _, verb = a.partition(":")
        if a in _PERMISSION_ACTIONS or (service in ("iam", "sts") and not verb.startswith(_READ_PREFIXES)):
            levels.add("permissions")
        elif verb.startswith(_READ_PREFIXES):
            levels.add("read")
        else:
            levels.add("write")
    return [lv for lv in LEVEL_ORDER if lv in levels]


def summarize_actions(actions: Iterable[str], limit: int = 3) -> str:
    acts = sorted(set(actions))
    shown = ", ".join(acts[:limit])
    return shown + (f" +{len(acts) - limit}" if len(acts) > limit else "")


_GLOB_CACHE: dict[str, re.Pattern] = {}


def glob_regex(pattern: str) -> re.Pattern:
    """IAM-style wildcard ('*' any run, '?' one char) -> compiled regex (case-sensitive, full match)."""
    rx = _GLOB_CACHE.get(pattern)
    if rx is None:
        rx = re.compile("".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern), re.S)
        _GLOB_CACHE[pattern] = rx
    return rx


def has_wildcard(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern


def match_keys(pattern: str, keys: Iterable[str]) -> list[str]:
    """Which of ``keys`` does an IAM resource pattern select?"""
    if not has_wildcard(pattern):
        return [pattern] if pattern in set(keys) else []
    rx = glob_regex(pattern)
    return [k for k in keys if rx.fullmatch(k)]
