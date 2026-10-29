"""Azure identity & security layer: managed identities, RBAC role assignments, Key Vault keys/secrets.

Same split as the rest of the Azure provider: ``add_identity()`` is a pure function over plain dicts (so it
is testable offline); ``fetch_identity()`` is the only code that talks to Azure.

What is drawn
    principal --access--> scope        role assignments (scope = management group / subscription / RG / resource)
    resource  --identity--> identity   user-assigned managed identity attached to a resource
    vault     --contains--> key|secret Key Vault keys and secrets (metadata only - never values)
    key       --encrypts--> resource   customer-managed keys found in a resource's properties
    resource  --uses--> secret         Key Vault secret URIs found in a resource's properties
    principal --access--> vault        legacy Key Vault access policies

Like AWS, this shows what is *granted*. Deny assignments, PIM eligibility, conditions and Entra group
membership (who is in a group that holds a role) are not evaluated.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable

from ..model import Graph, Resource

TYPES = {
    "azure.iam":               {"label": "Identity & Access (RBAC)", "short": "IAM", "category": "container"},
    "azure.identity.managed":  {"label": "Managed Identity", "short": "MI", "category": "security"},
    "azure.identity.user":     {"label": "Entra User", "short": "USR", "category": "security"},
    "azure.identity.group":    {"label": "Entra Group", "short": "GRP", "category": "security"},
    "azure.identity.sp":       {"label": "Service Principal", "short": "SP", "category": "security"},
    "azure.identity.unknown":  {"label": "Principal", "short": "PRN", "category": "security"},
    "azure.keyvault.key":      {"label": "Key Vault Key", "short": "KEY", "category": "security"},
    "azure.keyvault.secret":   {"label": "Key Vault Secret", "short": "SEC", "category": "security"},
}
MAX_ASSIGNMENT_EDGES = 6000

ASSIGNMENTS_KQL = ("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' "
                   "| project id, name, type, properties")
DEFINITIONS_KQL = ("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' "
                   "| project id, name, type, properties")

# Fallback when role definitions can't be read: a handful of well-known built-in roles (GUID -> name, level).
_BUILTIN = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": ("Owner", "full"),
    "b24988ac-6180-42a0-ab88-20f7382dd24c": ("Contributor", "write"),
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": ("Reader", "read"),
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": ("User Access Administrator", "permissions"),
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": ("Storage Blob Data Contributor", "write"),
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": ("Storage Blob Data Reader", "read"),
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": ("Key Vault Administrator", "full"),
    "4633458b-17de-408a-b874-0445c86b69e6": ("Key Vault Secrets User", "read"),
    "7f951dda-4ed3-4680-a7ca-43fe172d538d": ("AcrPull", "read"),
}
_LEVEL_ORDER = ("full", "permissions", "write", "read")
_PTYPE = {"user": "azure.identity.user", "group": "azure.identity.group",
          "serviceprincipal": "azure.identity.sp", "foreigngroup": "azure.identity.group"}

_KV_KEY = re.compile(r"https://([a-z0-9-]+)\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)(?::443)?/keys/([A-Za-z0-9-]+)", re.I)
_KV_SECRET = re.compile(r"https://([a-z0-9-]+)\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)(?::443)?/secrets/([A-Za-z0-9-]+)", re.I)


def _l(v: Any) -> str:
    return str(v or "").lower()


def role_level(name: str | None, permissions: Iterable[dict] | None) -> str:
    """full / permissions / write / read, from a role definition's permission blocks."""
    actions: list[str] = []
    not_actions: list[str] = []
    for blk in permissions or []:
        actions += [_l(a) for a in (blk.get("actions") or []) + (blk.get("dataActions") or [])]
        not_actions += [_l(a) for a in blk.get("notActions") or []]
    if not actions:
        return {"owner": "full", "contributor": "write", "reader": "read"}.get(_l(name), "read")
    if "*" in actions:
        # Contributor is '*' minus the Authorization write/delete actions - it cannot change who has access
        return "write" if any(n.startswith("microsoft.authorization/") for n in not_actions) else "full"
    if any(a.startswith("microsoft.authorization/") and not a.endswith("/read") for a in actions):
        return "permissions"
    return "write" if any(not _is_read(a) for a in actions) else "read"


def _is_read(action: str) -> bool:
    """'.../secrets/getSecret/action' and '.../read' are reads; '.../write', '.../delete', '*' are not."""
    parts = action.split("/")
    verb = parts[-2] if parts[-1] == "action" and len(parts) > 1 else parts[-1]
    return verb.startswith(("read", "get", "list", "view"))


def _scope_target(scope: str) -> tuple[str | None, str]:
    """Role-assignment scope -> (graph node id or None, short human label)."""
    parts = [x for x in scope.strip("/").split("/") if x]
    low = [x.lower() for x in parts]
    if scope.strip("/") == "" or "managementgroups" in low:
        return None, "management group" if "managementgroups" in low else "tenant root"
    sub = parts[1] if len(parts) >= 2 and low[0] == "subscriptions" else ""
    if len(parts) == 2:
        return f"sub:{sub.lower()}", "subscription"
    if len(parts) == 4 and low[2] == "resourcegroups":
        return f"rg:{sub.lower()}:{parts[3].lower()}", f"resource group {parts[3]}"
    return _l(scope), parts[-1] if parts else scope


def apply_principal_names(names: dict[str, dict], graph_objects: Iterable[dict]) -> None:
    """Fold a Microsoft Graph ``getByIds`` response into ``{object id: {name, type}}``."""
    for o in graph_objects:
        oid = _l(o.get("id"))
        if not oid:
            continue
        kind = str(o.get("@odata.type", "")).rsplit(".", 1)[-1].lower()
        names[oid] = {"name": o.get("displayName") or o.get("userPrincipalName") or oid,
                      "type": {"user": "User", "group": "Group", "serviceprincipal": "ServicePrincipal"}.get(kind, "")}


def add_identity(g: Graph, rows: list[dict], identity: dict | None, *, root: str | None,
                 ensure_rg: Callable[[str, str, str | None], str], skip_types: set[str]) -> None:
    identity = identity or {}
    g.type_info.update(TYPES)
    by_id: dict[str, dict] = {_l(r.get("id")): r for r in rows}
    names: dict[str, dict] = {_l(k): v for k, v in (identity.get("names") or {}).items()}

    # ---- 1. managed identities, and which principal id belongs to which graph node --------------
    principal_node: dict[str, str] = {}
    for r in rows:
        rid = _l(r.get("id"))
        if _l(r.get("type")) == "microsoft.managedidentity/userassignedidentities":
            p = r.get("properties") or {}
            g.add(Resource(id=rid, type="azure.identity.managed", name=r["name"], region=r.get("location"),
                           parent=ensure_rg(r["subscriptionId"], r["resourceGroup"], r.get("location")),
                           arn=rid, created=r.get("createdTime"), tags=r.get("tags") or {},
                           props={k: v for k, v in {"kind": "user-assigned", "principal_id": p.get("principalId"),
                                                    "client_id": p.get("clientId")}.items() if v}))
            if p.get("principalId"):
                principal_node[_l(p["principalId"])] = rid
    for r in rows:
        ident = r.get("identity") or {}
        rid = _l(r.get("id"))
        if not ident or rid not in g.resources:
            continue
        if ident.get("principalId"):                                  # system-assigned: the resource itself is the principal
            principal_node.setdefault(_l(ident["principalId"]), rid)
            g.resources[rid].props["identity"] = "system-assigned"
        uai = list((ident.get("userAssignedIdentities") or {}).keys())
        for u in uai:
            g.link(rid, _l(u), "identity", "user-assigned identity")
        if uai:
            g.resources[rid].props["identity"] = ("system + user-assigned" if ident.get("principalId") else "user-assigned")

    iam_box = {"id": None}

    def principal(pid: str, ptype: str | None) -> str:
        pid = _l(pid)
        if pid in principal_node:
            return principal_node[pid]
        if iam_box["id"] is None:
            iam_box["id"] = f"iam:{_l(g.account) or 'tenant'}"
            g.add(Resource(id=iam_box["id"], type="azure.iam", name="Identity & Access (RBAC)", parent=root,
                           container=True, prune_empty=True))
        info = names.get(pid) or {}
        kind = _PTYPE.get(_l(info.get("type") or ptype), "azure.identity.unknown")
        label = {"azure.identity.user": "user", "azure.identity.group": "group", "azure.identity.sp": "service principal"}.get(kind, "principal")
        node = f"principal:{pid}"
        g.add(Resource(id=node, type=kind, name=info.get("name") or f"{label} {pid[:8]}…", parent=iam_box["id"],
                       props={"object_id": pid, **({} if info.get("name") else {"name_unresolved": True})}))
        principal_node[pid] = node
        return node

    def note(node: str, key: str, text: str) -> None:
        res = g.resources.get(node)
        if res is not None and text not in res.props.setdefault(key, []):
            res.props[key].append(text)

    # ---- 2. role definitions -----------------------------------------------------------------------
    roles: dict[str, tuple[str, str]] = {}
    for d in identity.get("definitions") or []:
        p = d.get("properties") or {}
        roles[_l(d.get("id"))] = (p.get("roleName") or d.get("name"), role_level(p.get("roleName"), p.get("permissions")))

    # ---- 3. role assignments: principal -> scope -------------------------------------------------
    n_edges = 0
    for a in identity.get("assignments") or []:
        p = a.get("properties") or {}
        if not p.get("principalId"):
            continue
        rdef = _l(p.get("roleDefinitionId"))
        name, level = roles.get(rdef) or _BUILTIN.get(rdef.rsplit("/", 1)[-1], (rdef.rsplit("/", 1)[-1][:8] + "…", "read"))
        node = principal(p["principalId"], p.get("principalType"))
        target, short = _scope_target(str(p.get("scope") or ""))
        note(node, "roles", f"{name} on {short}")
        if level == "full" and (target is None or target.startswith("sub:")):
            g.resources[node].props["admin_access"] = True
        if target and target != node:
            if n_edges >= MAX_ASSIGNMENT_EDGES:
                g.warn(f"More than {MAX_ASSIGNMENT_EDGES} role assignments - the rest are listed on the principals but not drawn.")
                continue
            n_edges += 1
            g.link(node, target, "access", f"{name} ({level})")

    # ---- 4. Key Vault: access policies, keys, secrets ------------------------------------------------
    vault_by_host: dict[str, str] = {}
    for r in rows:
        if _l(r.get("type")) == "microsoft.keyvault/vaults" and _l(r.get("id")) in g.resources:
            p = r.get("properties") or {}
            host = re.sub(r"^https?://|[:/].*$", "", str(p.get("vaultUri") or "")).lower() or f"{_l(r.get('name'))}.vault.azure.net"
            vault_by_host[host.split(".")[0]] = _l(r["id"])
            for pol in p.get("accessPolicies") or []:
                if not pol.get("objectId"):
                    continue
                perms = pol.get("permissions") or {}
                flat = [f"{k}:{x}" for k in ("keys", "secrets", "certificates", "storage") for x in perms.get(k) or []]
                level = "write" if any(x.split(":")[1].lower() not in ("get", "list") for x in flat) else "read"
                node = principal(pol["objectId"], None)
                note(node, "roles", f"access policy on {r['name']}")
                g.link(node, _l(r["id"]), "access", f"{level}: access policy ({len(flat)} permissions)")

    item_node: dict[tuple[str, str, str], str] = {}
    for it in identity.get("kv_items") or []:
        vault = _l(it.get("vault"))
        if vault not in g.resources:
            continue
        kind = "key" if it.get("kind") == "key" else "secret"
        node = f"{vault}/{kind}s/{_l(it.get('name'))}"
        props = {"vault": g.resources[vault].name, "enabled": it.get("enabled"), "expires": it.get("expires"),
                 "key_type": it.get("key_type"), "content_type": it.get("content_type")}
        g.add(Resource(id=node, type=f"azure.keyvault.{kind}", name=it["name"], parent=g.resources[vault].parent,
                       region=g.resources[vault].region, created=it.get("created"),
                       props={k: v for k, v in props.items() if v is not None}))
        g.link(vault, node, "contains", kind)
        item_node[(vault, kind, _l(it["name"]))] = node

    # ---- 5. customer-managed keys / secret references found in resource properties -------------------
    vault_ids = set(vault_by_host.values())
    for r in rows:
        rid = _l(r.get("id"))
        if rid not in g.resources or rid in vault_ids or _l(r.get("type")) in skip_types:
            continue
        props = r.get("properties") or {}
        blob = json.dumps(props, default=str)
        if "vault." not in blob:
            continue
        keys = {(m.group(1).lower(), m.group(2).lower()) for m in _KV_KEY.finditer(blob)} | _split_key_refs(props)
        for host, kname in keys:
            vault = vault_by_host.get(host)
            if vault:
                g.link(item_node.get((vault, "key", kname), vault), rid, "encrypts", f"customer-managed key {kname}")
        for host, sname in {(m.group(1).lower(), m.group(2).lower()) for m in _KV_SECRET.finditer(blob)}:
            vault = vault_by_host.get(host)
            if vault:
                g.link(rid, item_node.get((vault, "secret", sname), vault), "uses", f"secret {sname}")


def _split_key_refs(obj: Any) -> set[tuple[str, str]]:
    """Some types (Storage) give the vault URI and key name as two fields instead of one URL."""
    found: set[tuple[str, str]] = set()
    if isinstance(obj, dict):
        low = {str(k).lower(): v for k, v in obj.items()}
        uri, name = low.get("keyvaulturi") or low.get("vaultbaseurl"), low.get("keyname")
        if isinstance(uri, str) and isinstance(name, str):
            m = re.match(r"https://([a-z0-9-]+)\.vault\.", uri, re.I)
            if m:
                found.add((m.group(1).lower(), name.lower()))
        for v in obj.values():
            found |= _split_key_refs(v)
    elif isinstance(obj, list):
        for v in obj:
            found |= _split_key_refs(v)
    return found


# ----------------------------------------------------------------------------------- live fetch
def _query(client: Any, subs: list[str], kql: str) -> list[dict]:
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
    out: list[dict] = []
    for i in range(0, len(subs), 100):
        token = None
        while True:
            res = client.resources(QueryRequest(subscriptions=subs[i:i + 100], query=kql, options=QueryRequestOptions(
                result_format="objectArray", top=1000, skip_token=token)))
            out.extend(res.data)
            token = res.skip_token
            if not token:
                break
    return out


def _epoch_or_dt(v: Any) -> Any:
    return v.isoformat() if hasattr(v, "isoformat") else v


def fetch_identity(cred: Any, subs: list[str], rows: list[dict], log: Callable[[str], None],
                   resolve_names: bool = True) -> dict:
    """Role assignments + definitions (Resource Graph), Key Vault key/secret metadata, principal display names.
    Every step degrades to a one-line note: identity data is additive, a missing permission never aborts a scan."""
    out: dict = {"assignments": [], "definitions": [], "kv_items": [], "names": {}}
    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        client = ResourceGraphClient(cred)
        out["assignments"] = _query(client, subs, ASSIGNMENTS_KQL)
        out["definitions"] = _query(client, subs, DEFINITIONS_KQL)
        log(f"  role assignments: {len(out['assignments'])}")
    except Exception as e:  # noqa: BLE001
        log(f"  note: could not read role assignments ({type(e).__name__}) - access arrows will be missing")

    vaults = [r for r in rows if _l(r.get("type")) == "microsoft.keyvault/vaults"]
    if vaults:
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError:
            log("  note: azure-mgmt-keyvault not installed - Key Vault keys/secrets not listed (pip install azure-mgmt-keyvault)")
        else:
            clients: dict[str, Any] = {}
            for v in vaults:
                kv = clients.setdefault(v["subscriptionId"], KeyVaultManagementClient(cred, v["subscriptionId"]))
                for kind, op in (("key", kv.keys), ("secret", kv.secrets)):
                    try:
                        for item in op.list(v["resourceGroup"], v["name"]):          # control plane: metadata only, no values
                            d = item.as_dict() if hasattr(item, "as_dict") else {}
                            props = d.get("properties") or {}
                            attrs = props.get("attributes") or {}
                            out["kv_items"].append({
                                "vault": v["id"], "kind": kind, "name": d.get("name"), "enabled": attrs.get("enabled"),
                                "created": _epoch_or_dt(attrs.get("created")), "expires": _epoch_or_dt(attrs.get("expires")),
                                "key_type": props.get("kty") if kind == "key" else None,
                                "content_type": props.get("content_type") if kind == "secret" else None})
                    except Exception as e:  # noqa: BLE001
                        log(f"  note: could not list {kind}s in vault {v['name']} ({type(e).__name__})")
            log(f"  key vault items: {len(out['kv_items'])}")

    if resolve_names:
        ids = {_l(a.get("properties", {}).get("principalId")) for a in out["assignments"]}
        ids |= {_l(p.get("objectId")) for v in vaults for p in (v.get("properties") or {}).get("accessPolicies") or []}
        ids |= {_l((r.get("properties") or {}).get("principalId")) for r in rows
                if _l(r.get("type")) == "microsoft.managedidentity/userassignedidentities"}
        ids.discard("")
        _resolve_names(cred, sorted(ids), out["names"], log)
    return out


def _resolve_names(cred: Any, ids: list[str], names: dict, log: Callable[[str], None]) -> None:
    """Best effort via Microsoft Graph (needs Directory.Read.All or similar); otherwise principals show as ids."""
    if not ids:
        return
    import urllib.request
    try:
        token = cred.get_token("https://graph.microsoft.com/.default").token
        for i in range(0, len(ids), 1000):
            req = urllib.request.Request(
                "https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
                data=json.dumps({"ids": ids[i:i + 1000], "types": ["user", "group", "servicePrincipal"]}).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:                    # noqa: S310 - fixed https endpoint
                apply_principal_names(names, json.loads(resp.read()).get("value") or [])
        log(f"  resolved {len(names)} of {len(ids)} principal names")
    except Exception as e:  # noqa: BLE001
        log(f"  note: principal names not resolved ({type(e).__name__}); shown by object id. "
            "Grant Microsoft Graph Directory.Read.All, or pass --no-principal-names to skip this step")
