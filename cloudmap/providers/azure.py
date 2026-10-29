"""Azure discovery via Azure Resource Graph (read-only, one query covers every subscription).

Placement model:
    Subscription > Resource group > { VNet > Subnet > VMs, AKS, App Gateway, private endpoints ... }
Resources that live in a subnet (found through NICs / properties) are drawn inside that subnet;
everything else sits in its resource group.

The work is split in two so the interesting part is testable without an Azure account:
    fetch_rows()    - the only code that touches the Azure SDK
    build_graph()   - pure function: Resource Graph rows -> Graph
Secrets are never read (no app settings, connection strings, keys, or Key Vault contents).
"""
from __future__ import annotations

import argparse
from typing import Any, Callable, Iterable

from ..model import Graph, Resource
from . import azure_iam
from .base import Provider

# type -> (display name, glyph, category)
_T = {
    "azure.tenant":           ("Tenant", "TEN", "container"),
    "azure.subscription":     ("Subscription", "SUB", "container"),
    "azure.resourcegroup":    ("Resource Group", "RG", "container"),
    "azure.network.vnet":     ("Virtual Network", "VNET", "container"),
    "azure.network.subnet":   ("Subnet", "SUB", "container"),
    "microsoft.compute/virtualmachines":          ("Virtual Machine", "VM", "compute"),
    "microsoft.compute/virtualmachinescalesets":  ("VM Scale Set", "VMSS", "compute"),
    "microsoft.containerservice/managedclusters": ("AKS Cluster", "AKS", "compute"),
    "microsoft.web/sites":                        ("App Service", "APP", "compute"),
    "microsoft.web/sites#function":               ("Function App", "FN", "compute"),
    "microsoft.web/serverfarms":                  ("App Service Plan", "ASP", "compute"),
    "microsoft.app/containerapps":                ("Container App", "CA", "compute"),
    "microsoft.app/managedenvironments":          ("Container Apps Env", "CAE", "compute"),
    "microsoft.containerinstance/containergroups": ("Container Instance", "ACI", "compute"),
    "microsoft.batch/batchaccounts":              ("Batch Account", "BAT", "compute"),
    "microsoft.network/loadbalancers":            ("Load Balancer", "LB", "network"),
    "microsoft.network/applicationgateways":      ("Application Gateway", "AGW", "network"),
    "microsoft.network/natgateways":              ("NAT Gateway", "NAT", "network"),
    "microsoft.network/azurefirewalls":           ("Azure Firewall", "FW", "network"),
    "microsoft.network/virtualnetworkgateways":   ("VPN/ER Gateway", "GW", "network"),
    "microsoft.network/bastionhosts":             ("Bastion", "BAS", "network"),
    "microsoft.network/privateendpoints":         ("Private Endpoint", "PE", "network"),
    "microsoft.network/publicipaddresses":        ("Public IP", "PIP", "network"),
    "microsoft.network/dnszones":                 ("DNS Zone", "DNS", "network"),
    "microsoft.network/trafficmanagerprofiles":   ("Traffic Manager", "TM", "edge"),
    "microsoft.cdn/profiles":                     ("CDN / Front Door", "CDN", "edge"),
    "microsoft.network/frontdoors":               ("Front Door", "AFD", "edge"),
    "microsoft.apimanagement/service":            ("API Management", "APIM", "edge"),
    "microsoft.storage/storageaccounts":          ("Storage Account", "STO", "storage"),
    "microsoft.containerregistry/registries":     ("Container Registry", "ACR", "storage"),
    "microsoft.sql/servers":                      ("SQL Server", "SQL", "database"),
    "microsoft.sql/servers/databases":            ("SQL Database", "DB", "database"),
    "microsoft.sql/managedinstances":             ("SQL Managed Instance", "SMI", "database"),
    "microsoft.documentdb/databaseaccounts":      ("Cosmos DB", "COS", "database"),
    "microsoft.dbforpostgresql/flexibleservers":  ("PostgreSQL", "PG", "database"),
    "microsoft.dbformysql/flexibleservers":       ("MySQL", "MY", "database"),
    "microsoft.cache/redis":                      ("Redis Cache", "RDS", "database"),
    "microsoft.servicebus/namespaces":            ("Service Bus", "SB", "integration"),
    "microsoft.eventhub/namespaces":              ("Event Hubs", "EH", "integration"),
    "microsoft.eventgrid/topics":                 ("Event Grid Topic", "EG", "integration"),
    "microsoft.logic/workflows":                  ("Logic App", "LA", "integration"),
    "microsoft.keyvault/vaults":                  ("Key Vault", "KV", "security"),
    "microsoft.operationalinsights/workspaces":   ("Log Analytics", "LAW", "other"),
}
TYPES = {k: {"label": v[0], "short": v[1], "category": v[2]} for k, v in _T.items()}

# Plumbing that would drown the diagram; still used internally to work out placement.
SKIP_TYPES = {
    "microsoft.network/networkinterfaces", "microsoft.compute/disks", "microsoft.compute/snapshots",
    "microsoft.network/networkwatchers", "microsoft.network/networksecuritygroups",
    "microsoft.network/routetables", "microsoft.network/virtualnetworks",   # drawn as containers
    "microsoft.managedidentity/userassignedidentities", "microsoft.compute/sshpublickeys",
    "microsoft.compute/images", "microsoft.insights/components", "microsoft.insights/actiongroups",
    "microsoft.insights/metricalerts", "microsoft.insights/workbooks", "microsoft.alertsmanagement/smartdetectoralertrules",
    "microsoft.network/privatednszones", "microsoft.network/privatednszones/virtualnetworklinks",
    "microsoft.compute/virtualmachines/extensions", "microsoft.network/ddosprotectionplans",
}
CREATED_KEYS = ("timeCreated", "creationTime", "createdTime", "createdDate", "creationDate",
                "dateCreated", "createdAt", "createTime")

KQL = ("Resources | project id, name, type, kind, location, resourceGroup, subscriptionId, "
       "tags, sku, properties, zones, identity")


def _lid(v: Any) -> str:
    return str(v or "").lower()


def _created(row: dict) -> Any:
    if row.get("createdTime"):                  # ARM `$expand=createdTime`, attached by fetch_rows()
        return row["createdTime"]
    props = row.get("properties") or {}
    for key in CREATED_KEYS:
        if props.get(key):
            return props[key]
    return (props.get("systemData") or row.get("systemData") or {}).get("createdAt")


def _subnet_of(row: dict) -> str | None:
    """Find the subnet a resource lives in, from the properties each Azure type uses."""
    p = row.get("properties") or {}
    t = _lid(row.get("type"))
    cands: list[Any] = [p.get("subnet"), p.get("virtualNetworkSubnetId"), p.get("subnetId")]
    for key in ("ipConfigurations", "gatewayIPConfigurations", "frontendIPConfigurations"):
        for ic in p.get(key) or []:
            ip = ic.get("properties") or {}
            cands += [ip.get("subnet")]
    for pool in p.get("agentPoolProfiles") or []:
        cands.append(pool.get("vnetSubnetID"))
    for c in cands:
        sid = c.get("id") if isinstance(c, dict) else c
        if sid and "/subnets/" in str(sid):
            return _lid(sid)
    return None


def build_graph(rows: Iterable[dict], subscription_names: dict[str, str] | None = None,
                tenant: str = "", identity: dict | None = None) -> Graph:
    rows = list(rows)
    names = {k.lower(): v for k, v in (subscription_names or {}).items()}
    g = Graph("azure", tenant, TYPES, account_label="Tenant")
    root = None
    if tenant:
        root = f"tenant:{tenant}"
        g.add(Resource(id=root, type="azure.tenant", name=f"Tenant {tenant[:8]}…",
                       container=True, props={"tenant_id": tenant}))

    by_type: dict[str, list[dict]] = {}
    for r in rows:
        by_type.setdefault(_lid(r.get("type")), []).append(r)

    def ensure_sub(sub: str) -> str:
        sid = f"sub:{sub.lower()}"
        if sid not in g.resources:
            g.add(Resource(id=sid, type="azure.subscription", name=names.get(sub.lower(), sub),
                           parent=root, container=True, props={"subscription_id": sub}))
        return sid

    def ensure_rg(sub: str, rg: str, loc: str | None) -> str:
        rid = f"rg:{sub.lower()}:{rg.lower()}"
        if rid not in g.resources:
            g.add(Resource(id=rid, type="azure.resourcegroup", name=rg, parent=ensure_sub(sub),
                           region=loc, container=True, prune_empty=True))
        return rid

    # ---- virtual networks and subnets (containers) ----
    peered: set[frozenset] = set()
    for v in by_type.get("microsoft.network/virtualnetworks", []):
        p = v.get("properties") or {}
        vid = _lid(v["id"])
        g.add(Resource(id=vid, type="azure.network.vnet", name=v["name"],
                       parent=ensure_rg(v["subscriptionId"], v["resourceGroup"], v.get("location")),
                       region=v.get("location"), container=True, tags=v.get("tags") or {},
                       props={"cidr": ", ".join((p.get("addressSpace") or {}).get("addressPrefixes", [])),
                              "location": v.get("location")}))
        for sn in p.get("subnets") or []:
            sp = sn.get("properties") or {}
            prefixes = sp.get("addressPrefixes") or [sp.get("addressPrefix")]
            g.add(Resource(id=_lid(sn["id"]), type="azure.network.subnet", name=sn["name"], parent=vid,
                           region=v.get("location"), container=True,
                           props={"cidr": ", ".join(x for x in prefixes if x),
                                  "delegations": [d.get("properties", {}).get("serviceName")
                                                  for d in sp.get("delegations") or []]}))
            nat = (sp.get("natGateway") or {}).get("id")
            if nat:
                g.link(_lid(sn["id"]), _lid(nat), "route", "NAT gateway")
        for peer in p.get("virtualNetworkPeerings") or []:
            remote = ((peer.get("properties") or {}).get("remoteVirtualNetwork") or {}).get("id")
            pair = frozenset((vid, _lid(remote)))
            if remote and pair not in peered:           # peerings are listed on both VNets; draw one arrow
                peered.add(pair)
                g.link(vid, _lid(remote), "peering", "VNet peering")

    # ---- NIC map: VM -> subnet, and load balancer -> VM ----
    vm_subnet: dict[str, str] = {}
    for nic in by_type.get("microsoft.network/networkinterfaces", []):
        p = nic.get("properties") or {}
        vm = (p.get("virtualMachine") or {}).get("id")
        for ic in p.get("ipConfigurations") or []:
            ip = ic.get("properties") or {}
            sub = (ip.get("subnet") or {}).get("id")
            if vm and sub:
                vm_subnet[_lid(vm)] = _lid(sub)
            for pool in (ip.get("loadBalancerBackendAddressPools") or []) + \
                        (ip.get("applicationGatewayBackendAddressPools") or []):
                owner = str(pool.get("id", "")).lower().split("/backendaddresspools/")[0]
                if vm and owner:
                    g.link(owner, _lid(vm), "traffic", "backend pool")

    # ---- everything else ----
    for t, items in by_type.items():
        if t in SKIP_TYPES:
            continue
        for r in items:
            kind = _lid(r.get("kind"))
            tkey = t + "#function" if t == "microsoft.web/sites" and "functionapp" in kind else t
            if tkey not in g.type_info:
                label = tkey.split("/")[-1].replace("#", " ")
                g.type_info[tkey] = {"label": label.title(), "short": label[:3].upper() or "?", "category": "other"}
            rid = _lid(r["id"])
            parent = vm_subnet.get(rid) or _subnet_of(r)
            if parent not in g.resources:
                parent = ensure_rg(r["subscriptionId"], r["resourceGroup"], r.get("location"))
            p = r.get("properties") or {}
            props = {"location": r.get("location"), "resource_group": r.get("resourceGroup"),
                     "kind": r.get("kind"), "sku": (r.get("sku") or {}).get("name") if isinstance(r.get("sku"), dict) else r.get("sku")}
            if t == "microsoft.compute/virtualmachines":
                power = (((p.get("extended") or {}).get("instanceView") or {}).get("powerState") or {}).get("code")
                props.update(size=(p.get("hardwareProfile") or {}).get("vmSize"),
                             os=((p.get("storageProfile") or {}).get("osDisk") or {}).get("osType"),
                             state=str(power).split("/")[-1] if power else p.get("provisioningState"))
            elif t == "microsoft.containerservice/managedclusters":
                props.update(version=p.get("kubernetesVersion"), state=p.get("provisioningState"),
                             nodes=sum(x.get("count", 0) for x in p.get("agentPoolProfiles") or []))
            elif t == "microsoft.storage/storageaccounts":
                props.update(access_tier=p.get("accessTier"), https_only=p.get("supportsHttpsTrafficOnly"),
                             public_blob_access=p.get("allowBlobPublicAccess"))
            elif t == "microsoft.sql/servers/databases":
                props.update(state=p.get("status"), max_size_bytes=p.get("maxSizeBytes"))
            elif t == "microsoft.keyvault/vaults":
                props.update(state=p.get("provisioningState"), uri=p.get("vaultUri"), rbac_authorization=p.get("enableRbacAuthorization"),
                             soft_delete=p.get("enableSoftDelete"), purge_protection=p.get("enablePurgeProtection"),
                             public_network_access=p.get("publicNetworkAccess"))
            else:
                props["state"] = p.get("provisioningState")
            g.add(Resource(id=rid, type=tkey, name=r["name"], parent=parent, region=r.get("location"),
                           arn=rid, created=_created(r), tags=r.get("tags") or {},
                           props={k: v for k, v in props.items() if v is not None}))
            # private endpoint -> the service it exposes
            if t == "microsoft.network/privateendpoints":
                for conn in (p.get("privateLinkServiceConnections") or []) + \
                            (p.get("manualPrivateLinkServiceConnections") or []):
                    target = (conn.get("properties") or {}).get("privateLinkServiceId")
                    if target:
                        g.link(rid, _lid(target), "private-link", "private link")
            # SQL database -> its server
            if t == "microsoft.sql/servers/databases":
                g.link(_lid(rid.rsplit("/databases/", 1)[0]), rid, "contains", "")
            # App Service / Function -> hosting plan
            if t == "microsoft.web/sites" and p.get("serverFarmId"):
                g.link(_lid(p["serverFarmId"]), rid, "contains", "hosts")
    azure_iam.add_identity(g, rows, identity, root=root, ensure_rg=ensure_rg, skip_types=SKIP_TYPES)
    return g.finalize()


# --------------------------------------------------------------------------- live fetch
def fetch_rows(subscriptions: list[str] | None, log: Callable[[str], None]) -> tuple[list[dict], dict[str, str], str, Any, list[str]]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        raise SystemExit("Azure support needs extra packages:\n"
                         "  pip install azure-identity azure-mgmt-resourcegraph azure-mgmt-subscription") from None

    cred = DefaultAzureCredential()
    names: dict[str, str] = {}
    tenant = ""
    for s in SubscriptionClient(cred).subscriptions.list():
        names[s.subscription_id] = s.display_name
        tenant = tenant or getattr(s, "tenant_id", "") or ""
    subs = subscriptions or list(names)
    if not subs:
        raise SystemExit("No Azure subscriptions are visible to these credentials (try `az login`).")
    log(f"Querying Azure Resource Graph across {len(subs)} subscription(s)")

    client = ResourceGraphClient(cred)
    rows: list[dict] = []
    for i in range(0, len(subs), 100):               # Resource Graph accepts up to 1000; stay well below
        skip_token = None
        while True:
            opts = QueryRequestOptions(result_format="objectArray", top=1000, skip_token=skip_token)
            res = client.resources(QueryRequest(subscriptions=subs[i:i + 100], query=KQL, options=opts))
            rows.extend(res.data)
            skip_token = res.skip_token
            if not skip_token:
                break
    _attach_created_times(cred, subs, rows, log)
    return rows, names, tenant, cred, subs


def _attach_created_times(cred: Any, subs: list[str], rows: list[dict], log: Callable[[str], None]) -> None:
    """Resource Graph rows rarely carry a creation date; ARM does, via $expand=createdTime."""
    try:
        from azure.mgmt.resource.resources import ResourceManagementClient
    except ImportError:
        log("  note: azure-mgmt-resource not installed - creation dates limited to what Resource Graph returns")
        return
    created: dict[str, Any] = {}
    for sub in subs:
        try:
            for r in ResourceManagementClient(cred, sub).resources.list(expand="createdTime"):
                if r.id and r.created_time:
                    created[r.id.lower()] = r.created_time
        except Exception as e:  # noqa: BLE001 - dates are a bonus; never fail the scan over them
            log(f"  note: could not read creation times for subscription {sub}: {type(e).__name__}")
    for row in rows:
        t = created.get(str(row.get("id", "")).lower())
        if t:
            row["createdTime"] = t


class AzureProvider(Provider):
    name = "azure"

    def __init__(self, subscriptions: list[str] | None = None, log: Callable[[str], None] | None = None,
                 resolve_names: bool = True):
        super().__init__(log)
        self.subscriptions = subscriptions
        self.resolve_names = resolve_names

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--subscriptions", help="comma-separated subscription ids (default: all visible)")
        parser.add_argument("--no-principal-names", action="store_true",
                            help="don't look up user/group/app display names in Microsoft Graph (principals show as object ids)")

    @classmethod
    def from_args(cls, args, log):
        subs = [s.strip() for s in args.subscriptions.split(",") if s.strip()] if args.subscriptions else None
        return cls(subs, log, resolve_names=not args.no_principal_names)

    def discover(self) -> Graph:
        rows, names, tenant, cred, subs = fetch_rows(self.subscriptions, self.log)
        identity = azure_iam.fetch_identity(cred, subs, rows, self.log, self.resolve_names)
        g = build_graph(rows, names, tenant, identity)
        self.log(f"Found {sum(not r.container for r in g.resources.values())} resources, {len(g.edges)} connections.")
        return g
