"""GCP discovery via Cloud Asset Inventory (read-only; one API covers a project, folder or org).

Placement model:
    Project > VPC network > Subnet > { VM instances, GKE clusters }
    Project > Region > { Cloud SQL, buckets, functions, Cloud Run, Pub/Sub, load balancers ... }

Split in two so the logic is testable offline:
    fetch_assets()  - the only code that touches the Google SDK
    build_graph()   - pure function: asset dicts -> Graph
No secrets are read: Cloud Asset returns resource metadata, not env vars, keys or object contents.
"""
from __future__ import annotations

import argparse
import re
from typing import Any, Callable, Iterable

from ..model import Graph, Resource
from . import gcp_iam
from .base import Provider

_T = {
    "gcp.project":              ("Project", "PRJ", "container"),
    "gcp.region":               ("Region", "RGN", "container"),
    "compute.googleapis.com/Network":    ("VPC Network", "VPC", "container"),
    "compute.googleapis.com/Subnetwork": ("Subnet", "SUB", "container"),
    "compute.googleapis.com/Instance":   ("VM Instance", "GCE", "compute"),
    "compute.googleapis.com/InstanceGroupManager": ("Managed Instance Group", "MIG", "compute"),
    "container.googleapis.com/Cluster":  ("GKE Cluster", "GKE", "compute"),
    "cloudfunctions.googleapis.com/CloudFunction": ("Cloud Function", "FN", "compute"),
    "cloudfunctions.googleapis.com/Function": ("Cloud Function", "FN", "compute"),
    "run.googleapis.com/Service":        ("Cloud Run Service", "RUN", "compute"),
    "compute.googleapis.com/BackendService": ("Backend Service", "BES", "network"),
    "compute.googleapis.com/ForwardingRule": ("Forwarding Rule", "LB", "network"),
    "vpcaccess.googleapis.com/Connector": ("Serverless VPC Connector", "VPC", "network"),
    "sqladmin.googleapis.com/Instance":  ("Cloud SQL", "SQL", "database"),
    "redis.googleapis.com/Instance":     ("Memorystore Redis", "RDS", "database"),
    "spanner.googleapis.com/Instance":   ("Spanner", "SPN", "database"),
    "bigquery.googleapis.com/Dataset":   ("BigQuery Dataset", "BQ", "database"),
    "storage.googleapis.com/Bucket":     ("Cloud Storage Bucket", "GCS", "storage"),
    "pubsub.googleapis.com/Topic":       ("Pub/Sub Topic", "TOP", "integration"),
    "pubsub.googleapis.com/Subscription": ("Pub/Sub Subscription", "SUB", "integration"),
}
TYPES = {k: {"label": v[0], "short": v[1], "category": v[2]} for k, v in _T.items()}
TYPES.update(gcp_iam.TYPES)
SUPPORTED_ASSET_TYPES = [t for t in _T if "/" in t] + gcp_iam.ASSET_TYPES + [
    "cloudresourcemanager.googleapis.com/Project",
    "compute.googleapis.com/UrlMap", "compute.googleapis.com/TargetHttpProxy",
    "compute.googleapis.com/TargetHttpsProxy",
]


def norm(url: Any) -> str:
    """Canonical key for any GCP resource URL / asset name: 'projects/...' onwards."""
    s = str(url or "")
    i = s.find("projects/")
    return s[i:] if i >= 0 else s.rstrip("/")


def last(url: Any) -> str:
    return str(url or "").rstrip("/").split("/")[-1]


def region_of(location: str | None) -> str | None:
    """'us-central1-a' -> 'us-central1'; regions and multi-regions pass through."""
    if not location:
        return None
    loc = last(location).lower()
    return loc.rsplit("-", 1)[0] if re.search(r"-[a-z]$", loc) else loc


def _project_of(name: str) -> str:
    m = re.search(r"projects/([^/]+)", name)
    return m.group(1) if m else "unknown"


def _data(asset: dict) -> dict:
    return (asset.get("resource") or {}).get("data") or {}


def _parent_number(asset: dict) -> str | None:
    """'//cloudresourcemanager.googleapis.com/projects/123' -> '123' (assets carry the project *number*)."""
    m = re.search(r"projects/(\d+)", str((asset.get("resource") or {}).get("parent") or ""))
    return m.group(1) if m else None


def _project_ids_by_number(assets: list[dict]) -> dict[str, str]:
    """Some assets (Cloud Storage buckets) have no project id in their name, only a parent project
    number; learn number -> id from every asset that carries both."""
    out: dict[str, str] = {}
    for a in assets:
        num, m = _parent_number(a), re.search(r"projects/([a-z][a-z0-9-]+)", a.get("name", ""))
        if num and m:
            out[num] = m.group(1)
        d = _data(a)
        if a.get("asset_type") == "cloudresourcemanager.googleapis.com/Project" and d.get("projectId"):
            out[str(d.get("projectNumber") or "")] = d["projectId"]
    return out


def build_graph(assets: Iterable[dict], scope: str = "", policies: Iterable[dict] | None = None) -> Graph:
    assets = list(assets)
    g = Graph("gcp", scope, TYPES, account_label="Scope")
    ids_by_number = _project_ids_by_number(assets)
    by_type: dict[str, list[dict]] = {}
    for a in assets:
        by_type.setdefault(a.get("asset_type", ""), []).append(a)

    # ---- projects ----
    project_names = {}
    for a in by_type.get("cloudresourcemanager.googleapis.com/Project", []):
        d = _data(a)
        if d.get("projectId"):
            project_names[d["projectId"]] = d.get("name") or d["projectId"]

    def ensure_project(p: str) -> str:
        pid = f"proj:{p}"
        if pid not in g.resources:
            g.add(Resource(id=pid, type="gcp.project", name=project_names.get(p, p), container=True,
                           props={"project_id": p}))
        return pid

    def ensure_region(p: str, loc: str | None) -> str:
        loc = (loc or "global").lower()
        rid = f"region:{p}:{loc}"
        if rid not in g.resources:
            g.add(Resource(id=rid, type="gcp.region", name=loc, parent=ensure_project(p), region=loc,
                           container=True, prune_empty=True))
        return rid

    # ---- networks and subnets (containers) ----
    for a in by_type.get("compute.googleapis.com/Network", []):
        d, nid = _data(a), norm(a["name"])
        g.add(Resource(id=nid, type="compute.googleapis.com/Network", name=d.get("name", last(nid)),
                       parent=ensure_project(_project_of(nid)), container=True, created=d.get("creationTimestamp"),
                       props={"mode": "auto" if d.get("autoCreateSubnetworks") else "custom",
                              "routing": (d.get("routingConfig") or {}).get("routingMode")}))
    for a in by_type.get("compute.googleapis.com/Subnetwork", []):
        d, sid = _data(a), norm(a["name"])
        net = norm(d.get("network"))
        parent = net if net in g.resources else ensure_project(_project_of(sid))
        g.add(Resource(id=sid, type="compute.googleapis.com/Subnetwork", name=d.get("name", last(sid)),
                       parent=parent, region=last(d.get("region")), container=True,
                       created=d.get("creationTimestamp"),
                       props={"cidr": d.get("ipCidrRange"), "region": last(d.get("region")),
                              "private_google_access": d.get("privateIpGoogleAccess")}))
    # Dead-simple default VPCs ("auto" mode, nothing inside) are pruned by the same rule as AWS.

    def place(project: str, location: str | None, subnet: Any = None) -> str:
        s = norm(subnet)
        if s in g.resources:
            return s
        return ensure_region(project, region_of(location))

    # ---- load-balancer plumbing: resolve forwarding rule -> backend services ----
    chain: dict[str, list[str]] = {}
    for t in ("compute.googleapis.com/TargetHttpProxy", "compute.googleapis.com/TargetHttpsProxy"):
        for a in by_type.get(t, []):
            chain[norm(a["name"])] = [norm(_data(a).get("urlMap"))]
    for a in by_type.get("compute.googleapis.com/UrlMap", []):
        d = _data(a)
        svcs = [d.get("defaultService")]
        for pm in d.get("pathMatchers") or []:
            svcs.append(pm.get("defaultService"))
            svcs += [r.get("service") for r in pm.get("pathRules") or []]
        chain[norm(a["name"])] = [norm(x) for x in svcs if x]

    def resolve(url: str, seen: tuple = ()) -> list[str]:
        if url in seen:
            return []
        if url in chain:
            return [x for u in chain[url] for x in resolve(u, seen + (url,))]
        return [url]

    # ---- workloads and services ----
    for atype, items in by_type.items():
        for a in items:
            d, rid = _data(a), norm(a["name"])
            proj = _project_of(rid)
            if proj == "unknown":                     # e.g. buckets: fall back to the parent project number
                num = _parent_number(a)
                proj = ids_by_number.get(num or "", f"project-{num}" if num else "unknown")
            labels = d.get("labels") or (d.get("metadata") or {}).get("labels") or {}
            tags = {k: str(v) for k, v in labels.items()}

            if atype == "compute.googleapis.com/Instance":
                nic = (d.get("networkInterfaces") or [{}])[0]
                zone = last(d.get("zone"))
                ext = ((nic.get("accessConfigs") or [{}])[0]).get("natIP")
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=region_of(zone),
                               parent=place(proj, zone, nic.get("subnetwork")), created=d.get("creationTimestamp"),
                               tags=tags, props={"state": d.get("status"), "machine_type": last(d.get("machineType")),
                                                 "zone": zone, "private_ip": nic.get("networkIP"), "public_ip": ext,
                                                 "preemptible": (d.get("scheduling") or {}).get("preemptible")}))
            elif atype == "container.googleapis.com/Cluster":
                loc = d.get("location") or d.get("zone")
                r = region_of(loc)
                sub = f"projects/{proj}/regions/{r}/subnetworks/{last(d.get('subnetwork'))}"
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=r,
                               parent=place(proj, loc, sub), created=d.get("createTime"), tags=tags,
                               props={"state": d.get("status"), "version": d.get("currentMasterVersion"),
                                      "nodes": d.get("currentNodeCount"), "location": loc}))
            elif atype == "compute.googleapis.com/InstanceGroupManager":
                loc = d.get("zone") or d.get("region")
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=region_of(loc),
                               parent=place(proj, loc), created=d.get("creationTimestamp"),
                               props={"target_size": d.get("targetSize"), "base_name": d.get("baseInstanceName")}))
                if d.get("instanceGroup"):
                    g.alias(norm(d["instanceGroup"]), rid)
            elif atype == "compute.googleapis.com/BackendService":
                loc = d.get("region")
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=region_of(loc),
                               parent=place(proj, loc or "global"), created=d.get("creationTimestamp"),
                               props={"protocol": d.get("protocol"), "scheme": d.get("loadBalancingScheme")}))
                for b in d.get("backends") or []:
                    g.link(rid, norm(b.get("group")), "traffic", "backend")
            elif atype == "compute.googleapis.com/ForwardingRule":
                loc = d.get("region")
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=region_of(loc),
                               parent=place(proj, loc or "global"), created=d.get("creationTimestamp"),
                               props={"ip": d.get("IPAddress"), "scheme": d.get("loadBalancingScheme"),
                                      "ports": d.get("portRange") or d.get("ports")}))
                target = d.get("backendService") or d.get("target")
                for t in resolve(norm(target)) if target else []:
                    g.link(rid, t, "traffic", "routes to")
            elif atype == "vpcaccess.googleapis.com/Connector":
                loc = last(rid.split("/connectors/")[0])
                g.add(Resource(id=rid, type=atype, name=last(d.get("name", rid)), region=loc,
                               parent=place(proj, loc), props={"cidr": d.get("ipCidrRange"), "state": d.get("state")}))
            elif atype == "sqladmin.googleapis.com/Instance":
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=d.get("region"),
                               parent=place(proj, d.get("region")), created=d.get("createTime"), tags=tags,
                               props={"engine": d.get("databaseVersion"), "tier": (d.get("settings") or {}).get("tier"),
                                      "state": d.get("state"),
                                      "availability": (d.get("settings") or {}).get("availabilityType")}))
                priv = ((d.get("settings") or {}).get("ipConfiguration") or {}).get("privateNetwork")
                if priv:
                    g.link(rid, norm(priv), "private-link", "private IP")
            elif atype == "redis.googleapis.com/Instance":
                loc = d.get("locationId") or d.get("currentLocationId")
                g.add(Resource(id=rid, type=atype, name=last(d.get("name", rid)), region=region_of(loc),
                               parent=place(proj, loc), created=d.get("createTime"), tags=tags,
                               props={"tier": d.get("tier"), "memory_gb": d.get("memorySizeGb"), "state": d.get("state")}))
                if d.get("authorizedNetwork"):
                    g.link(rid, norm(d["authorizedNetwork"]), "private-link", "authorized network")
            elif atype == "spanner.googleapis.com/Instance":
                g.add(Resource(id=rid, type=atype, name=last(d.get("name", rid)), region=region_of(a.get("resource", {}).get("location")),
                               parent=place(proj, a.get("resource", {}).get("location")), tags=tags,
                               props={"nodes": d.get("nodeCount"), "state": d.get("state")}))
            elif atype == "bigquery.googleapis.com/Dataset":
                ref = d.get("datasetReference") or {}
                loc = d.get("location")
                g.add(Resource(id=rid, type=atype, name=ref.get("datasetId", last(rid)), region=(loc or "").lower() or None,
                               parent=place(proj, loc), created=d.get("creationTime"), tags=tags))
            elif atype == "storage.googleapis.com/Bucket":
                loc = d.get("location")
                g.add(Resource(id=rid, type=atype, name=d.get("name", last(rid)), region=(loc or "").lower() or None,
                               parent=place(proj, loc), created=d.get("timeCreated"), tags=tags,
                               props={"class": d.get("storageClass"), "location_type": d.get("locationType"),
                                      "versioning": (d.get("versioning") or {}).get("enabled"),
                                      "public_access_prevention": (d.get("iamConfiguration") or {}).get("publicAccessPrevention")}))
            elif atype in ("cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function"):
                loc = last(rid.split("/functions/")[0])
                g.add(Resource(id=rid, type=atype, name=last(d.get("name", rid)), region=loc, parent=place(proj, loc),
                               created=d.get("createTime") or d.get("updateTime"), tags=tags,
                               props={"date_basis": None if d.get("createTime") else "last modified",
                                      "runtime": d.get("runtime") or (d.get("buildConfig") or {}).get("runtime"),
                                      "state": d.get("status") or d.get("state")}))
                trig = d.get("eventTrigger") or {}
                topic = trig.get("resource") or trig.get("pubsubTopic")
                if topic:
                    g.link(norm(topic), rid, "trigger", "Pub/Sub trigger")
                if d.get("vpcConnector"):
                    g.link(rid, norm(d["vpcConnector"]), "link", "VPC connector")
            elif atype == "run.googleapis.com/Service":
                meta = d.get("metadata") or {}
                loc = (meta.get("labels") or {}).get("cloud.googleapis.com/location") or (a.get("resource") or {}).get("location")
                g.add(Resource(id=rid, type=atype, name=meta.get("name") or last(rid), region=loc,
                               parent=place(proj, loc), created=meta.get("creationTimestamp") or d.get("createTime"), tags=tags))
            elif atype == "pubsub.googleapis.com/Topic":
                g.add(Resource(id=rid, type=atype, name=last(rid), region="global", parent=ensure_region(proj, "global"),
                               tags=tags))
            elif atype == "pubsub.googleapis.com/Subscription":
                g.add(Resource(id=rid, type=atype, name=last(rid), region="global", parent=ensure_region(proj, "global"),
                               tags=tags, props={"ack_deadline_s": d.get("ackDeadlineSeconds"),
                                                 "push": bool((d.get("pushConfig") or {}).get("pushEndpoint"))}))
                if d.get("topic"):
                    g.link(norm(d["topic"]), rid, "event", "subscription")

    # Auto-mode default network with nothing in it is noise, like AWS default VPCs.
    for net in [r for r in g.snapshot() if r.type == "compute.googleapis.com/Network" and r.name == "default"]:
        inside = {net.id}
        used = False
        for r in g.snapshot():
            if r.parent in inside:
                inside.add(r.id)
                used = used or r.type != "compute.googleapis.com/Subnetwork"
        if not used:
            g.remove(inside)

    def proj_of(a: dict) -> str:
        proj = _project_of(norm(a["name"]))
        if proj.isdigit():
            proj = ids_by_number.get(proj, proj)
        if proj == "unknown":
            num = _parent_number(a)
            proj = ids_by_number.get(num or "", f"project-{num}" if num else "unknown")
        return proj

    gcp_iam.add_identity(g, assets, list(policies or []), proj_of=proj_of, project_ids=ids_by_number,
                         ensure_project=ensure_project, ensure_region=ensure_region, skip_types=set())
    return g.finalize()


# --------------------------------------------------------------------------- live fetch
def fetch_assets(parents: list[str], log: Callable[[str], None]) -> list[dict]:
    try:
        from google.cloud import asset_v1
    except ImportError:
        raise SystemExit("GCP support needs the Cloud Asset client:\n  pip install google-cloud-asset") from None
    client = asset_v1.AssetServiceClient()
    out: list[dict] = []
    for parent in parents:
        log(f"Listing assets under {parent}")
        req = asset_v1.ListAssetsRequest(parent=parent, content_type=asset_v1.ContentType.RESOURCE,
                                         asset_types=SUPPORTED_ASSET_TYPES, page_size=1000)
        for a in client.list_assets(request=req):
            out.append(asset_v1.Asset.to_dict(a, use_integers_for_enums=False, preserving_proto_field_name=True))
    return out


def fetch_policies(parents: list[str], log: Callable[[str], None]) -> list[dict]:
    """Who holds which role on what: a second Cloud Asset call with IAM_POLICY content. Best effort."""
    try:
        from google.cloud import asset_v1
        client = asset_v1.AssetServiceClient()
        out: list[dict] = []
        for parent in parents:
            req = asset_v1.ListAssetsRequest(
                parent=parent, content_type=asset_v1.ContentType.IAM_POLICY, page_size=1000,
                asset_types=SUPPORTED_ASSET_TYPES + gcp_iam.POLICY_EXTRA_TYPES)
            for a in client.list_assets(request=req):
                d = asset_v1.Asset.to_dict(a, use_integers_for_enums=False, preserving_proto_field_name=True)
                if (d.get("iam_policy") or {}).get("bindings"):
                    out.append({"name": d["name"], "asset_type": d.get("asset_type"), "iam_policy": d["iam_policy"]})
        log(f"  IAM policies on {len(out)} resources")
        return out
    except Exception as e:  # noqa: BLE001 - additive: never fail the scan over it
        log(f"  note: could not read IAM policies ({type(e).__name__}) - access arrows will be missing. "
            "Needs Cloud Asset Viewer (cloudasset.assets.listIamPolicy)")
        return []


class GCPProvider(Provider):
    name = "gcp"

    def __init__(self, parents: list[str], log: Callable[[str], None] | None = None):
        super().__init__(log)
        self.parents = parents

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--projects", help="comma-separated project ids")
        parser.add_argument("--organization", help="organization id (scans every project in it)")
        parser.add_argument("--folder", help="folder id (scans every project in it)")

    @classmethod
    def from_args(cls, args, log):
        parents = [f"projects/{p.strip()}" for p in (args.projects or "").split(",") if p.strip()]
        if args.organization:
            parents.append(f"organizations/{args.organization}")
        if args.folder:
            parents.append(f"folders/{args.folder}")
        if not parents:
            raise SystemExit("Give --projects, --organization or --folder.")
        return cls(parents, log)

    def discover(self) -> Graph:
        assets = fetch_assets(self.parents, self.log)
        g = build_graph(assets, ", ".join(p.split("/", 1)[1] for p in self.parents), fetch_policies(self.parents, self.log))
        self.log(f"Found {sum(not r.container for r in g.resources.values())} resources, {len(g.edges)} connections.")
        return g
