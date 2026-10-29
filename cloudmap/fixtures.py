"""Fake-but-realistic environments for ``--demo`` and the tests.

The Azure rows have the shape Azure Resource Graph returns (``Resources | project ...``) and the GCP
assets have the shape ``asset_v1.Asset.to_dict()`` returns for ``ContentType.RESOURCE``, so they exercise
the same ``build_graph()`` code a live scan does. Creation dates are spread over the last ~2 years with a
fixed seed, so the date filter has something to show. Nothing here touches a real account.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

_NOW = datetime.now(timezone.utc)


def _ago(rng: random.Random) -> str:
    """A past timestamp, skewed towards recent so every 'past day/week/month' preset has content."""
    days = int(rng.random() ** 2 * 700) + 1
    return (_NOW - timedelta(days=days, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))).isoformat(timespec="seconds")


# --------------------------------------------------------------------------------------- Azure
def azure_rows() -> tuple[list[dict], dict[str, str], str]:
    """-> (resource graph rows, {subscription id: display name}, tenant id)"""
    rng = random.Random(11)
    sub = "11111111-2222-3333-4444-555555555555"
    tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    rows: list[dict] = []

    def rid(rg: str, ptype: str, *names: str) -> str:
        return f"/subscriptions/{sub}/resourceGroups/{rg}/providers/{ptype}/" + "/".join(names)

    def add(rg: str, ptype: str, name: str, props: dict | None = None, loc: str = "westeurope", kind: str | None = None,
            sku: dict | None = None, tags: dict | None = None, undated: bool = False, ident: str | None = None) -> str:
        i = ident or rid(rg, ptype, name)
        row = {"id": i, "name": name, "type": ptype.lower(), "kind": kind, "location": loc, "resourceGroup": rg,
               "subscriptionId": sub, "tags": tags or {}, "sku": sku, "properties": props or {}, "zones": None}
        if not undated:
            row["createdTime"] = _ago(rng)          # what fetch_rows() attaches from ARM $expand=createdTime
        rows.append(row)
        return i

    # ---- hub network ----
    hub_id = rid("Hub-RG", "Microsoft.Network/virtualNetworks", "hub-vnet")
    spoke_id = rid("App-RG", "Microsoft.Network/virtualNetworks", "spoke-app")
    dr_id = rid("DR-RG", "Microsoft.Network/virtualNetworks", "dr-vnet")
    sn = lambda vnet, name: f"{vnet}/subnets/{name}"  # noqa: E731
    nat_id = rid("App-RG", "Microsoft.Network/natGateways", "data-nat")

    def subnet(vnet, name, prefix, **extra):
        return {"id": sn(vnet, name), "name": name, "properties": {"addressPrefix": prefix, **extra}}

    add("Hub-RG", "Microsoft.Network/virtualNetworks", "hub-vnet", ident=hub_id, props={
        "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
        "subnets": [subnet(hub_id, "AzureFirewallSubnet", "10.0.1.0/26"), subnet(hub_id, "AzureBastionSubnet", "10.0.2.0/26"),
                    subnet(hub_id, "GatewaySubnet", "10.0.3.0/27")],
        "virtualNetworkPeerings": [{"properties": {"remoteVirtualNetwork": {"id": spoke_id}}}]})
    add("App-RG", "Microsoft.Network/virtualNetworks", "spoke-app", ident=spoke_id, props={
        "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
        "subnets": [subnet(spoke_id, "web", "10.1.1.0/24"), subnet(spoke_id, "app", "10.1.2.0/24"),
                    subnet(spoke_id, "data", "10.1.3.0/24", natGateway={"id": nat_id}),
                    subnet(spoke_id, "aks", "10.1.4.0/22"), subnet(spoke_id, "appgw", "10.1.8.0/24"),
                    subnet(spoke_id, "private-endpoints", "10.1.9.0/24")],
        "virtualNetworkPeerings": [{"properties": {"remoteVirtualNetwork": {"id": hub_id}}}]})
    add("DR-RG", "Microsoft.Network/virtualNetworks", "dr-vnet", ident=dr_id, loc="northeurope", props={
        "addressSpace": {"addressPrefixes": ["10.9.0.0/16"]}, "subnets": [subnet(dr_id, "workload", "10.9.1.0/24")]})

    fw_ip = [{"properties": {"subnet": {"id": sn(hub_id, "AzureFirewallSubnet")}}}]
    add("Hub-RG", "Microsoft.Network/azureFirewalls", "hub-fw", {"ipConfigurations": fw_ip, "provisioningState": "Succeeded"})
    add("Hub-RG", "Microsoft.Network/bastionHosts", "hub-bastion",
        {"ipConfigurations": [{"properties": {"subnet": {"id": sn(hub_id, "AzureBastionSubnet")}}}]})
    add("Hub-RG", "Microsoft.Network/virtualNetworkGateways", "hub-vpngw",
        {"ipConfigurations": [{"properties": {"subnet": {"id": sn(hub_id, "GatewaySubnet")}}}], "provisioningState": "Succeeded"})
    add("App-RG", "Microsoft.Network/natGateways", "data-nat", ident=nat_id, props={"provisioningState": "Succeeded"})

    # ---- web tier behind an application gateway ----
    agw_id = rid("App-RG", "Microsoft.Network/applicationGateways", "app-agw")
    add("App-RG", "Microsoft.Network/applicationGateways", "app-agw", ident=agw_id, props={
        "gatewayIPConfigurations": [{"properties": {"subnet": {"id": sn(spoke_id, "appgw")}}}], "provisioningState": "Succeeded"})
    ilb_id = rid("App-RG", "Microsoft.Network/loadBalancers", "app-ilb")
    add("App-RG", "Microsoft.Network/loadBalancers", "app-ilb", ident=ilb_id, sku={"name": "Standard"}, props={
        "frontendIPConfigurations": [{"properties": {"subnet": {"id": sn(spoke_id, "app")}}}], "provisioningState": "Succeeded"})

    def vm(rg, name, size, subnet_id, pool_key=None, pool_id=None, power="running", loc="westeurope"):
        vid = add(rg, "Microsoft.Compute/virtualMachines", name, loc=loc, props={
            "hardwareProfile": {"vmSize": size}, "storageProfile": {"osDisk": {"osType": "Linux"}},
            "extended": {"instanceView": {"powerState": {"code": f"PowerState/{power}"}}}}, tags={"tier": rg.lower()})
        ipcfg = {"subnet": {"id": subnet_id}}
        if pool_key:
            ipcfg[pool_key] = [{"id": pool_id}]
        add(rg, "Microsoft.Network/networkInterfaces", f"{name}-nic", loc=loc, undated=True,
            props={"virtualMachine": {"id": vid}, "ipConfigurations": [{"properties": ipcfg}]})
        return vid

    for n in (1, 2):
        vm("App-RG", f"web-vm-{n}", "Standard_D2s_v5", sn(spoke_id, "web"),
           "applicationGatewayBackendAddressPools", f"{agw_id}/backendAddressPools/web")
        vm("App-RG", f"app-vm-{n}", "Standard_D4s_v5", sn(spoke_id, "app"),
           "loadBalancerBackendAddressPools", f"{ilb_id}/backendAddressPools/app")
    vm("DR-RG", "dr-standby", "Standard_D2s_v5", sn(dr_id, "workload"), power="deallocated", loc="northeurope")

    # ---- containers + serverless ----
    add("App-RG", "Microsoft.ContainerService/managedClusters", "platform-aks", sku={"name": "Base"}, props={
        "kubernetesVersion": "1.30.4", "provisioningState": "Succeeded",
        "agentPoolProfiles": [{"name": "system", "count": 3, "vnetSubnetID": sn(spoke_id, "aks")},
                              {"name": "user", "count": 4, "vnetSubnetID": sn(spoke_id, "aks")}]})
    plan = add("App-RG", "Microsoft.Web/serverFarms", "app-plan", sku={"name": "P1v3"})
    add("App-RG", "Microsoft.Web/sites", "orders-func", kind="functionapp,linux", props={
        "serverFarmId": plan, "virtualNetworkSubnetId": sn(spoke_id, "app"), "state": "Running"})
    add("App-RG", "Microsoft.Web/sites", "storefront", kind="app,linux", props={"serverFarmId": plan, "state": "Running"})

    # ---- data ----
    sql_id = add("App-RG", "Microsoft.Sql/servers", "acme-sql", props={"state": "Ready", "version": "12.0"})
    add("App-RG", "Microsoft.Sql/servers/databases", "orders", ident=f"{sql_id}/databases/orders",
        sku={"name": "GP_Gen5_4"}, props={"status": "Online", "maxSizeBytes": 268435456000})
    add("App-RG", "Microsoft.Network/privateEndpoints", "sql-pe", props={
        "subnet": {"id": sn(spoke_id, "private-endpoints")}, "provisioningState": "Succeeded",
        "privateLinkServiceConnections": [{"properties": {"privateLinkServiceId": sql_id}}]})
    add("App-RG", "Microsoft.Storage/storageAccounts", "acmeprodstorage", kind="StorageV2", sku={"name": "Standard_GRS"},
        props={"accessTier": "Hot", "supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": False})
    add("App-RG", "Microsoft.DocumentDB/databaseAccounts", "acme-cosmos", props={"provisioningState": "Succeeded"})
    add("App-RG", "Microsoft.KeyVault/vaults", "acme-kv", props={"provisioningState": "Succeeded"})
    add("App-RG", "Microsoft.ServiceBus/namespaces", "acme-bus", sku={"name": "Standard"}, props={"provisioningState": "Succeeded"})
    add("Hub-RG", "Microsoft.OperationalInsights/workspaces", "hub-logs", undated=True, props={"provisioningState": "Succeeded"})

    _azure_identity_rows(rows, rid)
    return rows, {sub: "Contoso Production"}, tenant


_AZ_SUB = "11111111-2222-3333-4444-555555555555"
_AZ_P = {"alice": "aa000000-0000-4000-8000-000000000001", "platform": "aa000000-0000-4000-8000-000000000002",
         "ci": "aa000000-0000-4000-8000-000000000003", "func": "aa000000-0000-4000-8000-000000000004",
         "uai": "aa000000-0000-4000-8000-000000000005", "aks": "aa000000-0000-4000-8000-000000000006",
         "vm": "aa000000-0000-4000-8000-000000000007", "gone": "aa000000-0000-4000-8000-000000000099"}
_AZ_ROLES = {   # name -> (guid, permission blocks) - what ARG's roledefinitions rows look like
    "Owner": ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", [{"actions": ["*"], "notActions": []}]),
    "Contributor": ("b24988ac-6180-42a0-ab88-20f7382dd24c", [{"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"]}]),
    "Reader": ("acdd72a7-3385-48ef-bd42-f606fba81ae7", [{"actions": ["*/read"], "notActions": []}]),
    "Key Vault Secrets User": ("4633458b-17de-408a-b874-0445c86b69e6", [{"actions": ["Microsoft.KeyVault/vaults/read"], "dataActions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action"]}]),
    "Storage Blob Data Contributor": ("ba92f5b4-2d11-453d-a403-e96b0029c9fe", [{"actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"], "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"]}]),
}


def _azure_identity_rows(rows: list[dict], rid) -> None:
    """Attach managed identities, Key Vault settings and CMK/secret references to the fixture rows."""
    by_name = {r["name"]: r for r in rows}
    uai = rid("App-RG", "Microsoft.ManagedIdentity/userAssignedIdentities", "orders-uai")
    rows.append({"id": uai, "name": "orders-uai", "type": "microsoft.managedidentity/userassignedidentities", "kind": None,
                 "location": "westeurope", "resourceGroup": "App-RG", "subscriptionId": _AZ_SUB, "tags": {}, "sku": None,
                 "zones": None, "createdTime": "2026-09-30T09:00:00+00:00",
                 "properties": {"principalId": _AZ_P["uai"], "clientId": "bb000000-0000-4000-8000-000000000005"}})
    by_name["orders-func"]["identity"] = {"type": "SystemAssigned, UserAssigned", "principalId": _AZ_P["func"],
                                          "userAssignedIdentities": {uai: {"principalId": _AZ_P["uai"]}}}
    by_name["platform-aks"]["identity"] = {"type": "SystemAssigned", "principalId": _AZ_P["aks"]}
    by_name["web-vm-1"]["identity"] = {"type": "SystemAssigned", "principalId": _AZ_P["vm"]}
    kv = by_name["acme-kv"]["properties"]
    kv.update(vaultUri="https://acme-kv.vault.azure.net/", enableRbacAuthorization=False, enableSoftDelete=True,
              enablePurgeProtection=False, publicNetworkAccess="Enabled", accessPolicies=[
                  {"objectId": _AZ_P["alice"], "permissions": {"keys": ["get", "list", "create"], "secrets": ["get", "list", "set"]}},
                  {"objectId": _AZ_P["gone"], "permissions": {"secrets": ["get", "list"]}}])
    by_name["acmeprodstorage"]["properties"]["encryption"] = {"keySource": "Microsoft.Keyvault", "keyvaultproperties": {
        "keyname": "storage-cmk", "keyvaulturi": "https://acme-kv.vault.azure.net/", "keyversion": ""}}
    by_name["acme-cosmos"]["properties"]["keyVaultKeyUri"] = "https://acme-kv.vault.azure.net/keys/cosmos-cmk/0123456789abcdef"
    by_name["app-agw"]["properties"]["sslCertificates"] = [{"name": "site", "properties": {
        "keyVaultSecretId": "https://acme-kv.vault.azure.net/secrets/agw-cert/9f8e7d"}}]


def azure_identity() -> dict:
    """Role assignments / definitions / Key Vault items / principal names, in the shape fetch_identity() returns."""
    sub = _AZ_SUB
    base = f"/subscriptions/{sub}"
    def scope(rg=None, *res):
        return base + (f"/resourceGroups/{rg}" if rg else "") + ("/providers/" + "/".join(res) if res else "")
    kv_scope = scope("App-RG", "Microsoft.KeyVault", "vaults", "acme-kv")
    st_scope = scope("App-RG", "Microsoft.Storage", "storageAccounts", "acmeprodstorage")
    vnet_scope = scope("App-RG", "Microsoft.Network", "virtualNetworks", "spoke-app")
    n = iter(range(1, 99))
    def assign(pid, role, where, ptype):
        return {"id": f"{where}/providers/Microsoft.Authorization/roleAssignments/ra-{next(n)}", "name": f"ra-{n}",
                "type": "microsoft.authorization/roleassignments", "properties": {
                    "principalId": pid, "principalType": ptype, "scope": where,
                    "roleDefinitionId": f"{base}/providers/Microsoft.Authorization/roleDefinitions/{_AZ_ROLES[role][0]}"}}
    P = _AZ_P
    assignments = [
        assign(P["alice"], "Owner", base, "User"),
        assign(P["platform"], "Contributor", scope("App-RG"), "Group"),
        assign(P["ci"], "Contributor", scope("App-RG"), "ServicePrincipal"),
        assign(P["ci"], "Reader", scope("Hub-RG"), "ServicePrincipal"),
        assign(P["func"], "Key Vault Secrets User", kv_scope, "ServicePrincipal"),
        assign(P["uai"], "Storage Blob Data Contributor", st_scope, "ServicePrincipal"),
        assign(P["aks"], "Contributor", vnet_scope, "ServicePrincipal"),
        assign(P["vm"], "Reader", scope("App-RG"), "ServicePrincipal"),
        assign(P["gone"], "Reader", base, "User"),                      # a deleted user: shows up unresolved
    ]
    definitions = [{"id": f"{base}/providers/Microsoft.Authorization/roleDefinitions/{g}", "name": g,
                    "type": "microsoft.authorization/roledefinitions", "properties": {"roleName": name, "permissions": perms}}
                   for name, (g, perms) in _AZ_ROLES.items()]
    vault = kv_scope.lower()
    kv_items = [
        {"vault": vault, "kind": "key", "name": "storage-cmk", "enabled": True, "created": "2025-11-02T10:00:00+00:00",
         "expires": None, "key_type": "RSA"},
        {"vault": vault, "kind": "key", "name": "cosmos-cmk", "enabled": True, "created": "2026-03-14T08:30:00+00:00",
         "expires": "2027-03-14T08:30:00+00:00", "key_type": "RSA"},
        {"vault": vault, "kind": "secret", "name": "db-password", "enabled": True, "created": "2026-01-20T12:00:00+00:00", "expires": None},
        {"vault": vault, "kind": "secret", "name": "stripe-api-key", "enabled": False, "created": "2024-12-05T12:00:00+00:00",
         "expires": "2025-12-05T12:00:00+00:00"},
        {"vault": vault, "kind": "secret", "name": "agw-cert", "enabled": True, "created": "2026-08-01T07:00:00+00:00",
         "expires": "2027-08-01T07:00:00+00:00", "content_type": "application/x-pkcs12"},
    ]
    names = {P["alice"]: {"name": "Alice Admin (alice@contoso.example)", "type": "User"},
             P["platform"]: {"name": "Platform Engineers", "type": "Group"},
             P["ci"]: {"name": "ci-pipeline", "type": "ServicePrincipal"}}
    return {"assignments": assignments, "definitions": definitions, "kv_items": kv_items, "names": names}


# ------------------------------------------------------------------------------------------ GCP
def gcp_assets() -> list[dict]:
    rng = random.Random(23)
    p, pn = "acme-prod", "111122223333"
    parent = f"//cloudresourcemanager.googleapis.com/projects/{pn}"
    api = "https://www.googleapis.com/compute/v1"
    assets: list[dict] = []

    def asset(atype: str, name: str, data: dict, location: str = "") -> str:
        assets.append({"name": name, "asset_type": atype,
                       "resource": {"data": data, "location": location, "parent": parent}})
        return name

    def c(path: str) -> str:                       # compute asset name for a project-relative path
        return f"//compute.googleapis.com/projects/{p}/{path}"

    asset("cloudresourcemanager.googleapis.com/Project", parent, {"projectId": p, "projectNumber": pn, "name": "Acme Production"})

    net = f"{api}/projects/{p}/global/networks/prod-vpc"
    asset("compute.googleapis.com/Network", c("global/networks/prod-vpc"), {
        "name": "prod-vpc", "autoCreateSubnetworks": False, "routingConfig": {"routingMode": "GLOBAL"},
        "creationTimestamp": _ago(rng)}, "global")
    asset("compute.googleapis.com/Network", c("global/networks/default"), {
        "name": "default", "autoCreateSubnetworks": True, "creationTimestamp": _ago(rng)}, "global")   # unused -> pruned

    def subnet(name: str, region: str, cidr: str) -> str:
        url = f"{api}/projects/{p}/regions/{region}/subnetworks/{name}"
        asset("compute.googleapis.com/Subnetwork", c(f"regions/{region}/subnetworks/{name}"), {
            "name": name, "network": net, "region": f"{api}/projects/{p}/regions/{region}", "ipCidrRange": cidr,
            "privateIpGoogleAccess": True, "creationTimestamp": _ago(rng)}, region)
        return url

    app_us, data_us = subnet("app-us", "us-central1", "10.10.0.0/20"), subnet("data-us", "us-central1", "10.10.16.0/20")
    app_eu = subnet("app-eu", "europe-west1", "10.20.0.0/20")

    def vm(name: str, zone: str, subnet_url: str, mtype: str = "e2-standard-4", status: str = "RUNNING", ext: str | None = None):
        nic = {"subnetwork": subnet_url, "networkIP": f"10.10.{rng.randint(0, 15)}.{rng.randint(2, 250)}"}
        if ext:
            nic["accessConfigs"] = [{"natIP": ext}]
        asset("compute.googleapis.com/Instance", c(f"zones/{zone}/instances/{name}"), {
            "name": name, "zone": f"{api}/projects/{p}/zones/{zone}", "machineType": f"{api}/projects/{p}/zones/{zone}/machineTypes/{mtype}",
            "status": status, "networkInterfaces": [nic], "labels": {"env": "prod"}, "creationTimestamp": _ago(rng)}, zone)

    vm("web-1", "us-central1-a", app_us); vm("web-2", "us-central1-b", app_us)
    vm("bastion", "us-central1-a", data_us, "e2-small", ext="34.68.10.20")
    vm("batch-1", "europe-west1-b", app_eu, "n2-standard-8", "TERMINATED")

    # ---- global HTTPS load balancer -> backend service -> managed instance group ----
    ig = f"{api}/projects/{p}/zones/us-central1-a/instanceGroups/web-mig"
    asset("compute.googleapis.com/InstanceGroupManager", c("zones/us-central1-a/instanceGroupManagers/web-mig"), {
        "name": "web-mig", "zone": f"{api}/projects/{p}/zones/us-central1-a", "targetSize": 2, "baseInstanceName": "web",
        "instanceGroup": ig, "creationTimestamp": _ago(rng)}, "us-central1-a")
    asset("compute.googleapis.com/BackendService", c("global/backendServices/web-bes"), {
        "name": "web-bes", "protocol": "HTTPS", "loadBalancingScheme": "EXTERNAL_MANAGED", "backends": [{"group": ig}],
        "creationTimestamp": _ago(rng)}, "global")
    asset("compute.googleapis.com/UrlMap", c("global/urlMaps/web-map"), {
        "name": "web-map", "defaultService": f"{api}/projects/{p}/global/backendServices/web-bes"}, "global")
    asset("compute.googleapis.com/TargetHttpsProxy", c("global/targetHttpsProxies/web-proxy"), {
        "name": "web-proxy", "urlMap": f"{api}/projects/{p}/global/urlMaps/web-map"}, "global")
    asset("compute.googleapis.com/ForwardingRule", c("global/forwardingRules/web-fr"), {
        "name": "web-fr", "IPAddress": "34.120.5.9", "loadBalancingScheme": "EXTERNAL_MANAGED", "portRange": "443-443",
        "target": f"{api}/projects/{p}/global/targetHttpsProxies/web-proxy", "creationTimestamp": _ago(rng)}, "global")

    # ---- managed services ----
    asset("container.googleapis.com/Cluster", f"//container.googleapis.com/projects/{p}/locations/us-central1/clusters/platform-gke", {
        "name": "platform-gke", "location": "us-central1", "network": "prod-vpc", "subnetwork": "app-us",
        "currentMasterVersion": "1.30.5-gke.1014001", "status": "RUNNING", "currentNodeCount": 6, "createTime": _ago(rng)}, "us-central1")
    asset("sqladmin.googleapis.com/Instance", f"//cloudsql.googleapis.com/projects/{p}/instances/orders-pg", {
        "name": "orders-pg", "region": "us-central1", "databaseVersion": "POSTGRES_15", "state": "RUNNABLE", "createTime": _ago(rng),
        "settings": {"tier": "db-custom-4-16384", "availabilityType": "REGIONAL", "ipConfiguration": {"privateNetwork": f"projects/{p}/global/networks/prod-vpc"}}}, "us-central1")
    asset("redis.googleapis.com/Instance", f"//redis.googleapis.com/projects/{p}/locations/us-central1/instances/session-cache", {
        "name": f"projects/{p}/locations/us-central1/instances/session-cache", "tier": "STANDARD_HA", "memorySizeGb": 5,
        "state": "READY", "locationId": "us-central1-a", "authorizedNetwork": f"projects/{p}/global/networks/prod-vpc",
        "createTime": _ago(rng)}, "us-central1")
    asset("run.googleapis.com/Service", f"//run.googleapis.com/projects/{p}/locations/us-central1/services/checkout", {
        "metadata": {"name": "checkout", "creationTimestamp": _ago(rng), "labels": {"cloud.googleapis.com/location": "us-central1"}}}, "us-central1")
    asset("cloudfunctions.googleapis.com/Function", f"//cloudfunctions.googleapis.com/projects/{p}/locations/us-central1/functions/thumbnailer", {
        "name": f"projects/{p}/locations/us-central1/functions/thumbnailer", "state": "ACTIVE", "createTime": _ago(rng),
        "buildConfig": {"runtime": "python312"}, "eventTrigger": {"pubsubTopic": f"projects/{p}/topics/orders"}}, "us-central1")
    asset("cloudfunctions.googleapis.com/CloudFunction", f"//cloudfunctions.googleapis.com/projects/{p}/locations/europe-west1/functions/legacy-hook", {
        "name": f"projects/{p}/locations/europe-west1/functions/legacy-hook", "status": "ACTIVE", "runtime": "nodejs18",
        "updateTime": _ago(rng)}, "europe-west1")                                   # v1: only a last-modified time
    asset("pubsub.googleapis.com/Topic", f"//pubsub.googleapis.com/projects/{p}/topics/orders", {"name": f"projects/{p}/topics/orders"}, "global")
    asset("pubsub.googleapis.com/Subscription", f"//pubsub.googleapis.com/projects/{p}/subscriptions/orders-sub", {
        "name": f"projects/{p}/subscriptions/orders-sub", "topic": f"projects/{p}/topics/orders", "ackDeadlineSeconds": 30}, "global")
    asset("bigquery.googleapis.com/Dataset", f"//bigquery.googleapis.com/projects/{p}/datasets/analytics", {
        "datasetReference": {"datasetId": "analytics", "projectId": p}, "location": "US",
        "creationTime": str(int((datetime.fromisoformat(_ago(rng))).timestamp() * 1000))}, "US")
    # buckets carry only the project *number* (no id in their name) - exercises the number -> id lookup
    for b, loc in (("acme-prod-assets", "US"), ("acme-uploads", "US-CENTRAL1"), ("acme-backups", "EUROPE-WEST1")):
        asset("storage.googleapis.com/Bucket", f"//storage.googleapis.com/{b}", {
            "name": b, "location": loc, "storageClass": "STANDARD", "timeCreated": _ago(rng), "versioning": {"enabled": b == "acme-backups"}}, loc)
    _gcp_identity_assets(assets, p, pn)
    return assets


def _gcp_identity_assets(assets: list[dict], p: str, pn: str) -> None:
    """Service accounts, KMS, secrets, and the CMEK / secret / runs-as references on existing resources."""
    parent = f"//cloudresourcemanager.googleapis.com/projects/{pn}"
    by_name = {a["name"]: a for a in assets}
    dom = f"{p}.iam.gserviceaccount.com"

    def add(atype: str, name: str, data: dict, location: str = "") -> None:
        assets.append({"name": name, "asset_type": atype, "resource": {"data": data, "location": location, "parent": parent}})

    for sa, desc, disabled in (("web-sa", "Runs the web tier", False), ("functions-sa", "Cloud Functions runtime", False),
                               ("run-sa", "Checkout service", False), ("gke-nodes-sa", "GKE node pools", False),
                               ("ci-deployer", "CI/CD deployments", False), ("legacy-sa", "Unused since 2023", True)):
        add("iam.googleapis.com/ServiceAccount", f"//iam.googleapis.com/projects/{p}/serviceAccounts/{sa}@{dom}", {
            "name": f"projects/{p}/serviceAccounts/{sa}@{dom}", "email": f"{sa}@{dom}", "displayName": sa,
            "description": desc, "uniqueId": str(10**20 + len(assets)), "disabled": disabled})
    for i, when in enumerate(("2023-02-01T10:00:00Z", "2025-06-10T10:00:00Z")):
        add("iam.googleapis.com/ServiceAccountKey", f"//iam.googleapis.com/projects/{p}/serviceAccounts/ci-deployer@{dom}/keys/k{i}", {
            "name": f"projects/{p}/serviceAccounts/ci-deployer@{dom}/keys/k{i}", "keyType": "USER_MANAGED", "validAfterTime": when})
    add("iam.googleapis.com/ServiceAccountKey", f"//iam.googleapis.com/projects/{p}/serviceAccounts/web-sa@{dom}/keys/sys", {
        "name": f"projects/{p}/serviceAccounts/web-sa@{dom}/keys/sys", "keyType": "SYSTEM_MANAGED", "validAfterTime": "2026-01-01T00:00:00Z"})

    def ring(name: str, loc: str) -> str:
        add("cloudkms.googleapis.com/KeyRing", f"//cloudkms.googleapis.com/projects/{p}/locations/{loc}/keyRings/{name}", {
            "name": f"projects/{p}/locations/{loc}/keyRings/{name}", "createTime": "2025-03-03T09:00:00Z"}, loc)
        return f"projects/{p}/locations/{loc}/keyRings/{name}"

    def key(ring_path: str, name: str, purpose="ENCRYPT_DECRYPT", rotation: str | None = "7776000s", level="SOFTWARE") -> str:
        full = f"{ring_path}/cryptoKeys/{name}"
        data = {"name": full, "purpose": purpose, "createTime": "2025-03-04T09:00:00Z", "primary": {"state": "ENABLED"},
                "versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION" if purpose == "ENCRYPT_DECRYPT" else "EC_SIGN_P256_SHA256",
                                    "protectionLevel": level}}
        if rotation:
            data.update(rotationPeriod=rotation, nextRotationTime="2027-01-01T00:00:00Z")
        add("cloudkms.googleapis.com/CryptoKey", "//cloudkms.googleapis.com/" + full, data, ring_path.split("/")[3])
        return full

    prod_ring, glob_ring = ring("prod-ring", "us-central1"), ring("global-ring", "global")
    app_key = key(prod_ring, "app-data", level="HSM")
    backup_key = key(prod_ring, "backup-key", rotation=None)
    key(glob_ring, "signing-key", purpose="ASYMMETRIC_SIGN", rotation=None)

    def secret(name: str, data: dict | None = None) -> None:
        add("secretmanager.googleapis.com/Secret", f"//secretmanager.googleapis.com/projects/{pn}/secrets/{name}", {
            "name": f"projects/{pn}/secrets/{name}", "createTime": "2026-02-10T08:00:00Z", "replication": {"automatic": {}},
            **(data or {})}, "global")
    secret("db-password")
    secret("jwt-secret", {"rotation": {"nextRotationTime": "2027-01-01T00:00:00Z", "rotationPeriod": "2592000s"}})
    secret("stripe-key", {"replication": {"userManaged": {"replicas": [{"location": "europe-west1", "customerManagedEncryption": {"kmsKeyName": backup_key}}]}}})

    A = lambda kind, name: by_name[f"//{kind}.googleapis.com/projects/{p}/{name}"]["resource"]["data"]  # noqa: E731
    for vm in ("web-1", "web-2"):
        by_name[f"//compute.googleapis.com/projects/{p}/zones/us-central1-{'a' if vm == 'web-1' else 'b'}/instances/{vm}"][
            "resource"]["data"]["serviceAccounts"] = [{"email": f"web-sa@{dom}", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]
    A("container", "locations/us-central1/clusters/platform-gke")["nodeConfig"] = {"serviceAccount": f"gke-nodes-sa@{dom}"}
    A("cloudsql", "instances/orders-pg")["diskEncryptionConfiguration"] = {"kmsKeyName": app_key}
    A("pubsub", "topics/orders")["kmsKeyName"] = app_key
    A("run", "locations/us-central1/services/checkout").update(spec={"template": {"spec": {
        "serviceAccountName": f"run-sa@{dom}", "containers": [{"image": "gcr.io/x/checkout", "env": [
            {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-password", "key": "latest"}}}]}]}}})
    fn = A("cloudfunctions", "locations/us-central1/functions/thumbnailer")
    fn["serviceAccountEmail"] = f"functions-sa@{dom}"
    fn["secretEnvironmentVariables"] = [{"key": "JWT", "projectId": p, "secret": "jwt-secret", "version": "latest"}]
    by_name["//storage.googleapis.com/acme-backups"]["resource"]["data"]["encryption"] = {"defaultKmsKeyName": backup_key}


def gcp_policies() -> list[dict]:
    """IAM_POLICY assets: name = the resource the policy is attached to."""
    p, pn = "acme-prod", "111122223333"
    dom = f"{p}.iam.gserviceaccount.com"
    sa = lambda n: f"serviceAccount:{n}@{dom}"  # noqa: E731

    def pol(name: str, *bindings: tuple[str, list[str]]) -> dict:
        return {"name": name, "asset_type": "x", "iam_policy": {"bindings": [{"role": r, "members": m} for r, m in bindings]}}
    return [
        pol(f"//cloudresourcemanager.googleapis.com/projects/{pn}",
            ("roles/owner", ["user:alice@acme.example"]),
            ("roles/editor", ["group:platform@acme.example"]),
            ("roles/viewer", ["domain:acme.example", "deleted:user:old.hire@acme.example?uid=123456"]),
            ("roles/storage.admin", [sa("ci-deployer")]),
            ("roles/cloudsql.client", [sa("web-sa"), sa("run-sa")]),
            ("roles/container.nodeServiceAccount", [sa("gke-nodes-sa")])),
        pol("//cloudresourcemanager.googleapis.com/organizations/999000111",
            ("roles/resourcemanager.organizationAdmin", ["group:org-admins@acme.example"])),
        pol("//storage.googleapis.com/acme-prod-assets", ("roles/storage.objectViewer", ["allUsers"]),
            ("roles/storage.objectAdmin", [sa("ci-deployer")])),
        pol(f"//secretmanager.googleapis.com/projects/{pn}/secrets/db-password",
            ("roles/secretmanager.secretAccessor", [sa("web-sa"), sa("run-sa")])),
        pol(f"//secretmanager.googleapis.com/projects/{pn}/secrets/jwt-secret",
            ("roles/secretmanager.secretAccessor", [sa("functions-sa")])),
        pol(f"//cloudkms.googleapis.com/projects/{p}/locations/us-central1/keyRings/prod-ring/cryptoKeys/app-data",
            ("roles/cloudkms.cryptoKeyEncrypterDecrypter",
             [sa("web-sa"), f"serviceAccount:service-{pn}@gcp-sa-cloud-sql.iam.gserviceaccount.com"])),
        pol(f"//pubsub.googleapis.com/projects/{p}/topics/orders", ("roles/pubsub.publisher", [sa("web-sa")])),
        pol(f"//iam.googleapis.com/projects/{p}/serviceAccounts/ci-deployer@{dom}",
            ("roles/iam.serviceAccountUser", ["user:bob@acme.example"]),
            ("roles/iam.serviceAccountTokenCreator", ["group:platform@acme.example"])),
    ]
