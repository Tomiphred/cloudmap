"""Identity & security layer: IAM users/roles, KMS, secrets - what each controls and what it connects to.

AWS runs against a moto-mocked estate through the real provider; Azure and GCP run build_graph() over
fixtures shaped like Resource Graph / Cloud Asset output. The table view is driven in headless Chromium.
"""
from __future__ import annotations

import json
import urllib.parse

import pytest

from cloudmap import iam
from cloudmap.demo import run_demo
from cloudmap.fixtures import azure_identity, azure_rows, gcp_assets, gcp_policies
from cloudmap.providers import azure as az, azure_iam, gcp, gcp_iam
from cloudmap.render import render_html

PLACEHOLDER_SECRETS = ("not-a-real", "Not-A-Real", "never-read-by-scanner", "postgres://placeholder")


def triples(graph, kinds):
    names = {r["id"]: r["name"] for r in graph["resources"]}
    return {(names[e["source"]], names[e["target"]], e["kind"]) for e in graph["edges"] if e["kind"] in kinds}


def by_name(graph):
    return {r["name"]: r for r in graph["resources"]}


# -------------------------------------------------------------------------------------- policy helpers
def test_policy_statements_parse_urlencoded_and_single_values():
    doc = urllib.parse.quote(json.dumps({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}))
    (st,) = iam.statements(doc)
    assert st["actions"] == ["s3:GetObject"] and st["resources"] == ["*"] and st["effect"] == "Allow"
    assert iam.statements("not json") == [] and iam.statements(None) == []


def test_public_principal_string_is_normalised():
    (st,) = iam.statements({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]})
    assert st["principals"] == {"AWS": ["*"]}


@pytest.mark.parametrize("actions, expected", [
    (["s3:GetObject", "s3:ListBucket"], ["read"]),
    (["dynamodb:PutItem", "dynamodb:GetItem"], ["write", "read"]),
    (["kms:Decrypt", "kms:GenerateDataKey"], ["read"]),
    (["lambda:*"], ["full"]),
    (["iam:PassRole"], ["permissions"]),
    (["iam:GetRole"], ["read"]),
    (["s3:PutBucketPolicy"], ["permissions"]),
    (["*"], ["full"]),
])
def test_action_levels(actions, expected):
    assert iam.level_of(actions) == expected


def test_wildcard_matching():
    keys = ["arn:aws:s3:::a", "arn:aws:s3:::a/x", "arn:aws:s3:::b"]
    assert iam.match_keys("arn:aws:s3:::a*", keys) == keys[:2]
    assert iam.match_keys("arn:aws:s3:::b", keys) == [keys[2]]
    assert iam.match_keys("arn:aws:s3:::nope", keys) == []


# ------------------------------------------------------------------------------------------------ AWS
@pytest.fixture(scope="module")
def aws():
    pytest.importorskip("moto")
    return run_demo("aws", lambda _m: None)


def test_aws_every_identity_service_is_itemized(aws):
    from collections import Counter
    c = Counter(r["type"] for r in aws["resources"])
    assert c["aws.iam.user"] == 3 and c["aws.iam.group"] == 2 and c["aws.iam.role"] == 7
    assert c["aws.kms.key"] == 3 and c["aws.secretsmanager.secret"] == 2 and c["aws.ssm.parameter"] == 2
    assert all(r["category"] == "security" for r in aws["resources"] if r["type"].startswith(("aws.iam.", "aws.kms", "aws.secrets", "aws.ssm")))


def test_aws_what_identities_control(aws):
    t = triples(aws, {"access"})
    assert ("web-instance-role", "prod/db/password", "access") in t
    assert ("web-instance-role", "acme-prod-assets", "access") in t
    assert ("order-processor-role", "orders", "access") in t
    assert ("ecs-exec-role", "prod/api/stripe-key", "access") in t
    assert ("developers", "thumbnailer", "access") in t                     # group policy: lambda:* on *
    assert ("ci-bot", "acme-prod-assets", "access") in t                    # user inline policy / bucket policy
    assert ("deploy-role", "acme-uploads", "access") in t


def test_aws_access_edges_carry_level_and_actions(aws):
    names = {r["id"]: r["name"] for r in aws["resources"]}
    e = next(e for e in aws["edges"] if e["kind"] == "access" and names[e["source"]] == "web-instance-role" and names[e["target"]] == "acme-prod-assets")
    assert e["label"].startswith("read:") and "s3:GetObject" in e["label"]
    kms = next(e for e in aws["edges"] if e["kind"] == "access" and names[e["target"]] == "app-data" and names[e["source"]] == "web-instance-role")
    assert kms["label"].startswith("read:")                                  # kms:Decrypt is a *use*, not a write


def test_aws_who_runs_as_which_role_and_group_membership(aws):
    t = triples(aws, {"identity", "member", "assume"})
    assert ("web-1", "web-instance-role", "identity") in t                  # via instance profile
    assert ("order-processor", "order-processor-role", "identity") in t
    assert ("checkout", "ecs-task-role", "identity") in t and ("checkout", "ecs-exec-role", "identity") in t
    assert ("alice", "admins", "member") in t and ("bob", "developers", "member") in t
    assert ("ci-bot", "deploy-role", "assume") in t


def test_aws_encryption_and_secret_use(aws):
    t = triples(aws, {"encrypts", "uses"})
    for target in ("orders-db", "orders", "orders-queue", "order-events", "acme-uploads", "prod/db/password", "/prod/app/api_token"):
        assert ("app-data", target, "encrypts") in t, target
    assert ("log-archive", "acme-prod-logs", "encrypts") in t                # key referenced by alias
    assert ("checkout", "prod/api/stripe-key", "uses") in t and ("checkout", "/prod/app/db_url", "uses") in t


def test_aws_risk_signals_are_properties(aws):
    r = by_name(aws)
    assert r["admins"]["props"]["admin_access"] is True
    assert "EXTERNAL" in " ".join(r["deploy-role"]["props"]["trusted_principals"])
    assert r["legacy-open-role"]["props"]["trust_public"] is True
    assert r["acme-prod-assets"]["props"]["public_policy"] is True
    assert r["orders-queue"]["props"]["service_principals"] == ["sns.amazonaws.com"]
    assert r["alice"]["props"]["console_access"] is True and r["alice"]["props"]["mfa_enabled"] is False
    assert r["retired-signing"]["props"]["state"] == "Disabled" and r["app-data"]["props"]["rotation_enabled"] is True


def test_aws_hides_service_linked_roles_and_aws_managed_keys(aws):
    names = {r["name"] for r in aws["resources"]}
    assert not any(n.startswith("AWSServiceRole") for n in names)
    assert not any(r["props"].get("managed_by") == "aws" for r in aws["resources"] if r["type"] == "aws.kms.key")


def test_aws_never_collects_secret_values(aws):
    blob = json.dumps(aws)
    for needle in PLACEHOLDER_SECRETS:
        assert needle not in blob, needle


# ---------------------------------------------------------------------------------------------- Azure
@pytest.fixture(scope="module")
def azure():
    rows, names, tenant = azure_rows()
    return az.build_graph(rows, names, tenant, azure_identity()).to_dict()


@pytest.mark.parametrize("role, perms, expected", [
    ("Owner", [{"actions": ["*"]}], "full"),
    ("Contributor", [{"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Write"]}], "write"),
    ("Reader", [{"actions": ["*/read"]}], "read"),
    ("User Access Administrator", [{"actions": ["*/read", "Microsoft.Authorization/*"]}], "permissions"),
    ("Key Vault Secrets User", [{"actions": ["Microsoft.KeyVault/vaults/read"], "dataActions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action"]}], "read"),
    ("Blob Writer", [{"dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"]}], "write"),
    ("Owner", None, "full"),
])
def test_azure_role_levels(role, perms, expected):
    assert azure_iam.role_level(role, perms) == expected


def test_azure_role_assignments_become_access_edges(azure):
    t = triples(azure, {"access"})
    assert ("Alice Admin (alice@contoso.example)", "Contoso Production", "access") in t
    assert ("Platform Engineers", "App-RG", "access") in t
    assert ("orders-func", "acme-kv", "access") in t                         # system-assigned identity -> the function itself
    assert ("orders-uai", "acmeprodstorage", "access") in t                  # user-assigned identity
    assert ("platform-aks", "spoke-app", "access") in t
    names = {r["id"]: r["name"] for r in azure["resources"]}
    e = next(e for e in azure["edges"] if names[e["source"]] == "orders-func" and names[e["target"]] == "acme-kv" and e["kind"] == "access")
    assert e["label"] == "Key Vault Secrets User (read)"


def test_azure_identity_attachment_admin_and_unresolved_principals(azure):
    r = by_name(azure)
    assert ("orders-func", "orders-uai", "identity") in triples(azure, {"identity"})
    assert r["orders-func"]["props"]["identity"] == "system + user-assigned"
    assert r["Alice Admin (alice@contoso.example)"]["props"]["admin_access"] is True
    ghost = next(x for x in azure["resources"] if x["props"].get("name_unresolved"))
    assert ghost["name"].startswith("user ") and "Reader on subscription" in ghost["props"]["roles"]


def test_azure_key_vault_items_cmk_and_secret_links(azure):
    t = triples(azure, {"contains", "encrypts", "uses", "access"})
    assert {("acme-kv", n, "contains") for n in ("storage-cmk", "cosmos-cmk", "db-password", "stripe-api-key", "agw-cert")} <= t
    assert ("storage-cmk", "acmeprodstorage", "encrypts") in t              # split keyvaulturi + keyname shape
    assert ("cosmos-cmk", "acme-cosmos", "encrypts") in t                   # full key URL shape
    assert ("app-agw", "agw-cert", "uses") in t
    assert ("Alice Admin (alice@contoso.example)", "acme-kv", "access") in t   # legacy access policy
    r = by_name(azure)
    assert r["stripe-api-key"]["props"]["enabled"] is False and r["acme-kv"]["props"]["rbac_authorization"] is False
    assert not any(k in ("value", "secret_value") for x in azure["resources"] for k in x["props"])


def test_azure_graph_principal_names_are_folded_in():
    names: dict = {}
    azure_iam.apply_principal_names(names, [
        {"@odata.type": "#microsoft.graph.user", "id": "ABC", "displayName": "Dana", "userPrincipalName": "d@x"},
        {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "DEF", "displayName": "pipeline"}])
    assert names["abc"] == {"name": "Dana", "type": "User"} and names["def"]["type"] == "ServicePrincipal"


def test_azure_without_identity_data_still_builds():
    rows, names, tenant = azure_rows()
    g = az.build_graph(rows, names, tenant).to_dict()          # identity=None: no role assignments, no crash
    assert not [e for e in g["edges"] if e["kind"] == "access" and "Alice" in str(e)]


# ------------------------------------------------------------------------------------------------- GCP
@pytest.fixture(scope="module")
def gcp_graph():
    return gcp.build_graph(gcp_assets(), "acme-prod", gcp_policies()).to_dict()


@pytest.mark.parametrize("role, expected", [
    ("roles/owner", "full"), ("roles/editor", "write"), ("roles/viewer", "read"), ("roles/storage.admin", "full"),
    ("roles/storage.objectViewer", "read"), ("roles/secretmanager.secretAccessor", "read"),
    ("roles/cloudkms.cryptoKeyEncrypterDecrypter", "read"), ("roles/iam.serviceAccountUser", "permissions"),
    ("roles/resourcemanager.organizationAdmin", "permissions"), ("roles/pubsub.publisher", "write"),
    ("projects/acme-prod/roles/customThing", None),
])
def test_gcp_role_levels(role, expected):
    assert gcp_iam.role_level(role) == expected


def test_gcp_every_identity_service_is_itemized(gcp_graph):
    from collections import Counter
    c = Counter(r["type"] for r in gcp_graph["resources"])
    assert c["iam.googleapis.com/ServiceAccount"] == 6 and c["cloudkms.googleapis.com/CryptoKey"] == 3
    assert c["cloudkms.googleapis.com/KeyRing"] == 2 and c["secretmanager.googleapis.com/Secret"] == 3


def test_gcp_bindings_runs_as_cmek_and_secrets(gcp_graph):
    t = triples(gcp_graph, {"access", "identity", "encrypts", "uses"})
    assert ("web-sa", "db-password", "access") in t and ("functions-sa", "jwt-secret", "access") in t
    assert ("web-sa", "app-data", "access") in t and ("bob@acme.example", "ci-deployer", "access") in t
    assert ("web-1", "web-sa", "identity") in t and ("platform-gke", "gke-nodes-sa", "identity") in t
    assert ("checkout", "db-password", "uses") in t and ("thumbnailer", "jwt-secret", "uses") in t    # secretKeyRef + {secret, projectId}
    assert {("app-data", "orders-pg", "encrypts"), ("app-data", "orders", "encrypts"),
            ("backup-key", "acme-backups", "encrypts"), ("backup-key", "stripe-key", "encrypts")} <= t
    assert ("alice@acme.example", "Acme Production", "access") in t         # project-number policy name resolved to the project


def test_gcp_risk_signals(gcp_graph):
    r = by_name(gcp_graph)
    assert r["acme-prod-assets"]["props"]["public_access"] == ["roles/storage.objectViewer"]
    assert r["Anyone on the internet"]["props"]["public"] is True
    assert r["alice@acme.example"]["props"]["admin_access"] is True
    assert r["ci-deployer"]["props"]["user_managed_keys"] == 2 and "web-sa" in r and "user_managed_keys" not in r["web-sa"]["props"]
    assert r["old.hire@acme.example [deleted]"]["props"]["deleted"] is True
    assert r["legacy-sa"]["props"]["disabled"] is True
    assert r["backup-key"]["props"]["rotation"] == "no automatic rotation" and r["app-data"]["props"]["rotation"] == "every 90 days"
    assert "roles/resourcemanager.organizationAdmin on organization" in r["org-admins@acme.example"]["props"]["roles"]


def test_gcp_without_policies_still_builds():
    g = gcp.build_graph(gcp_assets(), "acme-prod").to_dict()
    assert not [e for e in g["edges"] if e["kind"] == "access"] and any(e["kind"] == "identity" for e in g["edges"])


# ------------------------------------------------------------------------------ table view (browser)
@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    try:
        pw = sync_api.sync_playwright().start()
        b = pw.chromium.launch()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"no browser available: {e}")
    yield b
    b.close()
    pw.stop()


def open_page(browser, tmp_path, graph):
    f = tmp_path / "p.html"
    f.write_text(render_html(graph), encoding="utf-8")
    page = browser.new_page(viewport={"width": 1500, "height": 950})
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f.as_uri())
    page.wait_for_selector("g.node")
    return page, errors


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_table_view_itemizes_everything_with_connections(cloud, browser, tmp_path):
    graph = run_demo(cloud, lambda _m: None)
    page, errors = open_page(browser, tmp_path, graph)
    leaves = [r for r in graph["resources"] if not r["container"]]
    page.click("#v-table")
    page.wait_for_selector("tr.row")
    assert page.locator("tr.row").count() == len(graph["resources"])           # containers included by default
    page.locator("#tableview input[type=checkbox]").uncheck()
    assert page.locator("tr.row").count() == len(leaves)

    # an identity row lists what it controls; the resource it touches lists who can reach it
    leaf_ids = {r["id"] for r in leaves}
    ident = next(r for r in leaves if r["category"] == "security"
                 and any(e["kind"] == "access" and e["source"] == r["id"] and e["target"] in leaf_ids for e in graph["edges"]))
    named = lambda n: page.locator(f"tr.row:has(.tname:text-is({json.dumps(n)}))").first  # noqa: E731
    row = named(ident["name"])
    assert "Access (permission)" in row.inner_text()
    target = next(e["target"] for e in graph["edges"] if e["kind"] == "access" and e["source"] == ident["id"] and e["target"] in leaf_ids)
    tname = next(r["name"] for r in graph["resources"] if r["id"] == target)
    named(tname).click()
    assert "connected from / used by" in page.locator("#details").inner_text().lower()

    page.fill("#q", ident["name"])
    n = page.locator("tr.row").count()
    assert 1 <= n < len(leaves)
    page.fill("#q", "")
    page.click("th:has-text('Name')")                                           # sorting flips direction
    first_asc = page.locator("tr.row .tname").first.inner_text()
    page.click("th:has-text('Name')")
    assert page.locator("tr.row .tname").first.inner_text() != first_asc

    page.get_by_role("button", name="Past week", exact=True).click()           # sidebar date filter drives the table
    ref = __import__("datetime").datetime.fromisoformat(graph["generated"])
    expected = sum(__import__("datetime").datetime.fromisoformat(r["created"]) >= ref - __import__("datetime").timedelta(days=7) for r in leaves if r["created"])
    assert page.locator("tr.row").count() == expected
    page.get_by_role("button", name="All time", exact=True).click()

    page.click("#v-diagram")
    page.wait_for_timeout(100)
    assert page.locator("g.node").count() == len(leaves)
    assert not errors, errors
    page.close()


def test_csv_export_lists_connections_and_neutralises_formulas(browser, tmp_path):
    graph = {"provider": "aws", "account": "x", "generated": "2026-10-28T12:00:00+00:00", "warnings": [], "types": {}, "resources": [
        {"id": "a", "type": "t", "name": "=HYPERLINK(\"http://evil\")", "parent": None, "category": "security", "container": False,
         "created": None, "props": {"k": "v"}, "tags": {}},
        {"id": "b", "type": "t", "name": "bucket, with comma", "parent": None, "category": "storage", "container": False,
         "created": "2026-10-01T00:00:00+00:00", "props": {}, "tags": {}}],
        "edges": [{"source": "a", "target": "b", "kind": "access", "label": "read: s3:GetObject"}]}
    page, errors = open_page(browser, tmp_path, graph)
    csv = page.evaluate("window.__cloudmap.tableCSV()")
    lines = csv.lstrip("﻿").split("\r\n")
    assert lines[0].startswith("Name,Type,Category")
    assert "'=HYPERLINK" in csv and "\n=HYPERLINK" not in csv and ',=HYPERLINK' not in csv      # formula injection defused
    assert '"bucket, with comma"' in csv
    assert "Access (permission) → bucket, with comma (read: s3:GetObject)" in csv.replace('"', "")
    assert not errors
    page.close()


# ------------------------------------------------------------------------------------ least privilege
def test_aws_policy_file_covers_calls_and_never_grants_secret_values():
    from pathlib import Path
    actions = {a for st in json.loads((Path(__file__).parent.parent / "iam-policy.json").read_text())["Statement"] for a in st["Action"]}
    for needed in ("iam:GetAccountAuthorizationDetails", "kms:GetKeyPolicy", "secretsmanager:ListSecrets",
                   "secretsmanager:GetResourcePolicy", "ssm:DescribeParameters", "s3:GetBucketPolicy", "ecs:DescribeTaskDefinition"):
        assert needed in actions, needed
    forbidden = {"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
                 "kms:Decrypt", "kms:GenerateDataKey", "s3:GetObject"}
    assert not forbidden & actions


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_connection_presets_split_identity_from_infrastructure(cloud, browser, tmp_path):
    graph = run_demo(cloud, lambda _m: None)
    ident = {"access", "assume", "identity", "member", "encrypts", "uses"}
    page, errors = open_page(browser, tmp_path, graph)
    drawn = lambda: page.locator("path.edge").count()  # noqa: E731
    everything = drawn()
    page.get_by_role("button", name="Identity & access only").click()
    only_ident = drawn()
    page.get_by_role("button", name="Infrastructure only").click()
    only_infra = drawn()
    assert 0 < only_ident < everything and only_infra < everything
    page.get_by_role("button", name="All", exact=True).click()
    assert drawn() == everything
    # every drawn identity arrow is an identity kind, and the preset's checkboxes agree with the state
    page.get_by_role("button", name="Identity & access only").click()
    classes = page.locator("path.edge").evaluate_all("els => els.map(e => e.getAttribute('class'))")
    assert all(any(f"k-{k}" in c.split() for k in ident) for c in classes)
    assert not errors, errors
    page.close()


def test_risk_flags_are_searchable_by_name(browser, tmp_path):
    pytest.importorskip("moto")
    graph = run_demo("aws", lambda _m: None)
    page, errors = open_page(browser, tmp_path, graph)
    page.click("#v-table")
    for flag, expected in (("admin_access", {"admins"}), ("public_policy", {"acme-prod-assets"}), ("trust_public", {"legacy-open-role"})):
        page.fill("#q", flag)
        names = set(page.locator("tr.row .tname").all_inner_texts())
        assert expected <= names and len(names) <= 3, (flag, names)
    assert not errors
    page.close()
