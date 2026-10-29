"""Azure + GCP mapping (offline, fixture-driven), time parsing, and the sidebar date filter in a real browser.

The fixtures have the shape Azure Resource Graph / Cloud Asset Inventory return, so build_graph() - the
code a live scan runs - is what's under test. The thin SDK fetch layer is not exercised here (no account).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from cloudmap.demo import run_demo
from cloudmap.fixtures import azure_identity, azure_rows, gcp_assets, gcp_policies
from cloudmap.model import parse_time
from cloudmap.providers import azure as az, gcp
from cloudmap.render import render_html


# ------------------------------------------------------------------------------------ time parsing
@pytest.mark.parametrize("raw, expected", [
    ("2024-03-01T08:15:30.123-08:00", "2024-03-01T16:15:30+00:00"),
    ("2023-01-01T00:00:00.123456789Z", "2023-01-01T00:00:00+00:00"),     # GCP nanoseconds
    ("2024-03-01T08:15:30+0000", "2024-03-01T08:15:30+00:00"),
    ("2024-03-01", "2024-03-01T00:00:00+00:00"),
    (1709280000, "2024-03-01T08:00:00+00:00"),                           # epoch seconds (SQS)
    ("1709280000000", "2024-03-01T08:00:00+00:00"),                      # epoch ms string (BigQuery)
    (datetime(2024, 3, 1, 8, 15), "2024-03-01T08:15:00+00:00"),
    ("garbage", None), (None, None), ("", None), (0, None), (True, None),
])
def test_parse_time(raw, expected):
    assert parse_time(raw) == expected


# ----------------------------------------------------------------------------------------- Azure
@pytest.fixture(scope="module")
def azure_graph():
    rows, names, tenant = azure_rows()
    return az.build_graph(rows, names, tenant, azure_identity()).to_dict()


def _chain(graph, name):
    by_id = {r["id"]: r for r in graph["resources"]}
    cur, out = next(r for r in graph["resources"] if r["name"] == name), []
    while cur:
        out.append(cur["name"])
        cur = by_id.get(cur["parent"])
    return out


def _edges(graph):
    names = {r["id"]: r["name"] for r in graph["resources"]}
    return sorted((names[e["source"]], names[e["target"]], e["kind"]) for e in graph["edges"])


def test_azure_vm_is_nested_via_its_nic(azure_graph):
    assert _chain(azure_graph, "web-vm-1")[:5] == ["web-vm-1", "web", "spoke-app", "App-RG", "Contoso Production"]


def test_azure_connections(azure_graph):
    edges = _edges(azure_graph)
    assert ("app-agw", "web-vm-1", "traffic") in edges
    assert ("app-ilb", "app-vm-2", "traffic") in edges
    assert ("sql-pe", "acme-sql", "private-link") in edges
    assert ("acme-sql", "orders", "contains") in edges
    assert ("data", "data-nat", "route") in edges
    assert sum(k == "peering" for _, _, k in edges) == 1      # listed on both VNets, drawn once


def test_azure_function_app_and_power_state(azure_graph):
    by_name = {r["name"]: r for r in azure_graph["resources"]}
    assert azure_graph["types"][by_name["orders-func"]["type"]]["label"] == "Function App"
    assert by_name["dr-standby"]["props"]["state"] == "deallocated"      # 'PowerState/' prefix stripped
    assert by_name["web-vm-1"]["props"]["state"] == "running"


def test_azure_plumbing_hidden_and_dates_present(azure_graph):
    types = {r["type"] for r in azure_graph["resources"]}
    assert "microsoft.network/networkinterfaces" not in types
    leaves = [r for r in azure_graph["resources"] if not r["container"] and not r["type"].startswith("azure.identity.")]
    assert sum(1 for r in leaves if r["created"]) >= len(leaves) - 2      # directory principals have no creation date


def test_azure_arm_created_time_beats_properties():
    row = {"createdTime": "2024-05-01T10:00:00Z", "properties": {"timeCreated": "2020-01-01T00:00:00Z"}}
    assert az._created(row) == "2024-05-01T10:00:00Z"
    assert az._created({"properties": {"creationTime": "2020-01-01T00:00:00Z"}}) == "2020-01-01T00:00:00Z"


# ------------------------------------------------------------------------------------------ GCP
@pytest.fixture(scope="module")
def gcp_graph():
    return gcp.build_graph(gcp_assets(), "acme-prod", gcp_policies()).to_dict()


def test_gcp_nesting(gcp_graph):
    assert _chain(gcp_graph, "web-1") == ["web-1", "app-us", "prod-vpc", "Acme Production"]
    assert _chain(gcp_graph, "platform-gke")[:3] == ["platform-gke", "app-us", "prod-vpc"]
    assert _chain(gcp_graph, "orders-pg") == ["orders-pg", "us-central1", "Acme Production"]


def test_gcp_buckets_resolve_to_their_project_by_number(gcp_graph):
    # bucket asset names carry no project id - only a parent project *number*
    projects = {r["name"] for r in gcp_graph["resources"] if r["type"] == "gcp.project"}
    assert projects == {"Acme Production"}
    assert _chain(gcp_graph, "acme-uploads")[-1] == "Acme Production"


def test_gcp_load_balancer_chain_and_events(gcp_graph):
    edges = _edges(gcp_graph)
    assert ("web-fr", "web-bes", "traffic") in edges        # forwarding rule -> proxy -> url map -> backend service
    assert ("web-bes", "web-mig", "traffic") in edges       # backend service -> managed instance group
    assert ("orders", "thumbnailer", "trigger") in edges
    assert ("orders", "orders-sub", "event") in edges


def test_gcp_unused_default_network_is_pruned(gcp_graph):
    assert "default" not in {r["name"] for r in gcp_graph["resources"]}


def test_gcp_date_sources(gcp_graph):
    by_name = {r["name"]: r for r in gcp_graph["resources"]}
    assert by_name["analytics"]["created"]                   # BigQuery: epoch milliseconds
    assert by_name["orders"]["created"] is None              # Pub/Sub exposes no creation time
    assert by_name["legacy-hook"]["props"]["date_basis"] == "last modified"
    assert "date_basis" not in by_name["thumbnailer"]["props"]


# ------------------------------------------------------------------- the date filter, in a browser
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


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_date_filter(cloud, browser, tmp_path):
    graph = run_demo(cloud, lambda _m: None)
    ref = datetime.fromisoformat(graph["generated"])
    leaves = [r for r in graph["resources"] if not r["container"]]
    known = [r for r in leaves if r["created"]]
    assert 0 < len(known) < len(leaves), "demo data should include some undated resources"
    expected = lambda days: sum(datetime.fromisoformat(r["created"]) >= ref - timedelta(days=days) for r in known)  # noqa: E731

    f = tmp_path / "page.html"
    f.write_text(render_html(graph), encoding="utf-8")
    page = browser.new_page(viewport={"width": 1500, "height": 950})
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f.as_uri())
    page.wait_for_selector("g.node")
    nodes = lambda: page.locator("g.node").count()  # noqa: E731
    click = lambda name: (page.get_by_role("button", name=name, exact=True).click(), page.wait_for_timeout(80))  # noqa: E731
    assert nodes() == len(leaves)

    for label, days in (("Past year", 365), ("Past month", 30), ("Past week", 7)):
        click(label)
        assert nodes() == expected(days), label                 # undated resources are excluded once a range is set
        assert page.locator(".sumline b").first.inner_text() == str(expected(days))
    click("All time")
    assert nodes() == len(leaves)

    for gran in ("Year", "Month", "Week", "Day"):               # click the busiest bar at each grouping
        click(gran)
        bars = page.locator(".hbg")
        counts = [int(bars.nth(i).get_attribute("aria-label").split("·")[1].split()[0]) for i in range(bars.count())]
        busiest = max(range(len(counts)), key=counts.__getitem__)
        bars.nth(busiest).click()
        page.wait_for_timeout(80)
        assert nodes() == counts[busiest], gran
        bars.nth(busiest).click()                               # clicking the active bar clears the filter
        page.wait_for_timeout(80)
        assert nodes() == len(leaves)

    page.locator("input[type=date]").nth(0).fill("2099-01-01")  # nothing is that new -> friendly empty state
    page.wait_for_timeout(80)
    assert nodes() == 0 and page.locator("#empty:not(.hidden)").count() == 1
    click("Reset")
    click("Past year")
    before = nodes()
    page.locator("#inc-unknown").check()
    page.wait_for_timeout(80)
    assert nodes() == before + (len(leaves) - len(known))        # the toggle adds back exactly the undated ones
    assert not errors, errors
    page.close()


def test_filtering_keeps_a_new_container_but_drops_old_empty_ones(browser, tmp_path):
    graph = {"provider": "gcp", "account": "x", "generated": "2026-10-28T12:00:00+00:00", "warnings": [], "types": {},
             "edges": [], "resources": [
        {"id": "p", "type": "t", "name": "proj", "parent": None, "category": "container", "container": True, "created": None, "props": {}, "tags": {}},
        {"id": "old", "type": "t", "name": "old-vpc", "parent": "p", "category": "container", "container": True, "created": "2020-01-01T00:00:00+00:00", "props": {}, "tags": {}},
        {"id": "new", "type": "t", "name": "new-vpc", "parent": "p", "category": "container", "container": True, "created": "2026-10-26T00:00:00+00:00", "props": {}, "tags": {}},
        {"id": "vm", "type": "t", "name": "old-vm", "parent": "old", "category": "compute", "container": False, "created": "2020-01-02T00:00:00+00:00", "props": {}, "tags": {}},
        {"id": "vm2", "type": "t", "name": "recent-vm", "parent": "old", "category": "compute", "container": False, "created": "2026-10-25T00:00:00+00:00", "props": {}, "tags": {}},
    ]}
    f = tmp_path / "p.html"
    f.write_text(render_html(graph), encoding="utf-8")
    page = browser.new_page()
    page.goto(f.as_uri())
    page.get_by_role("button", name="Past week", exact=True).click()
    page.wait_for_timeout(100)
    names = page.locator("g.box").evaluate_all("els => els.map(e => e.textContent)")   # SVG has no innerText
    assert any("new-vpc" in n for n in names)        # created in range, though empty -> kept
    assert any("old-vpc" in n for n in names)        # holds a recent resource -> kept
    assert page.locator("g.node").count() == 1       # only recent-vm
    page.close()
