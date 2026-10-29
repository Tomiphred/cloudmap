"""End-to-end test: build a fake AWS estate with moto, scan it with the real AWS provider,
render the HTML, and (if Chromium is available) check the page actually draws without errors.

    pip install -e ".[dev]" && pytest -q
"""
from __future__ import annotations

import json
import re
from collections import Counter

import pytest

pytest.importorskip("moto")

from cloudmap.demo import run_demo  # noqa: E402
from cloudmap.model import Edge, Graph, Resource  # noqa: E402
from cloudmap.render import render_html  # noqa: E402


@pytest.fixture(scope="module")
def graph() -> dict:
    return run_demo("aws", lambda _m: None)


def test_scan_finds_core_resources(graph):
    types = Counter(r["type"] for r in graph["resources"])
    for expected in ("aws.ec2.vpc", "aws.ec2.subnet", "aws.ec2.instance", "aws.elbv2.alb",
                     "aws.rds.instance", "aws.lambda.function", "aws.s3.bucket", "aws.sqs.queue",
                     "aws.sns.topic", "aws.dynamodb.table", "aws.cloudfront.distribution"):
        assert types[expected] >= 1, f"missing {expected}"


def test_nesting_is_account_region_vpc_subnet(graph):
    by_id = {r["id"]: r for r in graph["resources"]}
    web = next(r for r in graph["resources"] if r["name"] == "web-1")
    chain = []
    cur = web
    while cur:
        chain.append(cur["type"])
        cur = by_id.get(cur["parent"])
    assert chain == ["aws.ec2.instance", "aws.ec2.subnet", "aws.ec2.vpc", "aws.region", "aws.account"]


def test_public_subnet_detected_from_routes(graph):
    subnets = {r["name"]: r for r in graph["resources"] if r["type"] == "aws.ec2.subnet"}
    assert subnets["public-a"]["props"]["public"] is True
    assert not subnets["app-a"]["props"].get("public")


def test_expected_connections(graph):
    names = {r["id"]: r["name"] for r in graph["resources"]}
    triples = {(names[e["source"]], names[e["target"]], e["kind"]) for e in graph["edges"]}
    assert ("prod-alb", "web-1", "traffic") in triples
    assert ("orders-queue", "order-processor", "trigger") in triples
    assert ("orders-queue", "orders-dlq", "dead-letter") in triples
    assert ("order-events", "orders-queue", "event") in triples
    assert ("acme-uploads", "thumbnailer", "event") in triples
    assert ("prod-vpc", "shared-services", "peering") in triples


def test_default_vpcs_are_hidden(graph):
    assert not any(r["props"].get("default") for r in graph["resources"] if r["type"] == "aws.ec2.vpc")


def test_no_secrets_collected(graph):
    blob = json.dumps(graph)
    assert "never-read-by-scanner" not in blob      # Lambda env var value
    assert "ops@example.com" not in blob            # SNS email endpoint
    assert "demo-not-real-pw1" not in blob          # DB password


def test_graph_edges_are_never_dangling(graph):
    ids = {r["id"] for r in graph["resources"]}
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])


def test_html_escapes_hostile_names():
    g = Graph("aws", "1")
    g.add(Resource(id="a", type="x", name="</script><img src=x onerror=alert(1)>"))
    html = render_html(g.finalize().to_dict())
    assert "</script><img" not in html
    assert len(re.findall(r"</script>", html)) == 2   # data block + app script only


def test_finalize_resolves_arns_and_prunes_empty_regions():
    g = Graph("aws", "1")
    g.add(Resource(id="acct", type="t", name="acct", container=True))
    g.add(Resource(id="region:x", type="t", name="x", parent="acct", container=True, prune_empty=True))
    g.add(Resource(id="q", type="t", name="q", arn="arn:q"))
    g.add(Resource(id="f", type="t", name="f", arn="arn:f"))
    g.link("arn:q", "arn:f", "trigger")
    g.link("q", "ghost", "trigger")          # dangling -> dropped
    g.finalize()
    assert "region:x" not in g.resources
    assert g.edges == [Edge("q", "f", "trigger", "")]


def test_page_renders_in_browser(graph, tmp_path):
    sync_api = pytest.importorskip("playwright.sync_api")
    page_file = tmp_path / "arch.html"
    page_file.write_text(render_html(graph), encoding="utf-8")
    try:
        pw = sync_api.sync_playwright().start()
        browser = pw.chromium.launch()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"no browser available: {e}")
    try:
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(page_file.as_uri())
        page.wait_for_selector("g.node")
        n_nodes = sum(1 for r in graph["resources"] if not r["container"])
        assert page.locator("g.node").count() == n_nodes
        assert page.locator("path.edge").count() == len(graph["edges"])
        page.locator("g.node", has_text="prod-alb").click()
        assert page.locator("#details:not(.hidden)").count() == 1
        assert not errors, errors
    finally:
        browser.close()
        pw.stop()
