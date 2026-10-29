"""Render a graph dict into one self-contained, offline-capable HTML file."""
from __future__ import annotations

import json
from html import escape
from pathlib import Path

_TEMPLATE = Path(__file__).with_name("template.html")


def render_html(graph: dict) -> str:
    # '<' is escaped so resource names/tags can never close the <script> block early.
    payload = json.dumps(graph, default=str, ensure_ascii=False).replace("<", "\\u003c")
    title = f"{graph.get('provider', 'cloud').upper()} architecture"
    if graph.get("account"):
        title += f" - {graph['account']}"
    html = _TEMPLATE.read_text(encoding="utf-8")
    return html.replace("/*__TITLE__*/", escape(title)).replace("/*__DATA__*/", payload)
