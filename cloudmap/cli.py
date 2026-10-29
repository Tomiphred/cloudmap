"""Command line entry point:  python -m cloudmap aws --out architecture.html"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, providers
from .render import render_html


AUTH_HINTS = {
    "aws": "Configure credentials with `aws configure`, `aws sso login`, or AWS_* environment variables (use --profile to pick one).",
    "azure": "Sign in with `az login` (or set AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET); the identity needs the Reader role.",
    "gcp": "Run `gcloud auth application-default login` (or set GOOGLE_APPLICATION_CREDENTIALS); needs Cloud Asset Viewer and the Cloud Asset API enabled.",
}


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudmap",
        description="Discover a cloud environment (read-only) and draw it as an architecture diagram.")
    p.add_argument("--version", action="version", version=f"cloudmap {__version__}")
    sub = p.add_subparsers(dest="provider", required=True, metavar="PROVIDER")
    for name in providers.names():
        if not providers.is_implemented(name):
            sp = sub.add_parser(name, help="(planned - not implemented yet)")
            sp.set_defaults(_unavailable=f"The '{name}' provider is planned but not implemented yet.")
            continue
        try:
            cls = providers.load(name)
        except ImportError as e:
            sp = sub.add_parser(name, help=f"(missing dependency: {e.name})")
            sp.set_defaults(_unavailable=f"Provider '{name}' needs a missing package: pip install {e.name}")
            continue
        sp = sub.add_parser(name, help=f"scan {name.upper()}")
        cls.add_arguments(sp)
        sp.add_argument("--out", default=f"{name}-architecture.html", help="HTML diagram to write")
        sp.add_argument("--json", metavar="FILE", help="also write the raw graph as JSON")
        sp.add_argument("--demo", action="store_true",
                        help="scan a mock environment instead of a real account (needs: pip install moto)")
        sp.set_defaults(_cls=cls)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "_unavailable", None):
        _log(args._unavailable)
        return 2

    try:
        if args.demo:
            from .demo import run_demo
            graph = run_demo(args.provider, _log)
        else:
            graph = args._cls.from_args(args, _log).discover().to_dict()
    except Exception as e:  # noqa: BLE001 - turn SDK stack traces into one readable line
        if os.environ.get("CLOUDMAP_DEBUG"):
            raise
        name, msg = type(e).__name__, (str(e).strip().splitlines() or [""])[0][:200]
        _log(f"{args.provider} scan failed: {name}: {msg}")
        if "credential" in (name + str(e)).lower() or "auth" in name.lower():
            _log(AUTH_HINTS.get(args.provider, "Check your credentials and try again."))
        _log("(set CLOUDMAP_DEBUG=1 for the full traceback)")
        return 1

    out = Path(args.out)
    out.write_text(render_html(graph), encoding="utf-8")
    _log(f"Diagram written to {out.resolve()}")
    if args.json:
        Path(args.json).write_text(json.dumps(graph, indent=2, default=str), encoding="utf-8")
        _log(f"Graph JSON written to {Path(args.json).resolve()}")
    for w in graph.get("warnings", []):
        _log(f"  note: {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
