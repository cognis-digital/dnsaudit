"""Command-line interface for DNSAUDIT."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    AuditReport,
    DictResolver,
    StdlibResolver,
    audit_domain,
)


def _load_fixture(path: str) -> DictResolver:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return DictResolver(txt_records=data.get("txt", {}), dnssec=data.get("dnssec", []))


def _render_table(report: AuditReport) -> str:
    lines = [
        f"DNSAUDIT report for {report.domain}",
        f"  score: {report.score}/100  grade: {report.grade}  status: {'PASS' if report.ok else 'FAIL'}",
        "",
        f"  {'SEVERITY':<9} {'CHECK':<8} MESSAGE",
        f"  {'-'*8:<9} {'-'*7:<8} {'-'*40}",
    ]
    if not report.findings:
        lines.append("  (no findings — posture is clean)")
    for f in report.findings:
        lines.append(f"  {f.severity.upper():<9} {f.check:<8} {f.message}")
    return "\n".join(lines)


def _emit(report: AuditReport, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(_render_table(report))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="DNS posture & misconfiguration scanner (SPF/DKIM/DMARC/DNSSEC/CAA).",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a domain's DNS security posture.")
    scan.add_argument("domain", help="Domain to audit, e.g. example.com")
    scan.add_argument("--format", choices=["table", "json"], default="table",
                      help="Output format (default: table).")
    scan.add_argument("--fixture", help="Path to a JSON resolver fixture (offline mode).")
    scan.add_argument("--server", default="1.1.1.1", help="DNS server for live queries (default: 1.1.1.1).")
    scan.add_argument("--selector", action="append", dest="selectors",
                      help="DKIM selector to probe (repeatable).")
    scan.add_argument("--fail-under", type=int, default=None,
                      help="Exit non-zero if the score is below this threshold.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            resolver = _load_fixture(args.fixture) if args.fixture else StdlibResolver(server=args.server)
            report = audit_domain(args.domain, resolver, dkim_selectors=args.selectors)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"error: DNS query failed: {exc}", file=sys.stderr)
            return 3
        _emit(report, args.format)
        if args.fail_under is not None and report.score < args.fail_under:
            return 1
        return 0 if report.ok else 1

    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
