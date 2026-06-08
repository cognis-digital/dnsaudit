"""Command-line interface for DNSAUDIT.

Usage:
    python -m dnsaudit audit --input demos/02-deep/records.json
    python -m dnsaudit audit --domain example.com --spf "v=spf1 -all" \
        --dmarc "v=DMARC1; p=reject; rua=mailto:d@example.com" --typosquats
    python -m dnsaudit typosquat --domain paypal.com --format json
    python -m dnsaudit --version

Input can come from a JSON file (--input) or directly via flags. Everything is
offline. Exit code is non-zero when findings warrant attention (HIGH+ or
spoofable), making it CI-friendly.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    audit_domain,
    generate_typosquats,
    AuditResult,
    SEVERITY_ORDER,
)


def _load_input(args) -> dict:
    data = {"domain": None, "spf": None, "dmarc": None, "dkim": None,
            "dnssec": None, "caa": None}
    if getattr(args, "input", None):
        with open(args.input, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        for k in data:
            if k in loaded:
                data[k] = loaded[k]
    if getattr(args, "domain", None):
        data["domain"] = args.domain
    for k in ("spf", "dmarc", "dkim"):
        v = getattr(args, k, None)
        if v is not None:
            data[k] = v
    if getattr(args, "dnssec", None):
        data["dnssec"] = True
    if not data["domain"]:
        data["domain"] = "unknown"
    return data


def _render_audit_table(res: AuditResult) -> str:
    L = []
    L.append("=" * 66)
    L.append(f" DNSAUDIT  {res.domain}")
    L.append("=" * 66)
    L.append(f" Grade      : {res.grade}   (score {res.score}/100)")
    L.append(f" Spoofable  : {'YES — at risk' if res.spoofable else 'no'}")
    L.append(f" SPF        : {'present' if res.spf['present'] else 'MISSING'}"
             + (f"  all={res.spf['all']}  lookups={res.spf['lookups']}"
                if res.spf['present'] else ""))
    L.append(f" DMARC      : {'present' if res.dmarc['present'] else 'MISSING'}"
             + (f"  p={res.dmarc['tags'].get('p', 'none')}"
                if res.dmarc['present'] else ""))
    L.append(f" DKIM       : {'present' if res.dkim['present'] else 'MISSING'}"
             + (f"  ~{res.dkim['key_bits']}-bit"
                if res.dkim['present'] and res.dkim.get('key_bits') else ""))
    L.append(f" DNSSEC     : {'signed' if res.dnssec['signed'] else 'UNSIGNED'}")
    L.append(f" CAA        : {'present' if res.caa['present'] else 'MISSING'}"
             + (f"  issuers={','.join(res.caa['issue']) or '-'}"
                if res.caa['present'] else ""))
    L.append("-" * 66)
    if not res.findings:
        L.append(" No findings. Posture looks strong.")
    else:
        L.append(f" Findings ({len(res.findings)}):")
        for f in res.findings:
            L.append(f"  [{f.severity:<8}] {f.record}/{f.code}")
            L.append(f"      {f.message}")
            if f.recommendation:
                L.append(f"      -> {f.recommendation}")
    if res.typosquats:
        L.append("-" * 66)
        L.append(f" Typosquats generated ({len(res.typosquats)}):")
        by_fuzzer: dict = {}
        for t in res.typosquats:
            by_fuzzer.setdefault(t["fuzzer"], []).append(t["domain"])
        for fuzzer in sorted(by_fuzzer):
            doms = by_fuzzer[fuzzer]
            sample = ", ".join(doms[:6]) + (" ..." if len(doms) > 6 else "")
            L.append(f"  {fuzzer:<14} ({len(doms):>3}): {sample}")
    L.append("=" * 66)
    return "\n".join(L)


def _render_typo_table(domain: str, typos: List[dict]) -> str:
    L = ["=" * 60, f" DNSAUDIT typosquats  {domain}", "=" * 60,
         f" {len(typos)} candidate domains", "-" * 60]
    for t in typos:
        L.append(f"  {t['fuzzer']:<14} {t['domain']}")
    L.append("=" * 60)
    return "\n".join(L)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Grade SPF/DKIM/DMARC/DNSSEC/CAA posture (A–F) and "
                    "generate typosquat domains — offline.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="Audit a domain's DNS/email posture.")
    a.add_argument("--input", help="JSON file with records.")
    a.add_argument("--domain", help="Domain name.")
    a.add_argument("--spf", help="Raw SPF TXT record.")
    a.add_argument("--dmarc", help="Raw DMARC TXT record.")
    a.add_argument("--dkim", help="Raw DKIM public-key TXT record.")
    a.add_argument("--dnssec", action="store_true",
                   help="Flag the zone as DNSSEC-signed.")
    a.add_argument("--typosquats", action="store_true",
                   help="Also generate typosquat permutations.")
    a.add_argument("--format", choices=["table", "json"], default="table",
                   help="Output format.")
    a.add_argument("--output", "-o", help="Write report to this file.")

    t = sub.add_parser("typosquat",
                       help="Generate dnstwist-style typosquat domains.")
    t.add_argument("--domain", required=True, help="Domain to permute.")
    t.add_argument("--tld", action="append", default=[],
                   help="Extra TLD for tld-swap (repeatable).")
    t.add_argument("--limit", type=int, default=0,
                   help="Cap number of results (0 = unlimited).")
    t.add_argument("--format", choices=["table", "json"], default="table",
                   help="Output format.")
    t.add_argument("--output", "-o", help="Write report to this file.")
    return p


def _emit(out: str, output_path: Optional[str]) -> int:
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(out)
            print(f"report written to {output_path}", file=sys.stderr)
        except OSError as exc:
            print(f"error: could not write output: {exc}", file=sys.stderr)
            return 2
    else:
        print(out)
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "typosquat":
        typos = generate_typosquats(args.domain, extra_tlds=args.tld,
                                    max_results=args.limit)
        if args.format == "json":
            out = json.dumps({"tool": TOOL_NAME, "version": TOOL_VERSION,
                              "domain": args.domain, "count": len(typos),
                              "typosquats": typos}, indent=2)
        else:
            out = _render_typo_table(args.domain, typos)
        rc = _emit(out, args.output)
        if rc:
            return rc
        # Non-zero exit when squat surface exists (there is something to watch).
        return 1 if typos else 0

    if args.command != "audit":
        parser.print_help()
        return 2

    if not args.input and not (args.domain or args.spf or args.dmarc
                               or args.dkim):
        parser.error("provide --input or at least one of "
                     "--domain/--spf/--dmarc/--dkim")

    try:
        data = _load_input(args)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read input: {exc}", file=sys.stderr)
        return 2

    res = audit_domain(
        data["domain"], data.get("spf"), data.get("dmarc"), data.get("dkim"),
        dnssec=data.get("dnssec"), caa=data.get("caa"),
        with_typosquats=args.typosquats)

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2)
    else:
        out = _render_audit_table(res)

    rc = _emit(out, args.output)
    if rc:
        return rc

    worst = res.worst_severity
    if res.spoofable or SEVERITY_ORDER[worst] >= SEVERITY_ORDER["HIGH"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
