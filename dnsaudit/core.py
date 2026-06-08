"""DNSAUDIT — DNS posture scanner (offline / fixture-based)."""
from __future__ import annotations
import json, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "DNSAUDIT"
TOOL_VERSION = "0.1.0"

# Demo mode: reads `dns-records.json` per domain. In production, plug into dnspython.

def _check_domain(domain: str, records: dict) -> list[Finding]:
    out: list[Finding] = []
    spf = next((v for v in records.get("TXT",[]) if v.startswith("v=spf1")), None)
    if not spf:
        out.append(Finding(id="DNS-SPF-001", severity="high", weight=2.5, title="MISSING_SPF",
                           description=f"{domain}: No SPF record found.", location=domain,
                           remediation="Publish v=spf1 ... -all", category="email-auth"))
    elif spf.endswith("+all") or " ?all" in spf:
        out.append(Finding(id="DNS-SPF-002", severity="medium", weight=2.0, title="LAX_SPF",
                           description=f"{domain}: SPF uses permissive qualifier ({spf!r})",
                           location=domain, remediation="Switch to -all or ~all", category="email-auth"))
    dmarc = next((v for v in records.get("_dmarc",[]) if "v=DMARC1" in v), None)
    if not dmarc:
        out.append(Finding(id="DNS-DMARC-001", severity="high", weight=2.5, title="MISSING_DMARC",
                           description=f"{domain}: No DMARC record.", location=f"_dmarc.{domain}",
                           remediation="Publish v=DMARC1; p=quarantine; rua=...", category="email-auth"))
    elif "p=none" in dmarc:
        out.append(Finding(id="DNS-DMARC-002", severity="medium", weight=2.0, title="DMARC_MONITOR_ONLY",
                           description=f"{domain}: DMARC p=none (monitor only)",
                           location=f"_dmarc.{domain}", remediation="Move to p=quarantine then p=reject.",
                           category="email-auth"))
    if not records.get("CAA"):
        out.append(Finding(id="DNS-CAA-001", severity="low", weight=1.5, title="MISSING_CAA",
                           description=f"{domain}: No CAA record (any CA may issue certs)",
                           location=domain, remediation="Publish CAA for letsencrypt, digicert, etc.",
                           category="cert-issuance"))
    return out

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    domains = {}
    if p.is_file():
        domains = json.loads(p.read_text())
    elif p.is_dir():
        for jf in p.rglob("*.json"):
            domains.update(json.loads(jf.read_text()))
    result.items_scanned = len(domains)
    for d, rec in domains.items():
        result.add_findings(_check_domain(d, rec))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
