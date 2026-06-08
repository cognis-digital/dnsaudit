"""Core DNS posture audit engine — standard library only.

No third-party DNS libraries. The default resolver shells out to nothing and
uses a minimal DNS-over-TCP query against a configurable nameserver via the
``socket`` module. For tests and offline scans, a DictResolver returns canned
records so no network access is needed.
"""

from __future__ import annotations

import dataclasses
import random
import socket
import struct
from typing import Dict, List, Optional, Sequence

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Common DKIM selectors to probe when none is supplied.
DEFAULT_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail")


@dataclasses.dataclass
class Finding:
    """A single posture observation."""

    check: str
    severity: str  # info|low|medium|high|critical
    message: str
    record: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AuditReport:
    domain: str
    findings: List[Finding] = dataclasses.field(default_factory=list)
    records: Dict[str, List[str]] = dataclasses.field(default_factory=dict)

    @property
    def score(self) -> int:
        """0-100 posture score; deductions weighted by severity."""
        weights = {"info": 0, "low": 3, "medium": 8, "high": 18, "critical": 30}
        deduction = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - deduction)

    @property
    def grade(self) -> str:
        return grade(self.score)

    @property
    def ok(self) -> bool:
        """True when no high/critical findings are present."""
        return not any(f.severity in ("high", "critical") for f in self.findings)

    def to_dict(self) -> Dict[str, object]:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "ok": self.ok,
            "records": self.records,
            "findings": [f.to_dict() for f in self.findings],
        }


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# --------------------------------------------------------------------------- #
# Resolvers
# --------------------------------------------------------------------------- #
class Resolver:
    """Abstract resolver interface."""

    def txt(self, name: str) -> List[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def has_dnskey(self, name: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class DictResolver(Resolver):
    """Offline resolver backed by canned data. Used in tests / fixtures.

    ``txt_records`` maps a fully-qualified name to a list of TXT strings.
    ``dnssec`` is a set of names that have a DNSKEY record.
    """

    def __init__(self, txt_records: Optional[Dict[str, Sequence[str]]] = None,
                 dnssec: Optional[Sequence[str]] = None) -> None:
        self._txt = {k.rstrip(".").lower(): list(v) for k, v in (txt_records or {}).items()}
        self._dnssec = {n.rstrip(".").lower() for n in (dnssec or [])}

    def txt(self, name: str) -> List[str]:
        return list(self._txt.get(name.rstrip(".").lower(), []))

    def has_dnskey(self, name: str) -> bool:
        return name.rstrip(".").lower() in self._dnssec


class StdlibResolver(Resolver):
    """Minimal DNS-over-TCP resolver using only the socket/struct modules."""

    def __init__(self, server: str = "1.1.1.1", timeout: float = 5.0) -> None:
        self.server = server
        self.timeout = timeout

    def _query(self, name: str, qtype: int) -> List[bytes]:
        qname = b"".join(
            struct.pack("B", len(lbl)) + lbl.encode("idna" if any(ord(c) > 127 for c in lbl) else "ascii")
            for lbl in name.rstrip(".").split(".")
        ) + b"\x00"
        txid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack(">HH", qtype, 1)
        msg = header + question
        with socket.create_connection((self.server, 53), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(struct.pack(">H", len(msg)) + msg)
            length = struct.unpack(">H", _recvall(sock, 2))[0]
            resp = _recvall(sock, length)
        return _parse_answers(resp, qtype)

    def txt(self, name: str) -> List[str]:
        out: List[str] = []
        for rdata in self._query(name, 16):  # TXT = 16
            # TXT rdata: one or more length-prefixed character-strings
            parts, i = [], 0
            while i < len(rdata):
                slen = rdata[i]
                parts.append(rdata[i + 1:i + 1 + slen].decode("utf-8", "replace"))
                i += 1 + slen
            out.append("".join(parts))
        return out

    def has_dnskey(self, name: str) -> bool:
        try:
            return bool(self._query(name, 48))  # DNSKEY = 48
        except OSError:
            return False


def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-message")
        buf += chunk
    return buf


def _parse_answers(resp: bytes, want_type: int) -> List[bytes]:
    """Parse a DNS response, returning rdata blobs matching want_type."""
    if len(resp) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off) + 4  # name + qtype + qclass
    answers: List[bytes] = []
    for _ in range(an):
        off = _skip_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == want_type:
            answers.append(rdata)
    return answers


def _skip_name(buf: bytes, off: int) -> int:
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:  # compression pointer
            return off + 2
        off += 1 + ln
    return off


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def parse_spf(record: str) -> Dict[str, object]:
    """Parse an SPF record into mechanisms and the terminating all-qualifier."""
    tokens = record.split()
    mechanisms = [t for t in tokens[1:]]
    all_qual = None
    lookups = 0
    for tok in mechanisms:
        low = tok.lower()
        if low in ("-all", "~all", "?all", "+all", "all"):
            all_qual = low
        if low.lstrip("+-~?").split(":")[0].split("=")[0] in (
            "include", "a", "mx", "ptr", "exists", "redirect"
        ):
            lookups += 1
    return {"mechanisms": mechanisms, "all": all_qual, "lookups": lookups}


def parse_dmarc(record: str) -> Dict[str, str]:
    """Parse a DMARC record into its tag=value pairs."""
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _check_spf(domain: str, resolver: Resolver, report: AuditReport) -> None:
    txts = resolver.txt(domain)
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    report.records["spf"] = spfs
    if not spfs:
        report.findings.append(Finding("spf", "high", "No SPF record found; sender forgery is unrestricted."))
        return
    if len(spfs) > 1:
        report.findings.append(Finding("spf", "high", "Multiple SPF records found; RFC 7208 requires exactly one."))
    spf = parse_spf(spfs[0])
    if spf["all"] in (None,):
        report.findings.append(Finding("spf", "medium", "SPF has no 'all' mechanism; policy is undefined.", spfs[0]))
    elif spf["all"] in ("+all", "all"):
        report.findings.append(Finding("spf", "critical", "SPF ends with '+all' — any host may send as this domain.", spfs[0]))
    elif spf["all"] == "?all":
        report.findings.append(Finding("spf", "medium", "SPF uses '?all' (neutral); offers no protection.", spfs[0]))
    elif spf["all"] == "~all":
        report.findings.append(Finding("spf", "low", "SPF uses '~all' (softfail); '-all' is stronger.", spfs[0]))
    if any(m.lower().lstrip("+-~?").startswith("ptr") for m in spf["mechanisms"]):
        report.findings.append(Finding("spf", "low", "SPF uses deprecated 'ptr' mechanism.", spfs[0]))
    if spf["lookups"] > 10:
        report.findings.append(Finding("spf", "medium", f"SPF declares {spf['lookups']} DNS-lookup mechanisms; limit is 10 (RFC 7208).", spfs[0]))


def _check_dmarc(domain: str, resolver: Resolver, report: AuditReport) -> None:
    name = f"_dmarc.{domain}"
    txts = [t for t in resolver.txt(name) if t.lower().startswith("v=dmarc1")]
    report.records["dmarc"] = txts
    if not txts:
        report.findings.append(Finding("dmarc", "high", "No DMARC record found; receivers cannot enforce alignment."))
        return
    tags = parse_dmarc(txts[0])
    policy = tags.get("p", "").lower()
    if policy == "none":
        report.findings.append(Finding("dmarc", "medium", "DMARC policy is 'none' (monitor only); move to quarantine/reject.", txts[0]))
    elif policy == "":
        report.findings.append(Finding("dmarc", "high", "DMARC record missing required 'p=' policy tag.", txts[0]))
    elif policy not in ("quarantine", "reject"):
        report.findings.append(Finding("dmarc", "medium", f"DMARC policy '{policy}' is not a valid enforcement value.", txts[0]))
    if "rua" not in tags:
        report.findings.append(Finding("dmarc", "low", "DMARC has no 'rua' aggregate-report address; you are blind to abuse.", txts[0]))
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        report.findings.append(Finding("dmarc", "low", f"DMARC pct={pct}; policy applies to only part of traffic.", txts[0]))


def _check_dkim(domain: str, resolver: Resolver, report: AuditReport,
                selectors: Sequence[str]) -> None:
    found: List[str] = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = [t for t in resolver.txt(name) if "p=" in t.lower() or t.lower().startswith("v=dkim1")]
        if txts:
            found.append(f"{sel}: {txts[0]}")
            if "p=" in txts[0] and txts[0].split("p=", 1)[1].strip().rstrip(";").strip() == "":
                report.findings.append(Finding("dkim", "medium", f"DKIM selector '{sel}' has an empty public key (revoked).", txts[0]))
    report.records["dkim"] = found
    if not found:
        report.findings.append(Finding("dkim", "medium", f"No DKIM key found for probed selectors ({', '.join(selectors)}); messages may be unsigned."))


def _check_caa(domain: str, resolver: Resolver, report: AuditReport) -> None:
    # CAA stored as TXT-style fixture entries under a sentinel name for offline use.
    txts = resolver.txt(f"_caa.{domain}")
    report.records["caa"] = txts
    if not txts:
        report.findings.append(Finding("caa", "low", "No CAA record; any CA may issue certificates for this domain."))


def _check_dnssec(domain: str, resolver: Resolver, report: AuditReport) -> None:
    enabled = resolver.has_dnskey(domain)
    report.records["dnssec"] = ["enabled"] if enabled else []
    if not enabled:
        report.findings.append(Finding("dnssec", "low", "DNSSEC not enabled; responses are not cryptographically signed."))


def audit_domain(domain: str, resolver: Resolver,
                 dkim_selectors: Optional[Sequence[str]] = None) -> AuditReport:
    """Run the full posture audit for ``domain`` using ``resolver``."""
    domain = domain.strip().rstrip(".").lower()
    if not domain or " " in domain or "." not in domain:
        raise ValueError(f"invalid domain: {domain!r}")
    report = AuditReport(domain=domain)
    _check_spf(domain, resolver, report)
    _check_dkim(domain, resolver, report, dkim_selectors or DEFAULT_DKIM_SELECTORS)
    _check_dmarc(domain, resolver, report)
    _check_caa(domain, resolver, report)
    _check_dnssec(domain, resolver, report)
    report.findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return report
