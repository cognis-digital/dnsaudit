"""DNSAUDIT engine — real SPF/DKIM/DMARC/DNSSEC/CAA posture grading and
dnstwist-style typosquat permutation generation. Standard library only.

The audit logic mirrors the test battery internet.nl runs for email security,
adapted to operate purely on records you supply (no live DNS). The typosquat
engine reimplements the core permutation families from dnstwist (insertion,
omission, repetition, replacement, transposition, bitsquatting, homoglyph,
hyphenation, subdomain, vowel-swap, addition, TLD-swap).

Everything is offline, deterministic, and dependency-free.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional

TOOL_NAME = "dnsaudit"
TOOL_VERSION = "2.0.0"

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Point penalty subtracted from a 100 baseline per finding severity.
SEVERITY_WEIGHT = {"INFO": 0, "LOW": 4, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 34}


@dataclass
class Finding:
    record: str          # spf | dmarc | dkim | dnssec | caa | domain
    code: str            # short machine code
    severity: str        # INFO..CRITICAL
    message: str
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditResult:
    domain: str
    grade: str
    score: int
    spoofable: bool
    spf: dict
    dmarc: dict
    dkim: dict
    dnssec: dict
    caa: dict
    findings: List[Finding] = field(default_factory=list)
    typosquats: List[dict] = field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        worst = "INFO"
        for f in self.findings:
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(worst, 0):
                worst = f.severity
        return worst

    def to_dict(self) -> dict:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "domain": self.domain,
            "grade": self.grade,
            "score": self.score,
            "spoofable": self.spoofable,
            "worst_severity": self.worst_severity,
            "spf": self.spf,
            "dmarc": self.dmarc,
            "dkim": self.dkim,
            "dnssec": self.dnssec,
            "caa": self.caa,
            "findings": [f.to_dict() for f in self.findings],
            "typosquats": self.typosquats,
        }


# --------------------------------------------------------------------------- #
# Record parsers
# --------------------------------------------------------------------------- #
def parse_spf(raw: Optional[str]) -> dict:
    """Parse an SPF TXT record into structured posture data."""
    out = {"present": False, "raw": raw, "all": None, "mechanisms": [],
           "includes": [], "lookups": 0, "redirect": None, "valid": False}
    if not raw:
        return out
    raw = raw.strip().strip('"')
    if not raw.lower().startswith("v=spf1"):
        return out
    out["present"] = True
    out["valid"] = True
    tokens = raw.split()[1:]
    for tok in tokens:
        low = tok.lower()
        if low in ("-all", "~all", "?all", "+all", "all"):
            out["all"] = tok
            continue
        out["mechanisms"].append(tok)
        if low.startswith("include:"):
            out["includes"].append(tok.split(":", 1)[1])
            out["lookups"] += 1
        elif low.startswith("redirect="):
            out["redirect"] = tok.split("=", 1)[1]
            out["lookups"] += 1
        elif low.startswith("exists:"):
            out["lookups"] += 1
        elif low in ("a", "mx", "ptr") or low.startswith(("a:", "mx:", "a/", "mx/")):
            out["lookups"] += 1
    return out


def parse_dmarc(raw: Optional[str]) -> dict:
    """Parse a DMARC TXT record (_dmarc.<domain>) into tag map."""
    out = {"present": False, "raw": raw, "tags": {}, "valid": False}
    if not raw:
        return out
    raw = raw.strip().strip('"')
    if not raw.lower().startswith("v=dmarc1"):
        return out
    out["present"] = True
    out["valid"] = True
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out["tags"][k.strip().lower()] = v.strip()
    return out


_DKIM_KEY_RE = re.compile(r"p=([A-Za-z0-9+/=]+)")


def parse_dkim(raw: Optional[str]) -> dict:
    """Parse a DKIM public-key TXT record and estimate the RSA key size."""
    out = {"present": False, "raw": raw, "tags": {}, "key_bits": None,
           "revoked": False, "valid": False}
    if not raw:
        return out
    raw = raw.strip().strip('"')
    out["present"] = True
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out["tags"][k.strip().lower()] = v.strip()
    pkey = out["tags"].get("p", None)
    if pkey is not None and pkey == "":
        out["revoked"] = True   # empty p= means the key is revoked
    m = _DKIM_KEY_RE.search(raw)
    if m and m.group(1):
        # base64 length -> raw DER bytes -> rough modulus bit estimate.
        b64 = m.group(1)
        der_bytes = (len(b64) * 3) // 4
        out["key_bits"] = _estimate_rsa_bits(der_bytes)
        out["valid"] = True
    return out


def _estimate_rsa_bits(der_bytes: int) -> int:
    """Map an X.509 SubjectPublicKeyInfo DER length to a nominal RSA key size."""
    # SPKI overhead for an RSA key is ~38 bytes (algorithm id + bit-string).
    modulus_bytes = max(der_bytes - 38, 1)
    bits = modulus_bytes * 8
    for nominal in (512, 768, 1024, 2048, 3072, 4096):
        if bits <= nominal + 64:
            return nominal
    return 4096


def parse_caa(raw: Optional[List[str]]) -> dict:
    """Parse CAA records into issuers + iodef contacts."""
    out = {"present": False, "issue": [], "issuewild": [], "iodef": [],
           "records": []}
    if not raw:
        return out
    if isinstance(raw, str):
        raw = [raw]
    for line in raw:
        line = line.strip().strip('"')
        if not line:
            continue
        out["records"].append(line)
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        _flag, tag, value = parts
        tag = tag.lower()
        value = value.strip().strip('"')
        if tag == "issue":
            out["issue"].append(value)
        elif tag == "issuewild":
            out["issuewild"].append(value)
        elif tag == "iodef":
            out["iodef"].append(value)
    out["present"] = bool(out["records"])
    return out


def parse_dnssec(raw) -> dict:
    """Normalize a DNSSEC posture descriptor.

    Accepts a bool, a dict ({signed, algorithm, ds_present}), or a string
    ('signed'/'unsigned').
    """
    out = {"signed": False, "algorithm": None, "ds_present": False,
           "raw": raw}
    if raw is None:
        return out
    if isinstance(raw, bool):
        out["signed"] = raw
        return out
    if isinstance(raw, str):
        out["signed"] = raw.strip().lower() in ("signed", "true", "yes", "1")
        return out
    if isinstance(raw, dict):
        out["signed"] = bool(raw.get("signed"))
        out["algorithm"] = raw.get("algorithm")
        out["ds_present"] = bool(raw.get("ds_present"))
    return out


# DNSSEC signing algorithms that are deprecated / cryptographically weak.
WEAK_DNSSEC_ALGOS = {1, 3, 5, 6, 7, "RSAMD5", "DSA", "RSASHA1",
                     "DSA-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1"}


# --------------------------------------------------------------------------- #
# Audit logic
# --------------------------------------------------------------------------- #
def _audit_spf(spf: dict, findings: List[Finding]) -> None:
    if not spf["present"]:
        findings.append(Finding(
            "spf", "SPF_MISSING", "HIGH",
            "No SPF record published. Receivers cannot validate which hosts "
            "may send mail for this domain.",
            "Publish a TXT record beginning with 'v=spf1' that lists your "
            "senders and ends in '-all'."))
        return
    allv = (spf["all"] or "").lower()
    if allv in ("+all", "all"):
        findings.append(Finding(
            "spf", "SPF_PLUS_ALL", "CRITICAL",
            "SPF ends in '+all' — any host on the internet is authorized to "
            "send as this domain.",
            "Change the terminal mechanism to '-all' (hard fail)."))
    elif allv == "?all":
        findings.append(Finding(
            "spf", "SPF_NEUTRAL_ALL", "MEDIUM",
            "SPF ends in '?all' (neutral) — unauthorized senders are not "
            "flagged.",
            "Tighten to '~all' (softfail) or '-all' (hardfail)."))
    elif allv == "~all":
        findings.append(Finding(
            "spf", "SPF_SOFT_ALL", "LOW",
            "SPF ends in '~all' (softfail). Mail from unlisted hosts is "
            "accepted but marked.",
            "Move to '-all' once you have confirmed all legitimate senders "
            "are listed."))
    elif allv == "" or spf["all"] is None:
        findings.append(Finding(
            "spf", "SPF_NO_ALL", "MEDIUM",
            "SPF record has no terminal 'all' mechanism; default is neutral.",
            "Append '-all' (or '~all') as the final mechanism."))
    if spf["lookups"] > 10:
        findings.append(Finding(
            "spf", "SPF_TOO_MANY_LOOKUPS", "MEDIUM",
            f"SPF requires {spf['lookups']} DNS lookups, exceeding the RFC 7208 "
            "limit of 10 — evaluation will PermError.",
            "Flatten includes or remove unused senders to stay under 10 "
            "lookups."))
    if any(m.lower() == "ptr" or m.lower().startswith("ptr:")
           for m in spf["mechanisms"]):
        findings.append(Finding(
            "spf", "SPF_PTR_MECH", "LOW",
            "SPF uses the deprecated 'ptr' mechanism (slow, unreliable, "
            "discouraged by RFC 7208).",
            "Replace 'ptr' with explicit 'ip4'/'ip6'/'a'/'mx' mechanisms."))


def _audit_dmarc(dmarc: dict, findings: List[Finding]) -> None:
    if not dmarc["present"]:
        findings.append(Finding(
            "dmarc", "DMARC_MISSING", "HIGH",
            "No DMARC record published — the domain has no published policy "
            "against spoofing and no reporting.",
            "Publish '_dmarc' TXT starting 'v=DMARC1; p=reject; "
            "rua=mailto:dmarc@yourdomain'."))
        return
    tags = dmarc["tags"]
    p = tags.get("p", "none").lower()
    if p == "none":
        findings.append(Finding(
            "dmarc", "DMARC_P_NONE", "HIGH",
            "DMARC policy is 'p=none' — monitoring only; spoofed mail is not "
            "blocked.",
            "After validating reports, move to 'p=quarantine' then "
            "'p=reject'."))
    elif p == "quarantine":
        findings.append(Finding(
            "dmarc", "DMARC_P_QUARANTINE", "LOW",
            "DMARC policy is 'p=quarantine'. Spoofed mail is junked but not "
            "rejected.",
            "Advance to 'p=reject' for full protection."))
    pct = tags.get("pct")
    if pct is not None and pct.isdigit() and int(pct) < 100:
        findings.append(Finding(
            "dmarc", "DMARC_PCT_PARTIAL", "MEDIUM",
            f"DMARC applies to only {pct}% of mail (pct={pct}).",
            "Set 'pct=100' so the policy applies to all messages."))
    if "rua" not in tags:
        findings.append(Finding(
            "dmarc", "DMARC_NO_RUA", "MEDIUM",
            "DMARC has no aggregate reporting address (rua=). You are blind to "
            "spoofing attempts.",
            "Add 'rua=mailto:dmarc-reports@yourdomain' to receive aggregate "
            "reports."))
    sp = tags.get("sp")
    if sp is not None and sp.lower() == "none" and p != "none":
        findings.append(Finding(
            "dmarc", "DMARC_SP_NONE", "MEDIUM",
            "Subdomain policy 'sp=none' weakens protection — subdomains can be "
            "spoofed even though the org domain is protected.",
            "Remove 'sp' (inherits p) or set 'sp=reject'."))
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    if adkim == "r" and aspf == "r" and p in ("reject", "quarantine"):
        findings.append(Finding(
            "dmarc", "DMARC_RELAXED_ALIGN", "INFO",
            "DMARC uses relaxed alignment (adkim=r, aspf=r) — acceptable but "
            "strict alignment is more spoof-resistant.",
            "Consider 'adkim=s; aspf=s' if your senders support it."))


def _audit_dkim(dkim: dict, findings: List[Finding]) -> None:
    if not dkim["present"]:
        findings.append(Finding(
            "dkim", "DKIM_MISSING", "MEDIUM",
            "No DKIM public key supplied. Without DKIM, forwarded mail and "
            "DMARC alignment are fragile.",
            "Publish a DKIM key (selector._domainkey) and sign outbound "
            "mail."))
        return
    if dkim["revoked"]:
        findings.append(Finding(
            "dkim", "DKIM_REVOKED", "MEDIUM",
            "DKIM record has an empty public key (p=) — the selector is "
            "revoked.",
            "Remove the revoked selector or publish a valid key."))
        return
    bits = dkim.get("key_bits")
    if bits is not None and bits < 1024:
        findings.append(Finding(
            "dkim", "DKIM_WEAK_KEY", "HIGH",
            f"DKIM key is ~{bits}-bit RSA — below 1024 bits and trivially "
            "forgeable.",
            "Rotate to a 2048-bit RSA key."))
    elif bits is not None and bits < 2048:
        findings.append(Finding(
            "dkim", "DKIM_KEY_1024", "LOW",
            f"DKIM key is ~{bits}-bit RSA. 1024-bit keys are accepted but "
            "2048-bit is the current recommendation.",
            "Rotate to a 2048-bit RSA key."))
    if dkim["tags"].get("t", "").lower() == "y":
        findings.append(Finding(
            "dkim", "DKIM_TEST_MODE", "LOW",
            "DKIM selector is in test mode (t=y); receivers may ignore signing "
            "failures.",
            "Remove 't=y' once signing is verified in production."))


def _audit_dnssec(dnssec: dict, findings: List[Finding]) -> None:
    if not dnssec["signed"]:
        findings.append(Finding(
            "dnssec", "DNSSEC_UNSIGNED", "MEDIUM",
            "Zone is not DNSSEC-signed — responses can be forged via cache "
            "poisoning / on-path tampering.",
            "Enable DNSSEC at your DNS provider and publish a DS record at the "
            "registrar."))
        return
    if not dnssec.get("ds_present", True):
        findings.append(Finding(
            "dnssec", "DNSSEC_NO_DS", "MEDIUM",
            "Zone is signed but no DS record is published at the parent — the "
            "chain of trust is broken, so DNSSEC is not actually enforced.",
            "Publish the DS record at your registrar to complete the chain of "
            "trust."))
    algo = dnssec.get("algorithm")
    if algo is not None and algo in WEAK_DNSSEC_ALGOS:
        findings.append(Finding(
            "dnssec", "DNSSEC_WEAK_ALGO", "MEDIUM",
            f"DNSSEC uses a weak/deprecated signing algorithm ({algo}).",
            "Roll the zone to a modern algorithm such as ECDSAP256SHA256 "
            "(13)."))


def _audit_caa(caa: dict, findings: List[Finding]) -> None:
    if not caa["present"]:
        findings.append(Finding(
            "caa", "CAA_MISSING", "LOW",
            "No CAA record — any certificate authority may issue certificates "
            "for this domain.",
            "Publish a CAA record restricting issuance to your CA(s), e.g. "
            "'0 issue \"letsencrypt.org\"'."))
        return
    if not caa["iodef"]:
        findings.append(Finding(
            "caa", "CAA_NO_IODEF", "INFO",
            "CAA has no 'iodef' contact — you will not be notified of "
            "unauthorized issuance attempts.",
            "Add '0 iodef \"mailto:security@yourdomain\"'."))
    if any(v == ";" for v in caa["issuewild"]):
        findings.append(Finding(
            "caa", "CAA_WILD_BLOCKED", "INFO",
            "Wildcard issuance is explicitly disallowed (issuewild \";\").",
            ""))


def grade_score(findings: List[Finding]) -> tuple:
    """Compute a 0–100 score and an A–F letter grade from findings."""
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    if score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 65:
        letter = "C"
    elif score >= 50:
        letter = "D"
    else:
        letter = "F"
    return letter, score


def _is_spoofable(spf: dict, dmarc: dict) -> bool:
    """A domain is trivially spoofable if it lacks an enforcing DMARC policy
    AND lacks a hard-fail SPF."""
    p = dmarc.get("tags", {}).get("p", "none").lower() if dmarc["present"] else "none"
    dmarc_enforces = p in ("quarantine", "reject")
    spf_hardfail = spf["present"] and (spf["all"] or "").lower() == "-all"
    return not (dmarc_enforces or spf_hardfail)


def audit_domain(domain: Optional[str], spf=None, dmarc=None, dkim=None,
                 dnssec=None, caa=None, with_typosquats: bool = False,
                 typo_tlds: Optional[List[str]] = None) -> AuditResult:
    """Run the full posture audit and (optionally) generate typosquats."""
    domain = domain or "unknown"
    spf_d = parse_spf(spf)
    dmarc_d = parse_dmarc(dmarc)
    dkim_d = parse_dkim(dkim)
    dnssec_d = parse_dnssec(dnssec)
    caa_d = parse_caa(caa)

    findings: List[Finding] = []
    _audit_spf(spf_d, findings)
    _audit_dmarc(dmarc_d, findings)
    _audit_dkim(dkim_d, findings)
    _audit_dnssec(dnssec_d, findings)
    _audit_caa(caa_d, findings)

    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    letter, score = grade_score(findings)
    spoofable = _is_spoofable(spf_d, dmarc_d)

    typos: List[dict] = []
    if with_typosquats and domain and domain != "unknown":
        typos = generate_typosquats(domain, extra_tlds=typo_tlds)

    return AuditResult(
        domain=domain, grade=letter, score=score, spoofable=spoofable,
        spf=spf_d, dmarc=dmarc_d, dkim=dkim_d, dnssec=dnssec_d, caa=caa_d,
        findings=findings, typosquats=typos)


# --------------------------------------------------------------------------- #
# Typosquat permutation engine (dnstwist-style)
# --------------------------------------------------------------------------- #
# QWERTY physical-adjacency map: each key -> keys a fat finger could hit.
KEYBOARD_ADJACENT = {
    "q": "was", "w": "qesad", "e": "wrdsf", "r": "etfdg", "t": "ryfgh",
    "y": "tugfh", "u": "yihjk", "i": "uojkl", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13qw", "3": "24we", "4": "35er", "5": "46rt",
    "6": "57ty", "7": "68yu", "8": "79ui", "9": "80io", "0": "9op",
}

# Visually confusable ASCII substitutions (homoglyph family).
HOMOGLYPHS = {
    "a": ["4", "@"], "b": ["d", "lb", "8"], "c": ["e"], "d": ["b", "cl"],
    "e": ["c", "3"], "f": ["t"], "g": ["q", "9"], "h": ["lh", "n"],
    "i": ["1", "l", "j", "!"], "j": ["i"], "k": ["lc"], "l": ["1", "i", "I"],
    "m": ["n", "nn", "rn", "rr"], "n": ["m", "r"], "o": ["0", "q"],
    "p": ["q"], "q": ["g", "9", "p"], "r": ["n"], "s": ["5", "$"],
    "t": ["f", "7"], "u": ["v", "w"], "v": ["u", "w"], "w": ["vv", "uu"],
    "x": ["×"], "y": ["v"], "z": ["2"],
    "0": ["o"], "1": ["l", "i"], "5": ["s"], "6": ["b"], "8": ["b"],
    "9": ["g", "q"],
}

VOWELS = "aeiou"

# A broad, realistic TLD set an attacker would consider for a swap.
COMMON_TLDS = [
    "com", "net", "org", "info", "biz", "co", "io", "app", "dev", "xyz",
    "online", "site", "shop", "store", "cloud", "club", "live", "link",
    "top", "vip", "icu", "cc", "tv", "me", "us", "uk", "ca", "de", "fr",
    "ru", "cn", "in", "br", "au", "eu", "email", "finance", "support",
    "security", "login", "help", "net.co", "com.co",
]


def _split_domain(domain: str) -> tuple:
    """Split 'mail.example.co.uk' into (subdomain, sld, tld).

    Uses a small multi-label-TLD set so 'example.co.uk' splits correctly.
    """
    domain = domain.strip().lower().rstrip(".")
    multi_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au",
                  "com.br", "com.co", "co.jp", "co.in", "co.za", "com.cn"}
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in multi_tlds:
        tld = ".".join(labels[-2:])
        rest = labels[:-2]
    elif len(labels) >= 2:
        tld = labels[-1]
        rest = labels[:-1]
    else:
        return "", domain, ""
    sld = rest[-1] if rest else ""
    sub = ".".join(rest[:-1]) if len(rest) > 1 else ""
    return sub, sld, tld


def _ins(name: str) -> set:
    """Insertion of a keyboard-adjacent character."""
    out = set()
    for i in range(len(name)):
        c = name[i]
        for adj in KEYBOARD_ADJACENT.get(c, ""):
            out.add(name[:i] + adj + name[i:])
            out.add(name[:i + 1] + adj + name[i + 1:])
    return out


def _omit(name: str) -> set:
    return {name[:i] + name[i + 1:] for i in range(len(name)) if len(name) > 1}


def _repeat(name: str) -> set:
    return {name[:i] + name[i] + name[i:] for i in range(len(name))}


def _replace(name: str) -> set:
    out = set()
    for i, c in enumerate(name):
        for adj in KEYBOARD_ADJACENT.get(c, ""):
            out.add(name[:i] + adj + name[i + 1:])
    return out


def _transpose(name: str) -> set:
    out = set()
    for i in range(len(name) - 1):
        if name[i] != name[i + 1]:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    return out


def _bitsquat(name: str) -> set:
    """Flip one bit of each ASCII character (DRAM/RAM bit-flip attacks)."""
    out = set()
    masks = (1, 2, 4, 8, 16, 32, 64, 128)
    for i, c in enumerate(name):
        for mask in masks:
            flipped = chr(ord(c) ^ mask)
            if flipped.isascii() and (flipped.isalnum() or flipped == "-"):
                out.add(name[:i] + flipped + name[i + 1:])
    return out


def _homoglyph(name: str) -> set:
    out = set()
    for i, c in enumerate(name):
        for g in HOMOGLYPHS.get(c, []):
            out.add(name[:i] + g + name[i + 1:])
    return out


def _hyphenation(name: str) -> set:
    return {name[:i] + "-" + name[i:] for i in range(1, len(name))}


def _vowel_swap(name: str) -> set:
    out = set()
    for i, c in enumerate(name):
        if c in VOWELS:
            for v in VOWELS:
                if v != c:
                    out.add(name[:i] + v + name[i + 1:])
    return out


def _addition(name: str) -> set:
    """Append a single trailing character (e.g. 'paypal1')."""
    return {name + chr(c) for c in range(ord("a"), ord("z") + 1)} | \
           {name + str(d) for d in range(10)}


def generate_typosquats(domain: str, extra_tlds: Optional[List[str]] = None,
                        max_results: int = 0) -> List[dict]:
    """Generate dnstwist-style typosquat permutations of *domain*.

    Returns a list of {domain, fuzzer} dicts, deduplicated and excluding the
    original. ``extra_tlds`` adds TLD-swap variants; ``max_results`` caps the
    output (0 = unlimited).
    """
    if not domain or not isinstance(domain, str):
        return []
    if max_results < 0:
        raise ValueError(f"max_results must be >= 0, got {max_results}")
    sub, sld, tld = _split_domain(domain)
    if not sld:
        return []
    suffix = ("." + tld) if tld else ""
    prefix = (sub + ".") if sub else ""

    families = {
        "insertion": _ins(sld),
        "omission": _omit(sld),
        "repetition": _repeat(sld),
        "replacement": _replace(sld),
        "transposition": _transpose(sld),
        "bitsquatting": _bitsquat(sld),
        "homoglyph": _homoglyph(sld),
        "hyphenation": _hyphenation(sld),
        "vowel-swap": _vowel_swap(sld),
        "addition": _addition(sld),
    }

    seen = {sld}
    results: List[dict] = []
    for fuzzer, variants in families.items():
        for v in sorted(variants):
            if v and v != sld and v not in seen:
                seen.add(v)
                results.append({"domain": f"{prefix}{v}{suffix}",
                                "fuzzer": fuzzer})

    # TLD swap: keep the SLD, change the TLD.
    tld_pool = list(COMMON_TLDS)
    if extra_tlds:
        for t in extra_tlds:
            if t not in tld_pool:
                tld_pool.append(t)
    for t in tld_pool:
        if t != tld:
            results.append({"domain": f"{prefix}{sld}.{t}",
                            "fuzzer": "tld-swap"})

    # Subdomain confusion: insert a dot to make the brand look like a host.
    for i in range(1, len(sld)):
        results.append({"domain": f"{prefix}{sld[:i]}.{sld[i:]}{suffix}",
                        "fuzzer": "subdomain"})

    if max_results and len(results) > max_results:
        results = results[:max_results]
    return results
