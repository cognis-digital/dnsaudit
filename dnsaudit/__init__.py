"""DNSAUDIT — best-in-class email/DNS posture grading + typosquat generation.

Folds in a real internet.nl-style posture audit (SPF / DKIM / DMARC / DNSSEC /
CAA) graded A–F, plus a dnstwist-style typosquat permutation engine that
generates the domains an attacker would register to phish your users.

Standard library only, zero install, fully offline. Feed it a DNS dump you
already captured (JSON) or individual records via flags — no network is used.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    AuditResult,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    audit_domain,
    parse_spf,
    parse_dmarc,
    parse_dkim,
    parse_caa,
    parse_dnssec,
    grade_score,
    generate_typosquats,
    KEYBOARD_ADJACENT,
    HOMOGLYPHS,
    COMMON_TLDS,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "AuditResult",
    "SEVERITY_ORDER",
    "SEVERITY_WEIGHT",
    "audit_domain",
    "parse_spf",
    "parse_dmarc",
    "parse_dkim",
    "parse_caa",
    "parse_dnssec",
    "grade_score",
    "generate_typosquats",
    "KEYBOARD_ADJACENT",
    "HOMOGLYPHS",
    "COMMON_TLDS",
]
