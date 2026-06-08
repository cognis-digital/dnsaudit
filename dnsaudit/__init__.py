"""DNSAUDIT — DNS posture & misconfiguration scanner.

Standard-library-only tool that audits a domain's email-authentication and
DNS-security posture by inspecting SPF, DKIM, DMARC, DNSSEC and CAA records.

The engine is transport-agnostic: it resolves records through a pluggable
resolver. The default resolver uses the standard library only. For testing and
offline use, a dict-backed resolver can be supplied so no network is required.
"""

from .core import (
    Finding,
    AuditReport,
    Resolver,
    DictResolver,
    StdlibResolver,
    audit_domain,
    parse_spf,
    parse_dmarc,
    grade,
)

TOOL_NAME = "dnsaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "AuditReport",
    "Resolver",
    "DictResolver",
    "StdlibResolver",
    "audit_domain",
    "parse_spf",
    "parse_dmarc",
    "grade",
]
