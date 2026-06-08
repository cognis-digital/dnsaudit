"""DNSAUDIT command-line interface."""
from cognis_core import build_cli
from dnsaudit.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="DNS posture & misconfiguration scanner — SPF/DKIM/DMARC/DNSSEC/CAA",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
