# Scenario: Startup with default-only DNS — fully spoofable

Two domains. Primary has lax SPF + monitoring-only DMARC. Subdomain has nothing.

## Expected findings

- DNS-SPF-002 (lax +all)
- DNS-DMARC-002 (p=none)
- DNS-CAA-001 × 2
- DNS-SPF-001 + DNS-DMARC-001 (subdomain)

## Why this matters

Phishers actively target startups with this exact configuration. Cognis Digital's brand has been spoofed before — DNSAUDIT prevents it.
