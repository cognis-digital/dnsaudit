# Scenario: Multi-domain portfolio with inconsistent hardening

Three domains. Corp tight; marketing lax; old-brand abandoned.

## Expected findings

- DNS-SPF-002, DNS-DMARC-002, DNS-CAA-001 (marketing)
- DNS-SPF-001, DNS-DMARC-001, DNS-CAA-001 (old-brand)

## Why this matters

Every retired brand domain is a phishing-ready spoofable asset. Audit quarterly.
