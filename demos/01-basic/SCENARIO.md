# Demo 01 — Basic offline DNS posture scan

This demo audits a deliberately misconfigured domain using an **offline**
resolver fixture, so it runs with zero network access.

The fixture (`weakcorp.example.json`) models a real-world weak posture:

- **SPF** present but terminates with `~all` (softfail) and uses the deprecated
  `ptr` mechanism.
- **DMARC** present but set to `p=none` (monitor only) with no `rua` address.
- **DKIM** key found under the `default` selector.
- **CAA** absent — any certificate authority may issue.
- **DNSSEC** not enabled.

## Run it

```bash
# Human-readable table
python -m dnsaudit scan weakcorp.example --fixture demos/01-basic/weakcorp.example.json

# Machine-readable JSON, fail the build if score < 70
python -m dnsaudit scan weakcorp.example \
    --fixture demos/01-basic/weakcorp.example.json \
    --format json --fail-under 70
```

## Expected

The scan reports several low/medium findings, computes a posture score and
letter grade, and exits non-zero because findings exist (and the score is
below the `--fail-under` threshold). Swap in a hardened fixture (SPF `-all`,
DMARC `p=reject`, CAA present, DNSSEC enabled) to watch the grade climb to A.
