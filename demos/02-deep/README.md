# 02-deep — full posture audit + typosquat surface

This example audits a deliberately weak domain so every check fires, then
generates the attacker's typosquat surface.

## Run

```sh
python -m dnsaudit audit --input demos/02-deep/records.json --typosquats
python -m dnsaudit audit --input demos/02-deep/records.json --format json --typosquats
python -m dnsaudit typosquat --domain acme-payments.com --tld zip --tld bank
```

## What the bundled record triggers

`records.json` describes `acme-payments.com` with intentionally poor hygiene:

| Area   | Problem in the demo record                              | Finding |
|--------|----------------------------------------------------------|---------|
| SPF    | `?all` neutral + 11 DNS lookups (over the RFC-7208 cap)  | `SPF_NEUTRAL_ALL`, `SPF_TOO_MANY_LOOKUPS` |
| DMARC  | `p=none` and `pct=50`, no `rua=`                          | `DMARC_P_NONE`, `DMARC_PCT_PARTIAL`, `DMARC_NO_RUA` |
| DKIM   | test mode `t=y` + a tiny ~512-bit key                    | `DKIM_TEST_MODE`, `DKIM_WEAK_KEY` |
| DNSSEC | signed with deprecated `RSASHA1`, no DS at parent        | `DNSSEC_NO_DS`, `DNSSEC_WEAK_ALGO` |
| CAA    | no record — any CA may issue                             | `CAA_MISSING` |

The domain is **spoofable** (no enforcing DMARC, no `-all`) and grades near the
bottom of the A–F scale. `--typosquats` enumerates insertion / omission /
homoglyph / bitsquat / tld-swap (etc.) permutations an attacker would register
to phish `acme-payments.com` customers.
