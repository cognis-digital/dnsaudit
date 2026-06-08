# DNSAUDIT — DNS posture & misconfiguration scanner — SPF/DKIM/DMARC/DNSSEC/CAA

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `network`

[![PyPI](https://img.shields.io/pypi/v/cognis-dnsaudit.svg)](https://pypi.org/project/cognis-dnsaudit/)
[![CI](https://github.com/cognis-digital/dnsaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/dnsaudit/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)

DNS posture & misconfiguration scanner — SPF/DKIM/DMARC/DNSSEC/CAA.

## Install

```bash
pip install cognis-dnsaudit
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
dnsaudit --version
dnsaudit scan demos/                          # run against bundled demo
dnsaudit scan demos/ --format sarif --out r.sarif --fail-on high
dnsaudit mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-startup-default-dns/` — see [`SCENARIO.md`](demos/01-startup-default-dns/SCENARIO.md)
- `demos/02-hardened-enterprise/` — see [`SCENARIO.md`](demos/02-hardened-enterprise/SCENARIO.md)
- `demos/03-multi-domain-portfolio/` — see [`SCENARIO.md`](demos/03-multi-domain-portfolio/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md) for the collaboration-pull model.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
