[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![Go Report Card](https://goreportcard.com/badge/github.com/Nicholas-Kloster/VisorSD)](https://goreportcard.com/report/github.com/Nicholas-Kloster/VisorSD)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# VisorSD

Shodan exposure scanner + adversarial RAG security testing toolkit.

VisorSD ships with ~20 hardcoded AI/LLM infra exposure queries organized by severity. Point it at a Shodan API key and it maps the AI attack surface of any org, ASN, or netblock — ranked CRITICAL to LOW, no manual dork-writing required.

---

## Installation

```bash
git clone https://github.com/Nicholas-Kloster/VisorSD.git
cd VisorSD
go build -o visorsd ./cmd/shodan-audit
```

**Requires:** Go 1.21+, Shodan API key

---

## Quick Start

```bash
export SHODAN_API_KEY="your_key_here"

# See all built-in queries — zero credits spent
./visorsd -dry-run

# Run full scan (global, all categories)
./visorsd

# Scope to a specific target
./visorsd -org "Acme Corp"
./visorsd -asn AS48090
./visorsd -net 93.123.0.0/16
```

---

## The Beginner AI/LLM Stack

VisorSD's built-in query catalog covers what a first-time AI developer typically exposes. This is the **beginner stack** — five components commonly deployed together with default (no-auth) configs:

| # | Component | Default Port | Risk |
|---|-----------|-------------|------|
| 1 | **Ollama** — LLM runtime | 11434 | Unauthenticated model API, compute drain |
| 2 | **Open WebUI** — chat frontend | 3000 / 8080 | First-user-becomes-admin signup |
| 3 | **ChromaDB** — vector store | 8000 | No auth by default, full data read |
| 4 | **n8n** — workflow/agent builder | 5678 | Credential exposure in workflows |
| 5 | **Cloudflared / ngrok** — tunnel | varies | Exposes all of the above to the internet |

Run `./visorsd -dry-run` to see the exact Shodan queries VisorSD uses to find each component.

---

## Hunting the Beginner Stack — Step by Step

**Step 1 — Preview queries (free, no credits)**
```bash
./visorsd -dry-run
```

**Step 2 — Run full scan**
```bash
SHODAN_API_KEY=$(cat ~/.config/nuclide/shodan.key) ./visorsd
```

Results are severity-ranked:
- `CRITICAL` — unauthenticated admin panels, open model APIs, exposed secrets
- `HIGH` — auth required but commonly misconfigured
- `MEDIUM` — version disclosure, shadow-IT indicators
- `LOW` — fingerprint only

**Step 3 — Scope to a target**
```bash
# By organization name
./visorsd -org "Target Org Name"

# By ASN
./visorsd -asn AS12345

# By IP range
./visorsd -net 192.168.1.0/24
```

**Step 4 — Export results**
```bash
./visorsd -format json -out results.json   # machine-readable
./visorsd -format csv  -out results.csv    # spreadsheet-friendly
./visorsd -fail-on critical                # exit non-zero on CRITICAL (CI/CD)
```

**Step 5 — Feed into JAXEN for deep enrichment**

VisorSD finds and scores. [JAXEN](https://github.com/Nicholas-Kloster/JAXEN) persists and deepens — import VisorSD results for full Shodan enrichment, empire.db tracking, and pivot analysis:

```bash
cd ~/Tools/JAXEN
SHODAN_API_KEY=$(cat ~/.config/nuclide/shodan.key) ./jaxen import results.csv
```

---

## Full Flag Reference

| Flag | Description | Example |
|------|-------------|---------|
| `-key` | Shodan API key (or use `SHODAN_API_KEY` env) | `-key abc123` |
| `-org` | Filter by organization name | `-org "Cloudflare"` |
| `-asn` | Filter by ASN | `-asn AS13335` |
| `-net` | Filter by CIDR | `-net 1.1.1.0/24` |
| `-limit` | Max results per query (default 10) | `-limit 50` |
| `-dry-run` | Print scoped queries, no API calls | `-dry-run` |
| `-fail-on` | Exit non-zero if severity ≥ threshold | `-fail-on high` |
| `-format` | Output format: `text`, `json`, `csv` | `-format json` |
| `-out` | Write to file (default stdout) | `-out results.json` |

---

## Use with Claude Code

Claude Code can run VisorSD scans, parse the severity-ranked JSON output, and chain results into VisorAgent or aimap workflows for deeper validation.

```
Run `./visorsd -org "Target Org" -format json -out visorsd.json` with SHODAN_API_KEY set, then analyze visorsd.json: list every CRITICAL and HIGH finding with IP, port, service, and a one-line description of the exposure. Flag any that are direct inputs for VisorAgent (exposed Ollama or Open WebUI endpoints).
```

```
I have visorsd.json from a scan. Extract all CRITICAL findings, format them as a findings table (IP | Port | Service | Severity | Evidence), and suggest which three findings to validate first with aimap active probes and why.
```

---

## Related Tools

VisorSD is part of the Nuclide recon ecosystem:

- **[JAXEN](https://github.com/Nicholas-Kloster/JAXEN)** — stateful Shodan recon engine with empire.db persistence
- **[aimap](https://github.com/Nicholas-Kloster/aimap)** — active AI/ML service enumerator (36 service types, 26 deep probes)
- **[BARE](https://github.com/Nicholas-Kloster/BARE)** — semantic exploit matching against Metasploit corpus
- **[VisorCorpus](https://github.com/Nicholas-Kloster/VisorCorpus)** — adversarial LLM prompt corpus generator
- **[AI-LLM-Infrastructure-OSINT](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT)** — verified Shodan dork catalogue with 15 categories

---

## License

MIT — see [LICENSE](LICENSE)
