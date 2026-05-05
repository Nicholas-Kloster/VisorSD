# VisorSD

Shodan exposure scanner + adversarial RAG security testing toolkit. Ships ~20 hardcoded AI/LLM-infra exposure queries severity-ranked CRITICAL → LOW. Point it at a Shodan API key and it maps the AI attack surface of any org / ASN / netblock without manual dork-writing.

The discovery / pre-flight stage of the NuClide chain. Output feeds JAXEN harvest, aimap fingerprinting, and VisorAgent target lists.

## Language
Go 1.21+ (single static binary)

## Build & Run
```
go build -o visorsd ./cmd/shodan-audit

export SHODAN_API_KEY="..."

./visorsd -dry-run                                # preview the ~20 queries, no credits spent
./visorsd                                         # global scan, all severities
./visorsd -org "Acme Corp"                        # scope to org
./visorsd -asn AS48090                            # scope to ASN
./visorsd -net 93.123.0.0/16                      # scope to netblock
./visorsd -format json -out results.json          # JSON report
./visorsd -severity critical                      # filter to CRITICAL only

# tests (when added — currently 0)
go test ./...
```

## The Beginner AI/LLM Stack

The query catalog targets the five components a first-time AI developer typically exposes:

| Component | Default Port | Risk |
|---|---|---|
| Ollama (LLM runtime) | 11434 | Unauth model API, compute drain |
| Open WebUI (chat frontend) | 3000 / 8080 | First-user-becomes-admin signup |
| ChromaDB (vector store) | 8000 | No auth by default, full data read |
| n8n (workflow / agent builder) | 5678 | Credential exposure in workflows |
| Cloudflared / ngrok (tunnel) | varies | Exposes the rest of the stack |

## Layout
```
cmd/shodan-audit/main.go    # CLI entry (binary name: visorsd)
internal/                   # query catalog + Shodan API client + severity ranker
go.mod
```

## Claude Code Notes
- Read README for the step-by-step Beginner Stack hunt guide and the full flag reference
- Output is severity-ranked Shodan results; pipe into JAXEN for harvesting or aimap for active fingerprinting
- The query catalog is the load-bearing artifact — extending it means adding new queries to the catalog code in `internal/`
- `-dry-run` is the preview path; never spend credits while iterating on a query change
- Built with [Claude Code](https://claude.ai/code)
