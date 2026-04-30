package shodan

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Config struct {
	APIKey string
	Org    string
	ASN    string
	Net    string
}

type Query struct {
	ID          string
	Description string
	Raw         string
	Severity    Severity
	Rationale   string
}

func (c Config) BuildScopedQuery(raw string) string {
	var scopeParts []string
	if c.Org != "" {
		scopeParts = append(scopeParts, fmt.Sprintf(`org:"%s"`, c.Org))
	}
	if c.ASN != "" {
		scopeParts = append(scopeParts, fmt.Sprintf(`asn:%s`, c.ASN))
	}
	if c.Net != "" {
		scopeParts = append(scopeParts, fmt.Sprintf(`net:"%s"`, c.Net))
	}

	scope := strings.Join(scopeParts, " OR ")
	if scope == "" {
		return raw
	}
	return fmt.Sprintf("(%s) AND (%s)", scope, raw)
}

func AllQueries() []Query {
	return []Query{
		{
			ID:          "llm_vllm_openai_compatible",
			Severity:    SeverityCritical,
			Description: "OpenAI-compatible LLM servers (vLLM or similar) exposed directly",
			Raw:         `"OpenAI-compatible" "chat/completions" OR http.html:"vLLM"`,
			Rationale:   "Exposed LLM endpoints can be abused for free compute, prompt injection, and exfiltration of connected data.",
		},
		{
			ID:          "llm_tgi",
			Severity:    SeverityCritical,
			Description: "Text Generation Inference (TGI) servers exposed",
			Raw:         `http.title:"text-generation-inference" OR "Text Generation Inference"`,
			Rationale:   "TGI endpoints should be gated; public exposure gives arbitrary users access to your models and infra.",
		},
		{
			ID:          "llm_llama_webui",
			Severity:    SeverityHigh,
			Description: "llama.cpp / text-generation web UIs exposed",
			Raw:         `http.title:"Text Generation WebUI" OR http.html:"llama.cpp"`,
			Rationale:   "These admin/dev UIs are not meant to be internet-facing; can leak model configs and be abused.",
		},
		{
			ID:          "vectordb_qdrant",
			Severity:    SeverityCritical,
			Description: "Qdrant vector DB HTTP endpoints or consoles exposed",
			Raw:         `"Qdrant" port:6333 OR http.html:"Qdrant" "collections"`,
			Rationale:   "Public Qdrant can leak embedded documents and metadata, effectively exposing your knowledge base.",
		},
		{
			ID:          "vectordb_weaviate",
			Severity:    SeverityCritical,
			Description: "Weaviate console or API exposed",
			Raw:         `http.title:"Weaviate Console" OR http.html:"Welcome to Weaviate"`,
			Rationale:   "Weaviate consoles often allow browsing and querying of KB content; must be internal-only.",
		},
		{
			ID:          "vectordb_milvus",
			Severity:    SeverityHigh,
			Description: "Milvus console/API exposed",
			Raw:         `http.title:"Milvus Insight" OR http.html:"Milvus"`,
			Rationale:   "Milvus exposure may allow enumeration of vector collections and indirect data leakage.",
		},
		{
			ID:          "vectordb_semantic_search_custom",
			Severity:    SeverityHigh,
			Description: "Custom semantic/vector search APIs with '/v1/embeddings' or 'top_k'",
			Raw:         `http.html:"/v1/embeddings" "top_k" OR "semantic search" "top_k"`,
			Rationale:   "Custom RAG APIs may provide access to sensitive documents or embeddings if unauthenticated.",
		},
		{
			ID:          "db_postgres_public",
			Severity:    SeverityCritical,
			Description: "PostgreSQL instances exposed on the internet",
			Raw:         `product:"PostgreSQL" port:5432`,
			Rationale:   "Directly exposed Postgres is a classic high-risk misconfig; can leak data or be taken over.",
		},
		{
			ID:          "db_redis_public",
			Severity:    SeverityHigh,
			Description: "Redis instances exposed on the internet",
			Raw:         `product:"Redis" port:6379`,
			Rationale:   "Public Redis often has no auth; can be used to exfiltrate data or gain further footholds.",
		},
		{
			ID:          "db_elasticsearch_public",
			Severity:    SeverityHigh,
			Description: "Elasticsearch clusters exposed (often hold logs/KB data)",
			Raw:         `product:"Elasticsearch" OR http.title:"Kibana"`,
			Rationale:   "ES commonly stores logs, documents, and KBs; public exposure is a frequent major data leak source.",
		},
		{
			ID:          "obs_prometheus_public",
			Severity:    SeverityMedium,
			Description: "Prometheus UIs exposed (metrics, internals)",
			Raw:         `http.title:"Prometheus Time Series Collection"`,
			Rationale:   "Prometheus can leak internal topology and metrics; should be internal or behind SSO.",
		},
		{
			ID:          "obs_grafana_public",
			Severity:    SeverityMedium,
			Description: "Grafana dashboards exposed",
			Raw:         `http.title:"Grafana"`,
			Rationale:   "Open Grafana may expose dashboards with infra details, logs, or business metrics.",
		},
		{
			ID:          "obs_airflow_public",
			Severity:    SeverityHigh,
			Description: "Airflow web UIs exposed (DAGs, ingestion details)",
			Raw:         `http.title:"Airflow" OR http.html:"Apache Airflow"`,
			Rationale:   "Airflow DAGs can reveal ingestion logic, endpoints, and sometimes secrets or file paths.",
		},
		{
			ID:          "obs_jaeger_tempo_public",
			Severity:    SeverityMedium,
			Description: "Jaeger/Tempo tracing UIs exposed",
			Raw:         `http.title:"Jaeger UI" OR http.title:"Grafana Tempo"`,
			Rationale:   "Tracing UIs show internal calls, URLs, sometimes parameters — good intel for attackers.",
		},
		{
			ID:          "rag_swagger_openapi",
			Severity:    SeverityHigh,
			Description: "Swagger/OpenAPI docs for RAG/LLM endpoints exposed",
			Raw:         `http.title:"Swagger UI" "/chat" "/embeddings" OR http.html:"/rag/query" OR http.html:"/documents/upload"`,
			Rationale:   "RAG OpenAPI docs reveal internal endpoints (/documents/upload, /kb/search) that may be unauthenticated.",
		},
		{
			ID:          "dev_fastapi_swagger",
			Severity:    SeverityMedium,
			Description: "FastAPI dev servers with Swagger UI exposed",
			Raw:         `http.title:"FastAPI - Swagger UI" OR "Server: uvicorn"`,
			Rationale:   "Dev servers may bypass auth and show full internal API surface.",
		},
		{
			ID:          "dev_go_default",
			Severity:    SeverityLow,
			Description: "Go default HTTP servers exposed (often dev tools)",
			Raw:         `"Go http package" "404 page"`,
			Rationale:   "Can indicate debug/dev endpoints accidentally exposed.",
		},
	}
}
