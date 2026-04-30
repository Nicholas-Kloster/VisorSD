package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"shodan-audit/internal/shodan"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	green  = "\033[32m"
	orange = "\033[38;5;208m"
)

type ResultRecord struct {
	QueryID     string `json:"query_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Hits        int    `json:"hits"`
	Query       string `json:"query"`
	Rationale   string `json:"rationale"`
}

func severityRank(s shodan.Severity) int {
	switch s {
	case shodan.SeverityCritical:
		return 4
	case shodan.SeverityHigh:
		return 3
	case shodan.SeverityMedium:
		return 2
	case shodan.SeverityLow:
		return 1
	}
	return 0
}

func badge(s shodan.Severity) string {
	switch s {
	case shodan.SeverityCritical:
		return red + bold + "[CRITICAL]" + reset
	case shodan.SeverityHigh:
		return orange + bold + "[HIGH]" + reset
	case shodan.SeverityMedium:
		return yellow + "[MEDIUM]" + reset
	case shodan.SeverityLow:
		return cyan + "[LOW]" + reset
	}
	return ""
}

func main() {
	key := flag.String("key", os.Getenv("SHODAN_API_KEY"), "Shodan API key (or set SHODAN_API_KEY)")
	org := flag.String("org", "", "Scope: org name (e.g. \"Acme Corp\")")
	asn := flag.String("asn", "", "Scope: ASN (e.g. AS12345)")
	net := flag.String("net", "", "Scope: CIDR (e.g. 203.0.113.0/24)")
	limit := flag.Int("limit", 10, "Max matches to fetch per query")
	format := flag.String("format", "text", "Output format: text|json|csv")
	out := flag.String("out", "", "Write results to file (default stdout)")
	failOn := flag.String("fail-on", "", "Exit non-zero if any hit at or above severity: CRITICAL|HIGH|MEDIUM|LOW")
	dryRun := flag.Bool("dry-run", false, "Print scoped queries without calling Shodan")
	flag.Parse()

	if *key == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "error: -key or SHODAN_API_KEY required")
		os.Exit(1)
	}

	cfg := shodan.Config{
		APIKey: *key,
		Org:    *org,
		ASN:    *asn,
		Net:    *net,
	}

	queries := shodan.AllQueries()
	client := shodan.NewClient(*key)

	var failRank int
	if *failOn != "" {
		failRank = severityRank(shodan.Severity(strings.ToUpper(*failOn)))
		if failRank == 0 {
			fmt.Fprintf(os.Stderr, "error: invalid -fail-on value %q\n", *failOn)
			os.Exit(1)
		}
	}

	var records []ResultRecord
	maxHitRank := 0

	for _, q := range queries {
		scoped := cfg.BuildScopedQuery(q.Raw)

		if *dryRun {
			fmt.Printf("%s  %s\n  %s%s%s\n\n", badge(q.Severity), q.Description, gray, scoped, reset)
			continue
		}

		resp, err := client.Search(context.Background(), scoped, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s: %v\n", q.ID, err)
			continue
		}

		hits := resp.Total
		rec := ResultRecord{
			QueryID:     q.ID,
			Severity:    string(q.Severity),
			Description: q.Description,
			Hits:        hits,
			Query:       scoped,
			Rationale:   q.Rationale,
		}
		records = append(records, rec)

		if hits > 0 && severityRank(q.Severity) > maxHitRank {
			maxHitRank = severityRank(q.Severity)
		}
	}

	if *dryRun {
		return
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(records)

	case "csv":
		cw := csv.NewWriter(w)
		cw.Write([]string{"query_id", "severity", "hits", "description", "query", "rationale"})
		for _, r := range records {
			cw.Write([]string{r.QueryID, r.Severity, fmt.Sprint(r.Hits), r.Description, r.Query, r.Rationale})
		}
		cw.Flush()

	default:
		printText(w, records)
	}

	if *failOn != "" && maxHitRank >= failRank {
		os.Exit(2)
	}
}

func printText(w *os.File, records []ResultRecord) {
	fmt.Fprintf(w, "\n%s%s SHODAN AUDIT%s\n", bold, cyan, reset)
	fmt.Fprintf(w, "%s%s%s\n\n", gray, strings.Repeat("─", 60), reset)

	var hits, clean int
	for _, r := range records {
		sev := shodan.Severity(r.Severity)
		b := badge(sev)

		if r.Hits > 0 {
			hits++
			fmt.Fprintf(w, "%s  %s  %s%d hit(s)%s\n", b, r.Description, bold, r.Hits, reset)
			fmt.Fprintf(w, "   %s%s%s\n", gray, r.Query, reset)
			fmt.Fprintf(w, "   %s%s%s\n\n", yellow, r.Rationale, reset)
		} else {
			clean++
			fmt.Fprintf(w, "  %s[CLEAN]%s  %s\n", green, reset, r.Description)
		}
	}

	fmt.Fprintf(w, "\n%s%s%s\n", gray, strings.Repeat("─", 60), reset)
	fmt.Fprintf(w, "%sSummary:%s %d/%d queries returned hits\n\n",
		bold, reset, hits, len(records))
}
