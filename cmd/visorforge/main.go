package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"shodan-audit/internal/security"
)

func main() {
	profileStr := flag.String("profile", "standard", "Base profile: standard|strict|lenient")
	useTemplates := flag.Bool("templates", true, "Include template-generated cases")
	maxBase := flag.Int("max-base", 100, "Max seed cases to mutate (0=all)")
	out := flag.String("out", "", "Output JSON file (default stdout)")
	statsOnly := flag.Bool("stats", false, "Print stats instead of dumping JSON")
	flag.Parse()

	var p security.Profile
	switch *profileStr {
	case "strict":
		p = security.ProfileStrict
	case "lenient":
		p = security.ProfileLenient
	default:
		p = security.ProfileStandard
	}

	seeds := security.CorpusForProfile(p)

	cfg := security.ForgeConfig{
		Profile:      p,
		BaseCorpus:   seeds,
		UseTemplates: *useTemplates,
		Mutators: []security.Mutator{
			security.MutatorAddPoliteness(),
			security.MutatorRemovePoliteness(),
			security.MutatorAddAuthority(),
			security.MutatorSynonymParaphrase(),
			security.MutatorLengthen(),
			security.MutatorShortenHard(180),
			security.MutatorKeepFirstSentence(),
			security.MutatorAddUrgency(),
			security.MutatorSandwichInjection(),
			security.MutatorReorderClauses(),
		},
		MaxBase: *maxBase,
	}

	corpus := security.ForgeCorpus(cfg)

	if *statsOnly {
		catCounts := map[security.Category]int{}
		for _, c := range corpus {
			catCounts[c.Category]++
		}
		fmt.Printf("Profile: %s   Total: %d\n\n", *profileStr, len(corpus))
		fmt.Printf("%-30s %s\n", "CATEGORY", "COUNT")
		fmt.Printf("%s\n", "─────────────────────────────────────")
		for cat, n := range catCounts {
			fmt.Printf("%-30s %d\n", cat, n)
		}
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(corpus); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
