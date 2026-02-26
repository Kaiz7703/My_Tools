package efficacy

import (
	"flag"
	"fmt"
)

func ParseFlags() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.WAFURL, "u", "", "WAF URL to test (required)")
	flag.StringVar(&cfg.MaliciousPath, "malicious", "Data/Malicious", "Path to malicious dataset")
	flag.StringVar(&cfg.LegitimPath, "legitimate", "Data/Legitimate", "Path to legitimate dataset")
	flag.StringVar(&cfg.OutputDir, "o", ".", "Output directory for results")
	flag.IntVar(&cfg.Timeout, "timeout", 5, "Request timeout in seconds")
	flag.IntVar(&cfg.Workers, "workers", 10, "Number of concurrent workers")

	// Mode flags
	tpOnly := flag.Bool("tp-only", false, "Test True Positive only")
	fpOnly := flag.Bool("fp-only", false, "Test False Positive only")
	verbose := flag.Bool("v", false, "Verbose output (show each request)")
	debug := flag.Bool("debug", false, "Debug mode (show full request/response details)")

	flag.Parse()

	if cfg.WAFURL == "" {
		return nil, fmt.Errorf("WAF URL is required (-u)")
	}

	cfg.Verbose = *verbose
	cfg.Debug = *debug

	// Determine mode (default to mixed)
	if *tpOnly {
		cfg.Mode = ModeTruePositive
	} else if *fpOnly {
		cfg.Mode = ModeFalsePositive
	} else {
		cfg.Mode = ModeMixed
	}

	return cfg, nil
}
