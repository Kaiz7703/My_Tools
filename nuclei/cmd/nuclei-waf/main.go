package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/waftest"
)

// WAF Testing CLI - Standalone wrapper for WAF testing functionality

func main() {
	// Initialize logger
	gologger.DefaultLogger.SetMaxLevel(gologger.Info)

	// Parse flags
	config := parseWAFFlags()
	if config == nil {
		return
	}

	// Create WAF tester
	tester, err := waftest.NewWAFTester(config)
	if err != nil {
		gologger.Fatal().Msgf("Failed to initialize WAF tester: %v", err)
	}
	defer tester.Close()

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		gologger.Info().Msg("\nCTRL+C pressed: Gracefully shutting down...")
		cancel()
	}()

	// Run WAF testing
	gologger.Info().Msg("Starting WAF testing...")
	if err := tester.Run(ctx); err != nil {
		if err == context.Canceled {
			gologger.Warning().Msg("WAF testing interrupted by user")
		} else {
			gologger.Fatal().Msgf("WAF testing failed: %v", err)
		}
	}

	gologger.Info().Msg("WAF testing completed successfully!")
}

func parseWAFFlags() *waftest.Config {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`WAF Testing Tool - Custom Nuclei modification for WAF efficacy testing

This tool tests WAF effectiveness by running Nuclei templates and checking for successful bypasses.
A bypass is detected when the response has HTTP 200 status AND X-WAF-Status: Passed header.`)

	config := &waftest.Config{}

	// Required flags
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&config.TemplateDir, "template-dir", "t", "", "path to templates directory (required)"),
		flagSet.StringVarP(&config.Target, "target", "u", "", "target URL to test (required)"),
	)

	// Output flags
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&config.CSVOutput, "csv-output", "o", "waf_test_results.csv", "comprehensive CSV output file"),
		flagSet.StringVarP(&config.CSVBypassed, "csv-bypassed", "ob", "", "bypassed-only CSV output file (auto-generated if not specified)"),
		flagSet.StringVarP(&config.StateFile, "state-file", "sf", "waf_test_state.json", "state file for progress tracking"),
	)

	// Execution flags
	flagSet.CreateGroup("execution", "Execution",
		flagSet.IntVarP(&config.BatchSize, "batch-size", "bs", 10, "number of templates to execute per batch"),
		flagSet.BoolVarP(&config.ResetState, "reset", "r", false, "reset state and start fresh (deletes state file)"),
	)

	// Debug flags
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&config.Verbose, "verbose", "v", false, "enable verbose output"),
		flagSet.BoolVarP(&config.Silent, "silent", "s", false, "silent mode (only show summary)"),
	)

	flagSet.SetCustomHelpText(`EXAMPLES:
Basic WAF test:
  $ nuclei-waf -t C:\Payloads\CVE -u https://example.com

Custom batch size:
  $ nuclei-waf -t C:\Payloads -u https://example.com -bs 20

Custom output files:
  $ nuclei-waf -t C:\Payloads -u https://example.com -o results.csv -ob bypassed.csv

Reset and start fresh:
  $ nuclei-waf -t C:\Payloads -u https://example.com --reset

For more information, see: user_guide.md
`)

	if err := flagSet.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		return nil
	}

	// Validate required flags
	if config.TemplateDir == "" {
		gologger.Fatal().Msg("Template directory is required (-t/--template-dir)")
	}

	if config.Target == "" {
		gologger.Fatal().Msg("Target URL is required (-u/--target)")
	}

	// Set log level
	if config.Verbose {
		gologger.DefaultLogger.SetMaxLevel(gologger.Debug)
	} else if config.Silent {
		gologger.DefaultLogger.SetMaxLevel(gologger.Silent)
	}

	// Handle reset flag
	if config.ResetState {
		if _, err := os.Stat(config.StateFile); err == nil {
			gologger.Info().Msgf("Deleting state file: %s", config.StateFile)
			if err := os.Remove(config.StateFile); err != nil {
				gologger.Warning().Msgf("Failed to delete state file: %v", err)
			}
		}
	}

	return config
}
