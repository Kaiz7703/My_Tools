package waftest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/pkg/errors"
)

// WAFTester orchestrates WAF testing with progressive execution
type WAFTester struct {
	templateDir   string
	target        string
	batchSize     int
	stateFile     string
	csvOutput     string
	csvBypassed   string
	stateManager  *StateManager
	csvWriter     *output.CSVWriter
	detector      *WAFBypassDetector
}

// Config holds configuration for WAF testing
type Config struct {
	TemplateDir string
	BatchSize   int
	StateFile   string
	CSVOutput   string
	CSVBypassed string
	Target      string
	Verbose     bool
	Silent      bool
	ResetState  bool
	DetectionMode string // strict or header
}

// NewWAFTester creates a new WAF tester
func NewWAFTester(config *Config) (*WAFTester, error) {
	if config.TemplateDir == "" {
		return nil, errors.New("template directory is required")
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 10 // default batch size
	}
	if config.StateFile == "" {
		config.StateFile = "waf_test_state.json"
	}
	if config.CSVOutput == "" {
		config.CSVOutput = "waf_test_results.csv"
	}

	// Initialize state manager
	stateManager := NewStateManager(config.StateFile)
	if err := stateManager.LoadState(); err != nil {
		return nil, errors.Wrap(err, "failed to load state")
	}

	// Initialize CSV writer
	csvWriter, err := output.NewCSVWriter(config.CSVOutput, config.CSVBypassed)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CSV writer")
	}

	// Initialize WAF bypass detector
	detector := NewWAFBypassDetector(config.DetectionMode)

	return &WAFTester{
		templateDir:  config.TemplateDir,
		target:       config.Target,
		batchSize:    config.BatchSize,
		stateFile:    config.StateFile,
		csvOutput:    config.CSVOutput,
		csvBypassed:  config.CSVBypassed,
		stateManager: stateManager,
		csvWriter:    csvWriter,
		detector:     detector,
	}, nil
}

// LoadTemplates loads templates from the specified directory
func (wt *WAFTester) LoadTemplates() ([]string, error) {
	gologger.Info().Msgf("Loading templates from %s...", wt.templateDir)

	// Get all template files recursively
	var templatePaths []string
	err := filepath.Walk(wt.templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			templatePaths = append(templatePaths, path)
		}
		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to walk template directory")
	}

	gologger.Info().Msgf("Found %d templates", len(templatePaths))
	return templatePaths, nil
}

// ExecuteBatch executes a single batch of templates
func (wt *WAFTester) ExecuteBatch(ctx context.Context, templates []string) error {
	if len(templates) == 0 {
		gologger.Info().Msg("No templates to execute")
		return nil
	}

	gologger.Info().Msgf("Executing batch of %d templates...", len(templates))
	startTime := time.Now()

	// Create Nuclei executor (uses real Nuclei engine)
	executor, err := NewNucleiExecutor(
		wt.target,
		wt.detector,
		wt.csvWriter,
		wt.stateManager,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create Nuclei executor")
	}
	defer executor.Close()

	// Execute each template using Nuclei engine
	successCount := 0
	failCount := 0
	
	for _, tmplPath := range templates {
		select {
		case <-ctx.Done():
			gologger.Warning().Msg("Batch execution cancelled by user")
			return ctx.Err()
		default:
		}

		gologger.Debug().Msgf("Executing template: %s", filepath.Base(tmplPath))
		
		if err := executor.Execute(ctx, tmplPath); err != nil {
			gologger.Warning().Msgf("Template execution failed: %s - %v", 
				filepath.Base(tmplPath), err)
			failCount++
			continue
		}
		
		successCount++
	}

	elapsed := time.Since(startTime)
	gologger.Info().Msgf("Batch completed in %s (%d success, %d failed)", 
		elapsed, successCount, failCount)

	return nil
}

// PrintSummary prints summary statistics
func (wt *WAFTester) PrintSummary() {
	completed, total, bypassed, blocked := wt.stateManager.GetProgress()
	rate := wt.stateManager.GetBypassRate()

	gologger.Info().Msg("═══════════════════════════════════════════════════════════")
	gologger.Info().Msgf("Results: %d/%d bypassed (%.1f%%)", bypassed, bypassed+blocked, rate)
	gologger.Info().Msgf("Cumulative: %d/%d templates completed", completed, total)
	gologger.Info().Msg("═══════════════════════════════════════════════════════════")
}

// PrintFinalSummary prints the final summary report
func (wt *WAFTester) PrintFinalSummary() {
	// Request-level stats
	completed, _, bypassedReqs, blockedReqs := wt.stateManager.GetProgress()
	reqRate := wt.stateManager.GetBypassRate()
	totalReqs := bypassedReqs + blockedReqs
	
	// Template-level stats
	bypassedTmpls, blockedTmpls, _ := wt.stateManager.GetTemplateStats()
	tmplRate := wt.stateManager.GetTemplateBypassRate()
	totalTmpls := bypassedTmpls + blockedTmpls

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              WAF Testing Summary Report                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total Templates Tested:     %-33d║\n", completed)
	fmt.Println("║                                                              ║")
	fmt.Println("║ REQUEST-LEVEL STATISTICS:                                    ║")
	fmt.Printf("║   • Bypassed Requests:        %-31d║\n", bypassedReqs)
	fmt.Printf("║   • Blocked Requests:         %-31d║\n", blockedReqs)
	fmt.Printf("║   • Total Requests:           %-31d║\n", totalReqs)
	fmt.Printf("║   • Request Bypass Rate:      %-30.1f%%║\n", reqRate)
	fmt.Println("║                                                              ║")
	fmt.Println("║ TEMPLATE-LEVEL STATISTICS:                                   ║")
	fmt.Printf("║   • Bypassed Templates:       %-31d║\n", bypassedTmpls)
	fmt.Printf("║   • Blocked Templates:        %-31d║\n", blockedTmpls)
	fmt.Printf("║   • Total Templates:          %-31d║\n", totalTmpls)
	fmt.Printf("║   • Template Bypass Rate:     %-30.1f%%║\n", tmplRate)
	fmt.Println("║                                                              ║")
	
	compPath, bypassPath := wt.csvWriter.GetPaths()
	fmt.Printf("║ Comprehensive CSV:            %-31s║\n", filepath.Base(compPath))
	fmt.Printf("║ Bypassed CSV:                 %-31s║\n", filepath.Base(bypassPath))
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// Run executes the WAF testing workflow
func (wt *WAFTester) Run(ctx context.Context) error {
	// Load templates
	allTemplates, err := wt.LoadTemplates()
	if err != nil {
		return err
	}

	if len(allTemplates) == 0 {
		return errors.New("no templates found")
	}

	// Get next batch
	batch := wt.stateManager.GetNextBatch(allTemplates, wt.batchSize)
	if len(batch) == 0 {
		gologger.Info().Msg("All templates completed! No new templates to run.")
		wt.PrintFinalSummary()
		return nil
	}

	gologger.Info().Msgf("Resume Mode: Executing next %d templates (Batch Size: %d)", len(batch), wt.batchSize)

	// Execute batch
	if err := wt.ExecuteBatch(ctx, batch); err != nil {
		return errors.Wrap(err, "batch execution failed")
	}

	// Save state
	if err := wt.stateManager.SaveState(); err != nil {
		gologger.Warning().Msgf("Failed to save state: %v", err)
	}

	// Print summary
	wt.PrintSummary()
	
	// Print hint for next run
	// Logic to check remaining is implicit implies we are done with THIS batch.
	gologger.Info().Msg("Batch execution completed. Run again to process next batch.")

	// Print final summary
	wt.PrintFinalSummary()

	return nil
}

// Close closes all resources
func (wt *WAFTester) Close() error {
	var errs []error

	// Close CSV writer
	if err := wt.csvWriter.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close CSV writer"))
	}

	// Save final state
	if err := wt.stateManager.SaveState(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to save final state"))
	}

	if len(errs) > 0 {
		return errors.Errorf("errors closing WAF tester: %v", errs)
	}

	return nil
}
