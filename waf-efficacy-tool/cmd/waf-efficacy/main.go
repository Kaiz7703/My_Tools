package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"waf-efficacy-tool/pkg/efficacy"

	"github.com/schollz/progressbar/v3"
)

func main() {
	// Parse config
	cfg, err := efficacy.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("WAF Efficacy Testing Tool\n")
	fmt.Printf("Target: %s\n", cfg.WAFURL)
	fmt.Printf("Mode: %s\n\n", cfg.Mode)

	// Initialize components
	client := efficacy.NewHTTPClient(cfg.WAFURL, cfg.Timeout, cfg.Verbose, cfg.Debug)
	analyzer := efficacy.NewResultAnalyzer()
	writer := efficacy.NewCSVWriter(cfg.OutputDir)

	// Run tests based on mode
	switch cfg.Mode {
	case efficacy.ModeTruePositive:
		runTPTest(cfg, client, analyzer)
	case efficacy.ModeFalsePositive:
		runFPTest(cfg, client, analyzer)
	case efficacy.ModeMixed:
		runTPTest(cfg, client, analyzer)
		runFPTest(cfg, client, analyzer)
	}

	// Generate summary and save results
	summary := analyzer.GetSummary(cfg.Mode)
	analyzer.PrintSummary(summary)

	if err := writer.WriteResults(analyzer.GetResults(), cfg.Mode); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}
}

func runTPTest(cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer) {
	fmt.Println("Running True Positive tests...")

	loader := efficacy.NewPayloadLoader(cfg.MaliciousPath)
	datasets, err := loader.LoadAll()
	if err != nil {
		log.Fatalf("Failed to load malicious datasets: %v", err)
	}

	runTests(datasets, "Malicious", cfg, client, analyzer)
}

func runFPTest(cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer) {
	fmt.Println("Running False Positive tests...")

	loader := efficacy.NewPayloadLoader(cfg.LegitimPath)
	datasets, err := loader.LoadAll()
	if err != nil {
		log.Fatalf("Failed to load legitimate datasets: %v", err)
	}

	runTests(datasets, "Legitimate", cfg, client, analyzer)
}

func runTests(datasets map[string][]efficacy.Payload, datasetType string, cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer) {
	// Count total payloads
	total := 0
	for _, payloads := range datasets {
		total += len(payloads)
	}

	bar := progressbar.Default(int64(total))

	// Process with workers
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.Workers)
	resultsChan := make(chan efficacy.TestResult, total)

	for testName, payloads := range datasets {
		for _, payload := range payloads {
			wg.Add(1)

			go func(tn string, p efficacy.Payload) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
				defer cancel()

				statusCode, isBlocked, err := client.SendRequest(ctx, p)
				if err != nil {
					statusCode = 0
					isBlocked = false
				}

				result := efficacy.TestResult{
					TestName:    tn,
					URL:         p.URL,
					Method:      p.Method,
					StatusCode:  statusCode,
					IsBlocked:   isBlocked,
					DatasetType: datasetType,
					Timestamp:   time.Now(),
				}

				if datasetType == "Malicious" {
					result.Bypassed = !isBlocked
				} else {
					result.FalsePositive = isBlocked
				}

				resultsChan <- result
				bar.Add(1)
			}(testName, payload)
		}
	}

	// Wait and collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		analyzer.AddResult(result)
	}

	bar.Finish()
}
