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

	if err := analyzer.InitWriter(cfg.OutputDir, cfg.Mode); err != nil {
		log.Fatalf("Failed to initialize CSV writer: %v", err)
	}
	defer analyzer.CloseWriter()

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
	_ = analyzer.GetSummary()
	analyzer.PrintSummary()
}

func runTPTest(cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer) {
	fmt.Println("Running True Positive tests...")

	loader := efficacy.NewPayloadLoader(cfg.MaliciousPath)
	files, err := loader.GetFiles()
	if err != nil {
		log.Fatalf("Failed to locate malicious datasets: %v", err)
	}

	runTests(files, "Malicious", cfg, client, analyzer, loader)
}

func runFPTest(cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer) {
	fmt.Println("Running False Positive tests...")

	loader := efficacy.NewPayloadLoader(cfg.LegitimPath)
	files, err := loader.GetFiles()
	if err != nil {
		log.Fatalf("Failed to locate legitimate datasets: %v", err)
	}

	runTests(files, "Legitimate", cfg, client, analyzer, loader)
}

func runTests(files map[string]string, datasetType string, cfg *efficacy.Config, client *efficacy.HTTPClient, analyzer *efficacy.ResultAnalyzer, loader *efficacy.PayloadLoader) {
	// Initialize progress bar without a known total at first
	bar := progressbar.Default(-1, "Processing Payloads")

	resultsChan := make(chan efficacy.TestResult, cfg.Workers*2)

	// Create a channel for workers to consume payloads
	type job struct {
		testName string
		payload  efficacy.Payload
	}
	jobsChan := make(chan job, cfg.Workers*2)

	// Start workers
	var wgWorkers sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			for j := range jobsChan {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)

				statusCode, isBlocked, err := client.SendRequest(ctx, j.payload)
				cancel()

				if err != nil {
					statusCode = 0
					isBlocked = false
				}

				result := efficacy.TestResult{
					TestName:    j.testName,
					URL:         j.payload.URL,
					Method:      j.payload.Method,
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
			}
		}()
	}

	// Result collector
	var wgCollector sync.WaitGroup
	wgCollector.Add(1)
	go func() {
		defer wgCollector.Done()
		for result := range resultsChan {
			analyzer.AddResult(result)
		}
	}()

	// Read files and stream payloads
	for testName, path := range files {
		payloadsChan := make(chan efficacy.Payload, 100)

		var fileWg sync.WaitGroup
		fileWg.Add(1)
		go func(tn string) {
			defer fileWg.Done()
			for p := range payloadsChan {
				jobsChan <- job{testName: tn, payload: p}
			}
		}(testName)

		_, err := loader.StreamFile(path, payloadsChan)
		if err != nil {
			log.Printf("Warning: failed to fully read %s: %v", path, err)
		}
		close(payloadsChan)
		fileWg.Wait() // wait for current file to finish sending to jobs
	}

	// Signal workers no more jobs
	close(jobsChan)
	// Wait for workers to finish
	wgWorkers.Wait()
	// Signal collector no more results
	close(resultsChan)
	// Wait for collector to finish
	wgCollector.Wait()

	bar.Finish()
	fmt.Println()
}
