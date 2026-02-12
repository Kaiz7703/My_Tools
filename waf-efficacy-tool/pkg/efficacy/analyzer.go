package efficacy

import (
	"fmt"
	"strings"
)

type ResultAnalyzer struct {
	results []TestResult
}

func NewResultAnalyzer() *ResultAnalyzer {
	return &ResultAnalyzer{
		results: make([]TestResult, 0),
	}
}

func (ra *ResultAnalyzer) AddResult(result TestResult) {
	ra.results = append(ra.results, result)
}

func (ra *ResultAnalyzer) GetResults() []TestResult {
	return ra.results
}

func (ra *ResultAnalyzer) GetSummary(mode TestMode) TestSummary {
	summary := TestSummary{Mode: mode}

	// Filter out errors (status code 0)
	validResults := make([]TestResult, 0)
	for _, r := range ra.results {
		if r.StatusCode != 0 {
			validResults = append(validResults, r)
		}
	}

	summary.TotalRequests = len(validResults)

	switch mode {
	case ModeTruePositive:
		for _, r := range validResults {
			if r.Bypassed {
				summary.BypassedCount++
			} else {
				summary.BlockedCount++
			}
		}
		if summary.TotalRequests > 0 {
			summary.BypassRate = float64(summary.BypassedCount) / float64(summary.TotalRequests) * 100
		}

	case ModeFalsePositive:
		for _, r := range validResults {
			if r.FalsePositive {
				summary.FalsePositiveCount++
			} else {
				summary.AllowedCount++
			}
		}
		if summary.TotalRequests > 0 {
			summary.FPRate = float64(summary.FalsePositiveCount) / float64(summary.TotalRequests) * 100
		}

	case ModeMixed:
		// Calculate both metrics
		tpResults := make([]TestResult, 0)
		fpResults := make([]TestResult, 0)

		for _, r := range validResults {
			if r.DatasetType == "Malicious" {
				tpResults = append(tpResults, r)
			} else {
				fpResults = append(fpResults, r)
			}
		}

		// TP metrics
		for _, r := range tpResults {
			if r.Bypassed {
				summary.BypassedCount++
			} else {
				summary.BlockedCount++
			}
		}

		// FP metrics
		for _, r := range fpResults {
			if r.FalsePositive {
				summary.FalsePositiveCount++
			} else {
				summary.AllowedCount++
			}
		}

		tpTotal := len(tpResults)
		fpTotal := len(fpResults)

		if tpTotal > 0 {
			summary.BypassRate = float64(summary.BypassedCount) / float64(tpTotal) * 100
		}
		if fpTotal > 0 {
			summary.FPRate = float64(summary.FalsePositiveCount) / float64(fpTotal) * 100
		}
	}

	return summary
}

func (ra *ResultAnalyzer) PrintSummary(summary TestSummary) {
	fmt.Println("\n" + strings.Repeat("=", 60))

	switch summary.Mode {
	case ModeTruePositive:
		fmt.Println("TRUE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Malicious Requests: %d\n", summary.TotalRequests)
		fmt.Printf("Bypassed (200):           %d\n", summary.BypassedCount)
		fmt.Printf("Blocked (400/403):        %d\n", summary.BlockedCount)
		fmt.Printf("Bypass Rate:              %.2f%%\n", summary.BypassRate)

	case ModeFalsePositive:
		fmt.Println("FALSE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Legitimate Requests: %d\n", summary.TotalRequests)
		fmt.Printf("Allowed (200):             %d\n", summary.AllowedCount)
		fmt.Printf("False Positives (400/403): %d\n", summary.FalsePositiveCount)
		fmt.Printf("False Positive Rate:       %.2f%%\n", summary.FPRate)

	case ModeMixed:
		fmt.Println("MIXED TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("True Positive Metrics:")
		fmt.Printf("  Bypassed:     %d\n", summary.BypassedCount)
		fmt.Printf("  Blocked:      %d\n", summary.BlockedCount)
		fmt.Printf("  Bypass Rate:  %.2f%%\n", summary.BypassRate)
		fmt.Println("\nFalse Positive Metrics:")
		fmt.Printf("  Allowed:      %d\n", summary.AllowedCount)
		fmt.Printf("  FP Count:     %d\n", summary.FalsePositiveCount)
		fmt.Printf("  FP Rate:      %.2f%%\n", summary.FPRate)
	}

	fmt.Println(strings.Repeat("=", 60))
}
