package efficacy

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ResultAnalyzer struct {
	summary    TestSummary
	writer     *csv.Writer
	file       *os.File
	isWriting  bool
	hasHeaders bool
	mode       TestMode
}

func NewResultAnalyzer() *ResultAnalyzer {
	return &ResultAnalyzer{}
}

func (ra *ResultAnalyzer) InitWriter(outputDir string, mode TestMode) error {
	var filename string
	ra.mode = mode
	ra.summary = TestSummary{Mode: mode}

	switch mode {
	case ModeTruePositive:
		filename = "tp_results.csv"
	case ModeFalsePositive:
		filename = "fp_results.csv"
	case ModeMixed:
		filename = "mixed_results.csv"
	}

	path := filepath.Join(outputDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	ra.file = file
	ra.writer = csv.NewWriter(file)
	ra.isWriting = true

	// Write header
	header := []string{"test_name", "index", "url", "method", "status_code", "is_blocked"}

	if mode == ModeTruePositive || mode == ModeMixed {
		header = append(header, "bypassed")
	}
	if mode == ModeFalsePositive || mode == ModeMixed {
		header = append(header, "false_positive")
	}
	if mode == ModeMixed {
		header = append(header, "dataset_type")
	}

	if err := ra.writer.Write(header); err != nil {
		return err
	}

	return nil
}

func (ra *ResultAnalyzer) CloseWriter() {
	if ra.isWriting && ra.writer != nil {
		ra.writer.Flush()
		if ra.file != nil {
			ra.file.Close()
		}
		ra.isWriting = false
	}
}

func (ra *ResultAnalyzer) AddResult(r TestResult) {
	if r.StatusCode == 0 {
		return // Skip errors
	}

	// Update Metrics
	ra.summary.TotalRequests++

	if ra.mode == ModeTruePositive || (ra.mode == ModeMixed && r.DatasetType == "Malicious") {
		if r.Bypassed {
			ra.summary.BypassedCount++
		} else {
			ra.summary.BlockedCount++
		}
	} else if ra.mode == ModeFalsePositive || (ra.mode == ModeMixed && r.DatasetType == "Legitimate") {
		if r.FalsePositive {
			ra.summary.FalsePositiveCount++
		} else {
			ra.summary.AllowedCount++
		}
	}

	// Write to CSV directly if we only want TP bypassed or FP blocked
	if ra.isWriting {
		var shouldWrite bool
		if ra.mode == ModeTruePositive && r.Bypassed {
			shouldWrite = true
		} else if ra.mode == ModeFalsePositive && r.FalsePositive {
			shouldWrite = true
		} else if ra.mode == ModeMixed {
			shouldWrite = true
		}

		if shouldWrite {
			row := []string{
				r.TestName,
				fmt.Sprintf("%d", r.Index),
				r.URL,
				r.Method,
				fmt.Sprintf("%d", r.StatusCode),
				fmt.Sprintf("%t", r.IsBlocked),
			}

			if ra.mode == ModeTruePositive || ra.mode == ModeMixed {
				row = append(row, fmt.Sprintf("%t", r.Bypassed))
			}
			if ra.mode == ModeFalsePositive || ra.mode == ModeMixed {
				row = append(row, fmt.Sprintf("%t", r.FalsePositive))
			}
			if ra.mode == ModeMixed {
				row = append(row, r.DatasetType)
			}

			_ = ra.writer.Write(row)
		}
	}
}

func (ra *ResultAnalyzer) GetSummary() TestSummary {
	switch ra.mode {
	case ModeTruePositive:
		if ra.summary.TotalRequests > 0 {
			ra.summary.BypassRate = float64(ra.summary.BypassedCount) / float64(ra.summary.TotalRequests) * 100
		}
	case ModeFalsePositive:
		if ra.summary.TotalRequests > 0 {
			ra.summary.FPRate = float64(ra.summary.FalsePositiveCount) / float64(ra.summary.TotalRequests) * 100
		}
	case ModeMixed:
		tpTotal := ra.summary.BypassedCount + ra.summary.BlockedCount
		fpTotal := ra.summary.FalsePositiveCount + ra.summary.AllowedCount

		if tpTotal > 0 {
			ra.summary.BypassRate = float64(ra.summary.BypassedCount) / float64(tpTotal) * 100
		}
		if fpTotal > 0 {
			ra.summary.FPRate = float64(ra.summary.FalsePositiveCount) / float64(fpTotal) * 100
		}
	}

	return ra.summary
}

func (ra *ResultAnalyzer) PrintSummary() {
	fmt.Println("\n" + strings.Repeat("=", 60))

	switch ra.mode {
	case ModeTruePositive:
		fmt.Println("TRUE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Malicious Requests: %d\n", ra.summary.TotalRequests)
		fmt.Printf("Bypassed (200):           %d\n", ra.summary.BypassedCount)
		fmt.Printf("Blocked (400/403):        %d\n", ra.summary.BlockedCount)
		fmt.Printf("Bypass Rate:              %.2f%%\n", ra.summary.BypassRate)

	case ModeFalsePositive:
		fmt.Println("FALSE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Legitimate Requests: %d\n", ra.summary.TotalRequests)
		fmt.Printf("Allowed (200):             %d\n", ra.summary.AllowedCount)
		fmt.Printf("False Positives (400/403): %d\n", ra.summary.FalsePositiveCount)
		fmt.Printf("False Positive Rate:       %.2f%%\n", ra.summary.FPRate)

	case ModeMixed:
		fmt.Println("MIXED TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("True Positive Metrics:")
		fmt.Printf("  Bypassed:     %d\n", ra.summary.BypassedCount)
		fmt.Printf("  Blocked:      %d\n", ra.summary.BlockedCount)
		fmt.Printf("  Bypass Rate:  %.2f%%\n", ra.summary.BypassRate)
		fmt.Println("\nFalse Positive Metrics:")
		fmt.Printf("  Allowed:      %d\n", ra.summary.AllowedCount)
		fmt.Printf("  FP Count:     %d\n", ra.summary.FalsePositiveCount)
		fmt.Printf("  FP Rate:      %.2f%%\n", ra.summary.FPRate)
	}

	fmt.Println(strings.Repeat("=", 60))
}
