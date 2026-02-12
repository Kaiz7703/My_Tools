package efficacy

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
)

type CSVWriter struct {
	outputDir string
}

func NewCSVWriter(outputDir string) *CSVWriter {
	return &CSVWriter{outputDir: outputDir}
}

func (cw *CSVWriter) WriteResults(results []TestResult, mode TestMode) error {
	var filename string

	switch mode {
	case ModeTruePositive:
		filename = "tp_results.csv"
	case ModeFalsePositive:
		filename = "fp_results.csv"
	case ModeMixed:
		filename = "mixed_results.csv"
	}

	path := filepath.Join(cw.outputDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"test_name", "url", "method", "status_code", "is_blocked"}

	if mode == ModeTruePositive || mode == ModeMixed {
		header = append(header, "bypassed")
	}
	if mode == ModeFalsePositive || mode == ModeMixed {
		header = append(header, "false_positive")
	}
	if mode == ModeMixed {
		header = append(header, "dataset_type")
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, r := range results {
		if r.StatusCode == 0 {
			continue // Skip errors
		}

		row := []string{
			r.TestName,
			r.URL,
			r.Method,
			fmt.Sprintf("%d", r.StatusCode),
			fmt.Sprintf("%t", r.IsBlocked),
		}

		if mode == ModeTruePositive || mode == ModeMixed {
			row = append(row, fmt.Sprintf("%t", r.Bypassed))
		}
		if mode == ModeFalsePositive || mode == ModeMixed {
			row = append(row, fmt.Sprintf("%t", r.FalsePositive))
		}
		if mode == ModeMixed {
			row = append(row, r.DatasetType)
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	fmt.Printf("Results saved to: %s\n", path)
	return nil
}
