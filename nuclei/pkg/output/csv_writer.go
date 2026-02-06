package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// CSVWriter writes WAF test results to CSV files
type CSVWriter struct {
	sync.Mutex
	comprehensiveFile *os.File
	bypassedFile      *os.File
	comprehensiveWriter *csv.Writer
	bypassedWriter      *csv.Writer
	comprehensivePath   string
	bypassedPath        string
	resultCount         int
	bypassedCount       int
}

// WAFResult represents a single WAF test result
type WAFResult struct {
	TemplateID       string
	TemplateName     string
	Severity         string
	TargetURL        string
	Status           string // "Bypassed" or "Blocked"
	HTTPStatusCode   int
	WAFStatusHeader  string
	Timestamp        time.Time
	Payload          string
	FlowIndex        int
	TotalFlow        int
}

// NewCSVWriter creates a new CSV writer for WAF testing
func NewCSVWriter(comprehensivePath, bypassedPath string) (*CSVWriter, error) {
	// If bypassed path not specified, auto-generate from comprehensive path
	if bypassedPath == "" {
		ext := filepath.Ext(comprehensivePath)
		base := comprehensivePath[:len(comprehensivePath)-len(ext)]
		bypassedPath = base + "_bypassed" + ext
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(comprehensivePath), 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create comprehensive CSV directory")
	}
	if err := os.MkdirAll(filepath.Dir(bypassedPath), 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create bypassed CSV directory")
	}

	// Open comprehensive file
	compFile, err := os.Create(comprehensivePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create comprehensive CSV file")
	}

	// Open bypassed file
	bypassFile, err := os.Create(bypassedPath)
	if err != nil {
		compFile.Close()
		return nil, errors.Wrap(err, "failed to create bypassed CSV file")
	}

	writer := &CSVWriter{
		comprehensiveFile:   compFile,
		bypassedFile:        bypassFile,
		comprehensiveWriter: csv.NewWriter(compFile),
		bypassedWriter:      csv.NewWriter(bypassFile),
		comprehensivePath:   comprehensivePath,
		bypassedPath:        bypassedPath,
		resultCount:         0,
		bypassedCount:       0,
	}

	// Write headers
	if err := writer.writeHeaders(); err != nil {
		writer.Close()
		return nil, err
	}

	return writer, nil
}

// writeHeaders writes CSV headers to both files
func (w *CSVWriter) writeHeaders() error {
	headers := []string{
		"Template ID",
		"Template Name",
		"Severity",
		"Target URL",
		"Status",
		"HTTP Status Code",
		"X-WAF-Status Header",
		"Timestamp",
		"WAF Status Header",
		"Timestamp",
		"Payload",
		"Flow Index",
		"Total Flow",
	}

	// Write to comprehensive file
	if err := w.comprehensiveWriter.Write(headers); err != nil {
		return errors.Wrap(err, "failed to write comprehensive headers")
	}

	// Write to bypassed file
	if err := w.bypassedWriter.Write(headers); err != nil {
		return errors.Wrap(err, "failed to write bypassed headers")
	}

	// Flush both
	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()

	return nil
}

// Write writes a WAF test result to CSV files
func (w *CSVWriter) Write(result *WAFResult) error {
	w.Lock()
	defer w.Unlock()

	if result == nil {
		return errors.New("result cannot be nil")
	}

	// Prepare CSV row
	row := []string{
		result.TemplateID,
		result.TemplateName,
		result.Severity,
		result.TargetURL,
		result.Status,
		fmt.Sprintf("%d", result.HTTPStatusCode),
		result.WAFStatusHeader,
		result.Timestamp.Format("2006-01-02 15:04:05"),
		result.Timestamp.Format("2006-01-02 15:04:05"),
		result.Payload,
		fmt.Sprintf("%d", result.FlowIndex),
		fmt.Sprintf("%d", result.TotalFlow),
	}

	// Write to comprehensive file
	if err := w.comprehensiveWriter.Write(row); err != nil {
		return errors.Wrap(err, "failed to write to comprehensive CSV")
	}
	w.resultCount++

	// Write to bypassed file if status is "Bypassed"
	if result.Status == "Bypassed" {
		if err := w.bypassedWriter.Write(row); err != nil {
			return errors.Wrap(err, "failed to write to bypassed CSV")
		}
		w.bypassedCount++
	}

	// Flush after each write to ensure data is persisted
	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()

	return nil
}

// WriteMultiple writes multiple results at once
func (w *CSVWriter) WriteMultiple(results []*WAFResult) error {
	for _, result := range results {
		if err := w.Write(result); err != nil {
			return err
		}
	}
	return nil
}

// Close closes both CSV files
func (w *CSVWriter) Close() error {
	w.Lock()
	defer w.Unlock()

	var errs []error

	// Flush writers
	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()

	// Check for flush errors
	if err := w.comprehensiveWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "comprehensive writer flush error"))
	}
	if err := w.bypassedWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "bypassed writer flush error"))
	}

	// Close files
	if err := w.comprehensiveFile.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close comprehensive file"))
	}
	if err := w.bypassedFile.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close bypassed file"))
	}

	if len(errs) > 0 {
		return errors.Errorf("errors closing CSV writer: %v", errs)
	}

	return nil
}

// GetResultCount returns the total number of results written
func (w *CSVWriter) GetResultCount() int {
	w.Lock()
	defer w.Unlock()
	return w.resultCount
}

// GetBypassedCount returns the number of bypassed results written
func (w *CSVWriter) GetBypassedCount() int {
	w.Lock()
	defer w.Unlock()
	return w.bypassedCount
}

// GetPaths returns the paths of both CSV files
func (w *CSVWriter) GetPaths() (comprehensive, bypassed string) {
	return w.comprehensivePath, w.bypassedPath
}
