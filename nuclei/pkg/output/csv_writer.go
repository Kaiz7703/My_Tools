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
	comprehensiveFile          *os.File
	bypassedFile               *os.File
	bypassedTemplatesFile      *os.File
	comprehensiveWriter        *csv.Writer
	bypassedWriter             *csv.Writer
	bypassedTemplatesWriter    *csv.Writer
	comprehensivePath          string
	bypassedPath               string
	bypassedTemplatesPath      string
	resultCount                int
	bypassedCount              int
	bypassedTemplatesCount     int
}

// BypassedTemplateSummary represents a template-level bypass summary (1 row per bypassed template)
type BypassedTemplateSummary struct {
	TemplateID   string
	TemplateName string
	Severity     string
	TotalRequests int
}

// WAFResult represents a single WAF test result
type WAFResult struct {
	TemplateID      string
	TemplateName    string
	Severity        string
	TargetURL       string
	Status          string // "Bypassed" or "Blocked"
	HTTPStatusCode  int
	WAFStatusHeader string
	Timestamp       time.Time
	Payload         string
	FlowIndex       int
	TotalFlow       int
}

// NewCSVWriter creates a new CSV writer for WAF testing
func NewCSVWriter(comprehensivePath, bypassedPath string) (*CSVWriter, error) {
	// If bypassed path not specified, auto-generate from comprehensive path
	if bypassedPath == "" {
		ext := filepath.Ext(comprehensivePath)
		base := comprehensivePath[:len(comprehensivePath)-len(ext)]
		bypassedPath = base + "_bypassed" + ext
	}

	// Auto-generate bypassed templates summary path
	ext := filepath.Ext(comprehensivePath)
	base := comprehensivePath[:len(comprehensivePath)-len(ext)]
	bypassedTemplatesPath := base + "_bypassed_templates" + ext

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

	// Open bypassed templates summary file
	bypassTmplFile, err := os.Create(bypassedTemplatesPath)
	if err != nil {
		compFile.Close()
		bypassFile.Close()
		return nil, errors.Wrap(err, "failed to create bypassed templates CSV file")
	}

	writer := &CSVWriter{
		comprehensiveFile:       compFile,
		bypassedFile:            bypassFile,
		bypassedTemplatesFile:   bypassTmplFile,
		comprehensiveWriter:     csv.NewWriter(compFile),
		bypassedWriter:          csv.NewWriter(bypassFile),
		bypassedTemplatesWriter: csv.NewWriter(bypassTmplFile),
		comprehensivePath:       comprehensivePath,
		bypassedPath:            bypassedPath,
		bypassedTemplatesPath:   bypassedTemplatesPath,
		resultCount:             0,
		bypassedCount:           0,
		bypassedTemplatesCount:  0,
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

	// Write headers for bypassed templates summary file
	tmplHeaders := []string{
		"Template ID",
		"Template Name",
		"Severity",
		"Total Requests",
	}
	if err := w.bypassedTemplatesWriter.Write(tmplHeaders); err != nil {
		return errors.Wrap(err, "failed to write bypassed templates headers")
	}

	// Flush all
	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()
	w.bypassedTemplatesWriter.Flush()

	return nil
}

// WriteBypassedTemplate writes a template-level bypass summary (1 row per bypassed template)
func (w *CSVWriter) WriteBypassedTemplate(summary *BypassedTemplateSummary) error {
	w.Lock()
	defer w.Unlock()

	if summary == nil {
		return errors.New("summary cannot be nil")
	}

	row := []string{
		summary.TemplateID,
		summary.TemplateName,
		summary.Severity,
		fmt.Sprintf("%d", summary.TotalRequests),
	}

	if err := w.bypassedTemplatesWriter.Write(row); err != nil {
		return errors.Wrap(err, "failed to write to bypassed templates CSV")
	}
	w.bypassedTemplatesWriter.Flush()
	w.bypassedTemplatesFile.Sync()
	w.bypassedTemplatesCount++

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

// Flush explicitly flushes any buffered data to the underlying io.Writer
func (w *CSVWriter) Flush() error {
	w.Lock()
	defer w.Unlock()

	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()
	w.bypassedTemplatesWriter.Flush()

	var errs []error
	if err := w.comprehensiveWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "comprehensive writer flush error"))
	}
	if err := w.bypassedWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "bypassed writer flush error"))
	}
	if err := w.bypassedTemplatesWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "bypassed templates writer flush error"))
	}

	if len(errs) > 0 {
		return errors.Errorf("errors flushing CSV writer: %v", errs)
	}

	// Sync all file descriptors to disk
	if w.comprehensiveFile != nil {
		w.comprehensiveFile.Sync()
	}
	if w.bypassedFile != nil {
		w.bypassedFile.Sync()
	}
	if w.bypassedTemplatesFile != nil {
		w.bypassedTemplatesFile.Sync()
	}

	return nil
}

// Close closes all CSV files
func (w *CSVWriter) Close() error {
	w.Lock()
	defer w.Unlock()

	var errs []error

	// Flush writers
	w.comprehensiveWriter.Flush()
	w.bypassedWriter.Flush()
	w.bypassedTemplatesWriter.Flush()

	// Check for flush errors
	if err := w.comprehensiveWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "comprehensive writer flush error"))
	}
	if err := w.bypassedWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "bypassed writer flush error"))
	}
	if err := w.bypassedTemplatesWriter.Error(); err != nil {
		errs = append(errs, errors.Wrap(err, "bypassed templates writer flush error"))
	}

	// Close files
	if err := w.comprehensiveFile.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close comprehensive file"))
	}
	if err := w.bypassedFile.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close bypassed file"))
	}
	if err := w.bypassedTemplatesFile.Close(); err != nil {
		errs = append(errs, errors.Wrap(err, "failed to close bypassed templates file"))
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

// GetPaths returns the paths of all CSV files
func (w *CSVWriter) GetPaths() (comprehensive, bypassed string) {
	return w.comprehensivePath, w.bypassedPath
}

// GetBypassedTemplatesPath returns the path of the bypassed templates summary CSV
func (w *CSVWriter) GetBypassedTemplatesPath() string {
	return w.bypassedTemplatesPath
}

// GetBypassedTemplatesCount returns the number of bypassed template summaries written
func (w *CSVWriter) GetBypassedTemplatesCount() int {
	w.Lock()
	defer w.Unlock()
	return w.bypassedTemplatesCount
}
