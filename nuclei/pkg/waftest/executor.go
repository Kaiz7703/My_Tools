package waftest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gopkg.in/yaml.v3"
)

// SimpleTemplate represents a simplified Nuclei template for WAF testing
type SimpleTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string `yaml:"name"`
		Author      string `yaml:"author"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
	} `yaml:"info"`
	HTTP []struct {
		Method  string            `yaml:"method"`
		Path    []string          `yaml:"path"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
		Raw     []string          `yaml:"raw"`
	} `yaml:"http"`
}

// TemplateExecutor executes Nuclei templates for WAF testing
type TemplateExecutor struct {
	target       string
	httpClient   *http.Client
	detector     *WAFBypassDetector
	csvWriter    *output.CSVWriter
	stateManager *StateManager
}

// NewTemplateExecutor creates a new template executor
func NewTemplateExecutor(target string, detector *WAFBypassDetector, 
                         csvWriter *output.CSVWriter, stateManager *StateManager) (*TemplateExecutor, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &TemplateExecutor{
		target:       target,
		httpClient:   client,
		detector:     detector,
		csvWriter:    csvWriter,
		stateManager: stateManager,
	}, nil
}

// Execute executes a single template
func (te *TemplateExecutor) Execute(ctx context.Context, templatePath string) error {
	// Parse template
	tmpl, err := te.parseTemplate(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute HTTP requests
	for _, httpReq := range tmpl.HTTP {
		// Handle multiple paths
		paths := httpReq.Path
		if len(paths) == 0 {
			paths = []string{"/"}
		}

		for _, path := range paths {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Execute request
			if err := te.executeHTTPRequest(ctx, tmpl, httpReq, path); err != nil {
				gologger.Warning().Msgf("Request failed for %s: %v", filepath.Base(templatePath), err)
				continue
			}
		}
	}

	// Mark template as completed
	te.stateManager.MarkCompleted([]string{templatePath})

	return nil
}

// parseTemplate parses a Nuclei YAML template
func (te *TemplateExecutor) parseTemplate(templatePath string) (*SimpleTemplate, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	var tmpl SimpleTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	// Validate template
	if tmpl.ID == "" {
		return nil, fmt.Errorf("template missing ID")
	}
	if len(tmpl.HTTP) == 0 {
		return nil, fmt.Errorf("template has no HTTP requests")
	}

	return &tmpl, nil
}

// executeHTTPRequest executes a single HTTP request
func (te *TemplateExecutor) executeHTTPRequest(ctx context.Context, tmpl *SimpleTemplate, 
                                                httpReq struct {
	Method  string            `yaml:"method"`
	Path    []string          `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	Raw     []string          `yaml:"raw"`
}, path string) error {
	// Build URL
	url := te.target + path

	// Default method
	method := httpReq.Method
	if method == "" {
		method = "GET"
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}

	// Add headers
	for k, v := range httpReq.Headers {
		req.Header.Set(k, v)
	}

	// Set default User-Agent if not present
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Nuclei-WAF-Tester/1.0)")
	}

	// Execute request
	startTime := time.Now()
	resp, err := te.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check WAF bypass
	bypassed := te.detector.CheckBypass(resp)

	// Update state
	te.stateManager.RecordResult(tmpl.ID, bypassed)

	// Create WAF result for CSV
	status := "Blocked"
	if bypassed {
		status = "Bypassed"
	}

	wafResult := &output.WAFResult{
		TemplateID:      tmpl.ID,
		TemplateName:    tmpl.Info.Name,
		Severity:        tmpl.Info.Severity,
		TargetURL:       url,
		Status:          status,
		HTTPStatusCode:  resp.StatusCode,
		WAFStatusHeader: resp.Header.Get("X-WAF-Status"),
		Timestamp:       startTime,
		Payload:         path,
	}

	// Write to CSV
	if err := te.csvWriter.Write(wafResult); err != nil {
		gologger.Warning().Msgf("Failed to write result: %v", err)
	}

	return nil
}

// Close closes the executor
func (te *TemplateExecutor) Close() error {
	// Nothing to close for now
	return nil
}
