package waftest

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// NucleiExecutor executes templates using real Nuclei engine
type NucleiExecutor struct {
	target       string
	options      *types.Options
	executorOpts *protocols.ExecutorOptions
	catalog      catalog.Catalog
	parser       *templates.Parser
	detector     *WAFBypassDetector
	csvWriter    *output.CSVWriter
	stateManager *StateManager
}

// NewNucleiExecutor creates a new Nuclei-powered executor
func NewNucleiExecutor(target string, detector *WAFBypassDetector,
	csvWriter *output.CSVWriter, stateManager *StateManager) (*NucleiExecutor, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	// Create minimal Nuclei options
	options := &types.Options{
		Targets:         []string{target},
		Silent:          true,
		NoColor:         true,
		Verbose:         false,
		Debug:           false,
		UpdateTemplates: false,
		NoInteractsh:    true,
		Timeout:         10,
		Retries:         0,
		RateLimit:       0,
		BulkSize:        1,
		TemplateThreads: 1,
		Logger:          gologger.DefaultLogger,
	}

	// Create catalog
	catalogInstance := disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)

	// Create template parser
	parser := templates.NewParser()
	parser.ShouldValidate = false
	parser.NoStrictSyntax = true

	// Create executor options
	executorOpts := &protocols.ExecutorOptions{
		Options:  options,
		Catalog:  catalogInstance,
		Progress: nil,
		Logger:   gologger.DefaultLogger,
	}

	return &NucleiExecutor{
		target:       target,
		options:      options,
		executorOpts: executorOpts,
		catalog:      catalogInstance,
		parser:       parser,
		detector:     detector,
		csvWriter:    csvWriter,
		stateManager: stateManager,
	}, nil
}

// Execute executes a single template using Nuclei engine
func (ne *NucleiExecutor) Execute(ctx context.Context, templatePath string) error {
	// Parse template using Nuclei parser
	parsedTemplate, err := ne.parser.ParseTemplate(templatePath, nil)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Type assert to *templates.Template
	template, ok := parsedTemplate.(*templates.Template)
	if !ok {
		return fmt.Errorf("failed to cast template to *templates.Template")
	}

	// Create scan context
	metaInput := &contextargs.MetaInput{
		Input: ne.target,
	}
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = metaInput
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Execute template and get results
	results, err := template.Executer.ExecuteWithResults(scanCtx)
	if err != nil {
		return fmt.Errorf("template execution failed: %w", err)
	}

	// Process each result
	for _, result := range results {
		ne.processResult(result)
	}

	// Mark template as completed
	ne.stateManager.MarkCompleted([]string{templatePath})

	return nil
}

// processResult processes a single Nuclei result event
func (ne *NucleiExecutor) processResult(result *output.ResultEvent) {
	// Extract HTTP response metadata
	statusCode := ne.extractStatusCode(result)
	wafStatus := ne.extractWAFStatus(result)

	// Check WAF bypass
	bypassed := (statusCode == 200 && strings.EqualFold(wafStatus, "Passed"))

	// Record result
	ne.stateManager.RecordResult(bypassed)

	// Determine status
	status := "Blocked"
	if bypassed {
		status = "Bypassed"
	}

	// Get severity
	severity := "unknown"
	if result.Info.SeverityHolder.Severity != 0 {
		severity = result.Info.SeverityHolder.Severity.String()
	}

	// Get template name
	templateName := result.TemplateID
	if result.Info.Name != "" {
		templateName = result.Info.Name
	}

	// Create WAF result for CSV
	wafResult := &output.WAFResult{
		TemplateID:      result.TemplateID,
		TemplateName:    templateName,
		Severity:        severity,
		TargetURL:       result.Matched,
		Status:          status,
		HTTPStatusCode:  statusCode,
		WAFStatusHeader: wafStatus,
		Timestamp:       result.Timestamp,
		Payload:         ne.extractPayload(result),
	}

	// Write to CSV
	if err := ne.csvWriter.Write(wafResult); err != nil {
		gologger.Warning().Msgf("Failed to write result: %v", err)
	}

	// Log if bypassed
	if bypassed {
		gologger.Info().Msgf("[%s] WAF BYPASSED: %s", result.TemplateID, result.Matched)
	}
}

// extractStatusCode extracts HTTP status code from result metadata
func (ne *NucleiExecutor) extractStatusCode(result *output.ResultEvent) int {
	if result.Metadata == nil {
		return 0
	}

	// Try different metadata keys
	if code, ok := result.Metadata["status_code"].(int); ok {
		return code
	}
	if code, ok := result.Metadata["status-code"].(int); ok {
		return code
	}
	if code, ok := result.Metadata["response_code"].(int); ok {
		return code
	}

	// Try to extract from response string
	if result.Response != "" {
		if strings.Contains(result.Response, "HTTP/") {
			parts := strings.Fields(result.Response)
			if len(parts) >= 2 {
				var code int
				fmt.Sscanf(parts[1], "%d", &code)
				return code
			}
		}
	}

	return 0
}

// extractWAFStatus extracts X-WAF-Status header from result
func (ne *NucleiExecutor) extractWAFStatus(result *output.ResultEvent) string {
	if result.Metadata == nil {
		return ""
	}

	// Try metadata
	if status, ok := result.Metadata["waf_status"].(string); ok {
		return status
	}
	if status, ok := result.Metadata["x-waf-status"].(string); ok {
		return status
	}

	// Try to extract from response headers
	if headers, ok := result.Metadata["response_headers"].(http.Header); ok {
		return headers.Get("X-WAF-Status")
	}

	return ""
}

// extractPayload extracts the payload/path from result
func (ne *NucleiExecutor) extractPayload(result *output.ResultEvent) string {
	// Try to get from request
	if result.Request != "" {
		parts := strings.Fields(result.Request)
		if len(parts) >= 2 {
			return parts[1]
		}
		return result.Request
	}

	// Fallback to matched URL
	if result.Matched != "" {
		return result.Matched
	}

	return ""
}

// Close closes the executor and cleans up resources
func (ne *NucleiExecutor) Close() error {
	return nil
}
