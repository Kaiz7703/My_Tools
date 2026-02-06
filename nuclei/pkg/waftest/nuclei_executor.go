package waftest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
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

	// Initialize all protocol clients (DNS, HTTP, Network, etc.)
	// This MUST be called before creating ExecutorOptions
	if err := protocolinit.Init(options); err != nil {
		return nil, fmt.Errorf("failed to initialize protocols: %w", err)
	}

	// Create executor options
	executorOpts := &protocols.ExecutorOptions{
		Options:  options,
		Catalog:  catalogInstance,
		Progress: &VoidProgress{}, // Fix: Set progress tracker to prevent nil pointer panic
		Logger:   gologger.DefaultLogger,
		Parser:   parser, // Required by templates.Parse()
		Output:   &VoidWriter{}, // Fix: Set output writer to prevent nil pointer panic
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
	// Always mark template as completed, even if execution fails
	// This prevents infinite loops when templates have errors
	defer ne.stateManager.MarkCompleted([]string{templatePath})
	
	// Parse and compile template using Nuclei
	template, err := templates.Parse(templatePath, nil, ne.executorOpts)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	
	// Skip if template is nil (e.g., global matchers)
	if template == nil {
		return nil
	}

	// FORCE MATCH: Override matchers to catch-all
	// This ensures we get a result for every request with actual status code
	ne.forceTemplateMatch(template)

	// Create scan context
	metaInput := contextargs.NewMetaInput()
	metaInput.Input = ne.target
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = metaInput
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Flow templates require OnResult callback to be set
	// We use this to collect results from flow executions
	var flowResults []*output.ResultEvent
	scanCtx.OnResult = func(event *output.InternalWrappedEvent) {
		if event != nil && event.Results != nil {
			flowResults = append(flowResults, event.Results...)
		}
	}

	// Execute template and get results
	gologger.Info().Msgf("[%s] Executing template...", template.ID)
	results, err := template.Executer.ExecuteWithResults(scanCtx)
	if err != nil {
		gologger.Error().Msgf("[%s] Execution error: %v", template.ID, err)
		return fmt.Errorf("template execution failed: %w", err)
	}

	// Merge results from callback (flow) and return value (simple)
	if len(flowResults) > 0 {
		results = append(results, flowResults...)
	}

	// Log results count
	gologger.Debug().Msgf("[%s] Got %d results", template.ID, len(results))

	// Process results
	if len(results) == 0 {
		// Template executed but no results (didn't match)
		// We treat this as "Blocked" or "Not Vulnerable" for WAF testing
		// Since we can't get the actual response status without a match, 
		// we log it as a special status.
		gologger.Debug().Msgf("[%s] No results found, creating synthetic blocked result", template.ID)
		
		syntheticResult := &output.ResultEvent{
			TemplateID: template.ID,
			Info:       template.Info,
			Matched:    ne.target,
			Timestamp:  time.Now(),
			// We assume blocked if not bypassed/matched
			Metadata: map[string]interface{}{
				"status_code":      403, // Assume blocked
				"synthetic_result": true,
			},
		}
		ne.processResult(syntheticResult)
	} else {
		// Process each result
		for i, result := range results {
			gologger.Debug().Msgf("[%s] Processing result %d/%d", template.ID, i+1, len(results))
			ne.processResult(result)
		}
	}

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

// forceTemplateMatch overrides template matchers to ensure we get results for every request
// regardless of whether vulnerability signature matches. This allows WAF testing on non-vulnerable targets.
func (ne *NucleiExecutor) forceTemplateMatch(template *templates.Template) {
	// Create a catch-all matcher (DSL: true)
	catchAllMatcher := &matchers.Matcher{
		Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
		DSL:  []string{"true"},
		Name: "waf-test-catch-all",
	}

	// Create operators with this matcher
	catchAllOperators := &operators.Operators{
		Matchers: []*matchers.Matcher{catchAllMatcher},
	}

	// Inject into HTTP requests
	for _, req := range template.RequestsHTTP {
		req.CompiledOperators = catchAllOperators
		// We can also clear req.Matchers if needed, but CompiledOperators is what Executer uses
	}
}

// VoidWriter implements output.Writer but does nothing
// This is used to prevent nil pointer panics when Nuclei logging is enabled
type VoidWriter struct{}

func (w *VoidWriter) Close() {}
func (w *VoidWriter) Colorizer() aurora.Aurora { return nil }
func (w *VoidWriter) Write(*output.ResultEvent) error { return nil }
func (w *VoidWriter) WriteFailure(*output.InternalWrappedEvent) error { return nil }
func (w *VoidWriter) Request(templateID, url, requestType string, err error) {}
func (w *VoidWriter) RequestStatsLog(statusCode, response string) {}
func (w *VoidWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
func (w *VoidWriter) ResultCount() int { return 0 }

// VoidProgress implements progress.Progress interface but does nothing
// This is used to prevent nil pointer panics when Nuclei execution updates progress
type VoidProgress struct{}

func (p *VoidProgress) Stop() {}
func (p *VoidProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (p *VoidProgress) AddToTotal(delta int64) {}
func (p *VoidProgress) IncrementRequests() {}
func (p *VoidProgress) SetRequests(count uint64) {}
func (p *VoidProgress) IncrementMatched() {}
func (p *VoidProgress) IncrementErrorsBy(count int64) {}
func (p *VoidProgress) IncrementFailedRequestsBy(count int64) {}
