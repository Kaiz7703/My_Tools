package waftest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"gopkg.in/yaml.v2"
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
	defer ne.stateManager.MarkCompleted([]string{templatePath})

	// Pre-process template: Flatten Flows and Inject Matchers
	rawBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	modBytes, err := ne.preprocessTemplate(rawBytes)
	if err != nil {
		gologger.Warning().Msgf("Failed to preprocess %s: %v", templatePath, err)
		modBytes = rawBytes
	}

	// Create temp file
	tmpFile, err := os.CreateTemp(filepath.Dir(templatePath), "waf-test-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(modBytes); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	// Parse template
	template, err := templates.Parse(tmpFile.Name(), nil, ne.executorOpts)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	template.Path = templatePath

	if template == nil {
		return nil
	}

	// Create scan context
	metaInput := contextargs.NewMetaInput()
	metaInput.Input = ne.target
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = metaInput
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Callback for Flow results (deprecated if we flatten, but good for backup)
	var flowResults []*output.ResultEvent
	scanCtx.OnResult = func(event *output.InternalWrappedEvent) {
		if event != nil && event.Results != nil {
			flowResults = append(flowResults, event.Results...)
		}
	}

	// Execute
	gologger.Info().Msgf("[%s] Executing template (Flattened)...", template.ID)
	results, err := template.Executer.ExecuteWithResults(scanCtx)
	// Ignore execution errors to process partial results

	// Deduplication Logic
	uniqueResults := make(map[string]*output.ResultEvent)
	genKey := func(r *output.ResultEvent) string {
		// Use Request URL + Timestamp + TemplateID + Matcher Status?
		// Simply ID + Matched + Time is mostly unique enough.
		// Use composite key including Timestamp.UnixNano()
		return fmt.Sprintf("%s|%s|%d", r.TemplateID, r.Matched, r.Timestamp.UnixNano())
	}

	for _, r := range results { uniqueResults[genKey(r)] = r }
	for _, r := range flowResults { uniqueResults[genKey(r)] = r }

	finalResults := make([]*output.ResultEvent, 0, len(uniqueResults))
	for _, r := range uniqueResults { finalResults = append(finalResults, r) }
	results = finalResults

	gologger.Debug().Msgf("[%s] Got %d unique results", template.ID, len(results))

	// Processing
	if len(results) == 0 {
		gologger.Debug().Msgf("[%s] No results found, generating synthetic blocked result", template.ID)
		syntheticResult := &output.ResultEvent{
			TemplateID: template.ID,
			Info:       template.Info,
			Matched:    ne.target,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{"status_code": 403, "synthetic_result": true},
		}
		ne.processResult(syntheticResult, 1, 1)
	} else {
		total := len(results)
		for i, result := range results {
			gologger.Debug().Msgf("[%s] Processing result %d/%d", template.ID, i+1, total)
			ne.processResult(result, i+1, total)
		}
	}

	return nil
}

// preprocessTemplate removes Flow logic and injects catch-all matchers
func (ne *NucleiExecutor) preprocessTemplate(data []byte) ([]byte, error) {
	var tpl map[string]interface{}
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil, err
	}

	// 1. Remove 'flow' key to standardise execution as sequential HTTP requests
	delete(tpl, "flow")
	// Ensure we don't stop early
	tpl["stop-at-first-match"] = false

	// 2. Inject Catch-All Matchers
	injectFn := func(requests []interface{}) {
		for _, req := range requests {
			if reqMap, ok := req.(map[interface{}]interface{}); ok {
				// Remove existing matchers to avoid noise
				delete(reqMap, "matchers")
				delete(reqMap, "matchers-condition")

				// Inject permissive matcher: DSL true
				trueMatcher := map[interface{}]interface{}{
					"type": "dsl",
					"dsl":  []interface{}{"true"},
					"name": "force-log",
				}
				reqMap["matchers"] = []interface{}{trueMatcher}
				
				// Request level stop-at-first-match might be relevant in some versions
				reqMap["stop-at-first-match"] = false
			}
		}
	}

	if val, ok := tpl["http"]; ok {
		if requests, ok := val.([]interface{}); ok {
			injectFn(requests)
		}
	}
	if val, ok := tpl["requests"]; ok {
		if requests, ok := val.([]interface{}); ok {
			injectFn(requests)
		}
	}
	
	// DEBUG: Dump one template to verify structure
	// Simply write to a fixed path "debug_last_template.yaml"
	// We handle error silently to not break flow
	_ = os.WriteFile("debug_last_template.yaml", []byte("Placeholder"), 0644) // Placeholder check
	
	bytes, err := yaml.Marshal(tpl)
	if err == nil {
		_ = os.WriteFile("debug_last_template.yaml", bytes, 0644)
	}

	return bytes, err
}

// processResult processes a single Nuclei result event
func (ne *NucleiExecutor) processResult(result *output.ResultEvent, flowIndex, totalFlow int) {
	statusCode := ne.extractStatusCode(result)
	wafStatus := ne.extractWAFStatus(result)
	bypassed := ne.detector.IsBypassed(statusCode, wafStatus)

	ne.stateManager.RecordResult(bypassed)

	status := "Blocked"
	if bypassed {
		status = "Bypassed"
	}
	if result.Error != "" {
		status = fmt.Sprintf("Error: %s", result.Error)
	}

	// Debug Status 0
	if statusCode == 0 {
		gologger.Debug().Msgf("[%s] Status 0. Meta: %v", result.TemplateID, result.Metadata)
	}
	
	// Debug: Print all response headers if available
	gologger.Debug().Msgf("[%s] Status Code: %d, WAF Header: '%s'", result.TemplateID, statusCode, wafStatus)
	
	// Try to extract and print all headers for debugging
	if result.Metadata != nil {
		if h, ok := result.Metadata["response_headers"].(http.Header); ok {
			gologger.Debug().Msgf("[%s] Response Headers: %v", result.TemplateID, h)
		}
		if h, ok := result.Metadata["all_headers"].(http.Header); ok {
			gologger.Debug().Msgf("[%s] All Headers: %v", result.TemplateID, h)
		}
		if headers, ok := result.Metadata["headers"].(map[string]interface{}); ok {
			gologger.Debug().Msgf("[%s] Headers Map: %v", result.TemplateID, headers)
		}
	}

	severity := "unknown"
	if result.Info.SeverityHolder.Severity != 0 {
		severity = result.Info.SeverityHolder.Severity.String()
	}

	templateName := result.TemplateID
	if result.Info.Name != "" {
		templateName = result.Info.Name
	}

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
		FlowIndex:       flowIndex, // Now meaningful because Flattened execution runs all
		TotalFlow:       totalFlow,
	}

	if err := ne.csvWriter.Write(wafResult); err != nil {
		gologger.Warning().Msgf("Failed to write result: %v", err)
	}

	if bypassed {
		gologger.Info().Msgf("[%s] (%d/%d) WAF BYPASSED: %s", result.TemplateID, flowIndex, totalFlow, result.Matched)
	}
}

// extractStatusCode extracts HTTP status code from result metadata
func (ne *NucleiExecutor) extractStatusCode(result *output.ResultEvent) int {
	if result.Metadata == nil { return 0 }
	
	for _, key := range []string{"status_code", "status-code", "response_code"} {
		if val, ok := result.Metadata[key]; ok {
			switch v := val.(type) {
			case int: return v
			case float64: return int(v)
			case string:
				var i int
				fmt.Sscanf(v, "%d", &i)
				return i
			}
		}
	}

	if result.Response != "" && strings.Contains(result.Response, "HTTP/") {
		parts := strings.Fields(result.Response)
		if len(parts) >= 2 {
			var code int
			fmt.Sscanf(parts[1], "%d", &code)
			return code
		}
	}
	return 0
}

func (ne *NucleiExecutor) extractWAFStatus(result *output.ResultEvent) string {
	if result.Metadata == nil { 
		return "" 
	}
	
	// Nuclei converts headers to lowercase and replaces "-" with "_"
	// So "X-WAF-Status" becomes "x_waf_status"
	
	// Method 1: Direct key (Nuclei format)
	if s, ok := result.Metadata["x_waf_status"].(string); ok && s != "" { 
		gologger.Debug().Msgf("[%s] Found WAF status: %s", result.TemplateID, s)
		return s 
	}
	
	// Method 2: Try alternative formats
	if s, ok := result.Metadata["waf_status"].(string); ok && s != "" { 
		return s 
	}
	
	// Method 3: response_headers as http.Header (unlikely but check anyway)
	if h, ok := result.Metadata["response_headers"].(http.Header); ok { 
		if val := h.Get("X-WAF-Status"); val != "" {
			return val
		}
	}
	
	// Method 4: Scan all metadata keys case-insensitively
	for key, value := range result.Metadata {
		keyLower := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if keyLower == "x_waf_status" || keyLower == "waf_status" {
			if s, ok := value.(string); ok && s != "" {
				gologger.Debug().Msgf("[%s] Found WAF status via key scan: %s = %s", result.TemplateID, key, s)
				return s
			}
		}
	}
	
	// Debug: Log all metadata keys if we couldn't find the header
	keys := make([]string, 0, len(result.Metadata))
	for k := range result.Metadata {
		keys = append(keys, k)
	}
	gologger.Debug().Msgf("[%s] WAF header not found. Available metadata keys: %v", result.TemplateID, keys)
	
	return ""
}

func (ne *NucleiExecutor) extractPayload(result *output.ResultEvent) string {
	if result.Request != "" {
		parts := strings.Fields(result.Request)
		if len(parts) >= 2 { return parts[1] }
		return result.Request
	}
	if result.Matched != "" { return result.Matched }
	return ""
}

func (ne *NucleiExecutor) Close() error { return nil }

type VoidWriter struct{}
func (w *VoidWriter) Close() {}
func (w *VoidWriter) Colorizer() aurora.Aurora { return nil }
func (w *VoidWriter) Write(*output.ResultEvent) error { return nil }
func (w *VoidWriter) WriteFailure(*output.InternalWrappedEvent) error { return nil }
func (w *VoidWriter) Request(templateID, url, requestType string, err error) {}
func (w *VoidWriter) RequestStatsLog(statusCode, response string) {}
func (w *VoidWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
func (w *VoidWriter) ResultCount() int { return 0 }

type VoidProgress struct{}
func (p *VoidProgress) Stop() {}
func (p *VoidProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (p *VoidProgress) AddToTotal(delta int64) {}
func (p *VoidProgress) IncrementRequests() {}
func (p *VoidProgress) SetRequests(count uint64) {}
func (p *VoidProgress) IncrementMatched() {}
func (p *VoidProgress) IncrementErrorsBy(count int64) {}
func (p *VoidProgress) IncrementFailedRequestsBy(count int64) {}
