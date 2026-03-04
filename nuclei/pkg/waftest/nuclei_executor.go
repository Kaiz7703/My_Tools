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
	target          string
	options         *types.Options
	executorOpts    *protocols.ExecutorOptions
	catalog         catalog.Catalog
	parser          *templates.Parser
	detector        *WAFBypassDetector
	csvWriter       *output.CSVWriter
	stateManager    *StateManager
	detailedVerbose bool // Print full request/response details
}

// NewNucleiExecutor creates a new Nuclei-powered executor
func NewNucleiExecutor(target string, detector *WAFBypassDetector,
	csvWriter *output.CSVWriter, stateManager *StateManager, detailedVerbose bool) (*NucleiExecutor, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	// Create minimal Nuclei options
	options := &types.Options{
		Targets:              []string{target},
		Silent:               true,
		NoColor:              true,
		Verbose:              false,
		Debug:                false,
		UpdateTemplates:      false,
		NoInteractsh:         true,
		Timeout:              10,
		Retries:              0,
		RateLimit:            0,
		BulkSize:             1,
		TemplateThreads:      1,
		Logger:               gologger.DefaultLogger,
		StoreResponse:        true, // CRITICAL: Enable response storage for status code extraction
		AllowLocalFileAccess: true, // CRITICAL: Allow loading payload lists from external txt files
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
		Parser:   parser,        // Required by templates.Parse()
		Output:   &VoidWriter{}, // Fix: Set output writer to prevent nil pointer panic
	}

	return &NucleiExecutor{
		target:          target,
		options:         options,
		executorOpts:    executorOpts,
		catalog:         catalogInstance,
		parser:          parser,
		detector:        detector,
		csvWriter:       csvWriter,
		stateManager:    stateManager,
		detailedVerbose: detailedVerbose,
	}, nil
}

// Execute executes a single template using Nuclei engine
func (ne *NucleiExecutor) Execute(ctx context.Context, templatePath string) (retErr error) {
	templateID := filepath.Base(templatePath)
	templateID = strings.TrimSuffix(templateID, filepath.Ext(templateID))

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			gologger.Warning().Msgf("[%s] Recovered from panic: %v", templateID, r)
			ne.stateManager.RecordFailed(templateID, fmt.Sprintf("panic: %v", r))
			retErr = nil // Continue to next template
		}
	}()

	defer ne.stateManager.MarkCompleted([]string{templatePath})

	// Pre-process template: Flatten Flows and Inject Matchers
	rawBytes, err := os.ReadFile(templatePath)
	if err != nil {
		ne.stateManager.RecordFailed(templateID, fmt.Sprintf("read error: %v", err))
		return nil // Continue to next template
	}

	// Early detection: Check if template requires interactsh BEFORE processing
	rawContent := string(rawBytes)
	if strings.Contains(rawContent, "interactsh-url") ||
		strings.Contains(rawContent, "{{interactsh") ||
		strings.Contains(rawContent, "oast-") {
		gologger.Debug().Msgf("[%s] Skipping: requires interactsh (detected in template)", templateID)
		ne.stateManager.RecordSkipped(templateID, "requires interactsh")
		return nil
	}

	modBytes, err := ne.preprocessTemplate(rawBytes, templatePath)
	if err != nil {
		gologger.Warning().Msgf("[%s] Failed to preprocess: %v", templateID, err)
		modBytes = rawBytes
	}

	// Create temp file
	tmpFile, err := os.CreateTemp(filepath.Dir(templatePath), "waf-test-*.yaml")
	if err != nil {
		ne.stateManager.RecordFailed(templateID, fmt.Sprintf("temp file error: %v", err))
		return nil
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(modBytes); err != nil {
		tmpFile.Close()
		ne.stateManager.RecordFailed(templateID, fmt.Sprintf("write error: %v", err))
		return nil
	}
	tmpFile.Close()

	// Parse template
	template, err := templates.Parse(tmpFile.Name(), nil, ne.executorOpts)
	if err != nil {
		// Check if interactsh-related error
		if strings.Contains(err.Error(), "interactsh") ||
			strings.Contains(err.Error(), "oast") ||
			strings.Contains(err.Error(), "unresolved variables") {
			gologger.Debug().Msgf("[%s] Skipping: requires interactsh", templateID)
			ne.stateManager.RecordSkipped(templateID, "requires interactsh")
			return nil
		}

		gologger.Warning().Msgf("[%s] Parse error: %v", templateID, err)
		ne.stateManager.RecordFailed(templateID, fmt.Sprintf("parse error: %v", err))
		return nil
	}
	template.Path = templatePath

	if template == nil {
		return nil
	}

	// Create scan context
	metaInput := contextargs.NewMetaInput()
	metaInput.Input = ne.target

	// Debug: Log what we're passing to template
	gologger.Debug().Msgf("[%s] Setting target for template: %s", template.ID, ne.target)
	gologger.Debug().Msgf("[%s] Template will receive {{Hostname}} = %s", template.ID, ne.target)

	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = metaInput
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Callback for Flow results (deprecated if we flatten, but good for backup)
	var flowResults []*output.ResultEvent
	var internalEvents []*output.InternalWrappedEvent // Store InternalEvents for status code extraction

	scanCtx.OnResult = func(event *output.InternalWrappedEvent) {
		if event != nil {
			// Store the InternalEvent for later processing
			internalEvents = append(internalEvents, event)

			if event.Results != nil {
				flowResults = append(flowResults, event.Results...)
			}
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

	for _, r := range results {
		uniqueResults[genKey(r)] = r
	}
	for _, r := range flowResults {
		uniqueResults[genKey(r)] = r
	}

	finalResults := make([]*output.ResultEvent, 0, len(uniqueResults))
	for _, r := range uniqueResults {
		finalResults = append(finalResults, r)
	}
	results = finalResults

	gologger.Debug().Msgf("[%s] Got %d unique results, %d internal events", template.ID, len(results), len(internalEvents))

	// Create a map to enrich ResultEvents with InternalEvent data
	enrichmentMap := make(map[string]map[string]interface{})
	for _, ie := range internalEvents {
		if ie.InternalEvent != nil {
			key := fmt.Sprintf("%s|%s", template.ID, ie.InternalEvent["matched"])
			enrichmentMap[key] = ie.InternalEvent
		}
	}

	// Processing
	if len(results) == 0 {
		gologger.Debug().Msgf("[%s] No results found, generating synthetic blocked result", template.ID)
		syntheticResult := &output.ResultEvent{
			TemplateID: template.ID,
			Info:       template.Info,
			Matched:    ne.target,
			Timestamp:  time.Now(),
			Metadata:   map[string]interface{}{"status_code": 403, "synthetic_result": true},
		}
		ne.processResult(syntheticResult, 1, 1, nil)
		// Finalize template stats for synthetic result
		ne.stateManager.FinalizeTemplate(template.ID)
	} else {
		total := len(results)
		for i, result := range results {
			gologger.Debug().Msgf("[%s] Processing result %d/%d", template.ID, i+1, total)

			// Try to find matching InternalEvent for enrichment
			key := fmt.Sprintf("%s|%s", result.TemplateID, result.Matched)
			internalEvent := enrichmentMap[key]

			ne.processResult(result, i+1, total, internalEvent)
		}

		// Finalize template stats after processing all results
		ne.stateManager.FinalizeTemplate(template.ID)
	}

	return nil
}

// preprocessTemplate removes Flow logic and injects catch-all matchers
func (ne *NucleiExecutor) preprocessTemplate(data []byte, templatePath string) ([]byte, error) {
	var tpl map[string]interface{}
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil, err
	}

	// 1. Remove 'flow' key to standardise execution as sequential HTTP requests
	delete(tpl, "flow")
	// Ensure we don't stop early
	tpl["stop-at-first-match"] = false

	// Helper to resolve and embed payload lists directly into memory
	readPayloadFile := func(path string) ([]string, bool) {
		absPath := path
		if !filepath.IsAbs(path) {
			absPath = filepath.Join(filepath.Dir(templatePath), path)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return nil, false
		}

		fileData, err := os.ReadFile(absPath)
		if err != nil {
			return nil, false
		}

		lines := strings.Split(string(fileData), "\n")
		var validLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				validLines = append(validLines, line)
			}
		}

		gologger.Info().Msgf("[%s] Extracted %d payloads from %s and embedded directly into template memory", filepath.Base(templatePath), len(validLines), filepath.Base(absPath))
		return validLines, true
	}

	// Cache variables for lookup
	varMapCache := make(map[string]interface{})
	if vars, ok := tpl["variables"]; ok {
		if varsMap, ok := vars.(map[interface{}]interface{}); ok {
			for k, v := range varsMap {
				if ks, ok := k.(string); ok {
					varMapCache[ks] = v
				}
			}
		}
	}

	// 2. Inject Catch-All Matchers & Embed Payloads
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
				reqMap["stop-at-first-match"] = false

				// Detect and embed payload files
				if p, ok := reqMap["payloads"]; ok {
					if payloadsMap, ok := p.(map[interface{}]interface{}); ok {
						for k, v := range payloadsMap {
							processStrPayload := func(strVal string) interface{} {
								if strings.HasPrefix(strVal, "{{") && strings.HasSuffix(strVal, "}}") {
									varName := strings.TrimSuffix(strings.TrimPrefix(strVal, "{{"), "}}")
									if fileRef, exists := varMapCache[varName].(string); exists {
										if lines, ok := readPayloadFile(fileRef); ok {
											return lines
										}
									}
								} else {
									// Direct path matching .txt
									if strings.HasSuffix(strVal, ".txt") || strings.Contains(strVal, "/payloads/") {
										if lines, ok := readPayloadFile(strVal); ok {
											return lines
										}
									}
								}
								return strVal
							}

							if strVal, isStr := v.(string); isStr {
								payloadsMap[k] = processStrPayload(strVal)
							} else if arrVal, isArr := v.([]interface{}); isArr {
								var newArr []interface{}
								for _, item := range arrVal {
									if strItem, isItemStr := item.(string); isItemStr {
										res := processStrPayload(strItem)
										if lines, isSlice := res.([]string); isSlice {
											for _, l := range lines {
												newArr = append(newArr, l)
											}
										} else {
											newArr = append(newArr, strItem)
										}
									} else {
										newArr = append(newArr, item)
									}
								}
								payloadsMap[k] = newArr
							}
						}
					}
				}
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

	bytes, err := yaml.Marshal(tpl)
	return bytes, err
}

// processResult processes a single Nuclei result event
func (ne *NucleiExecutor) processResult(result *output.ResultEvent, flowIndex, totalFlow int, internalEvent map[string]interface{}) {
	statusCode := ne.extractStatusCode(result, internalEvent)
	wafStatus := ne.extractWAFStatus(result, internalEvent)
	bypassed := ne.detector.IsBypassed(statusCode, wafStatus)

	ne.stateManager.RecordResult(result.TemplateID, bypassed)

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

	// Detailed verbose mode: Print full request/response
	if ne.detailedVerbose {
		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Printf("TEMPLATE: %s | STATUS: %s\n", result.TemplateID, status)
		fmt.Println(strings.Repeat("=", 70))

		// Print request details
		if result.Request != "" {
			fmt.Println("\n📤 REQUEST:")
			fmt.Println(strings.Repeat("-", 70))
			fmt.Println(result.Request)
		}

		// Print response details
		if result.Response != "" {
			fmt.Println("\n📥 RESPONSE:")
			fmt.Println(strings.Repeat("-", 70))
			fmt.Println(result.Response)
		} else if internalEvent != nil {
			// Try to get response from InternalEvent
			if respBody, ok := internalEvent["body"].(string); ok && respBody != "" {
				fmt.Println("\n📥 RESPONSE BODY:")
				fmt.Println(strings.Repeat("-", 70))
				fmt.Println(respBody)
			}
			if respHeaders, ok := internalEvent["response_headers"].(map[string]interface{}); ok {
				fmt.Println("\n📋 RESPONSE HEADERS:")
				fmt.Println(strings.Repeat("-", 70))
				for k, v := range respHeaders {
					fmt.Printf("%s: %v\n", k, v)
				}
			}
		}

		// Print metadata
		if len(result.Metadata) > 0 {
			fmt.Println("\n📊 METADATA:")
			fmt.Println(strings.Repeat("-", 70))
			for k, v := range result.Metadata {
				fmt.Printf("%s: %v\n", k, v)
			}
		}

		fmt.Println(strings.Repeat("=", 70) + "\n")
	}

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

// extractStatusCode extracts HTTP status code from result
// Priority: InternalEvent["status_code"] > result.Response parsing
func (ne *NucleiExecutor) extractStatusCode(result *output.ResultEvent, internalEvent map[string]interface{}) int {
	// Method 1: Extract from InternalEvent (MOST RELIABLE!)
	if internalEvent != nil {
		if statusCode, ok := internalEvent["status_code"]; ok {
			switch v := statusCode.(type) {
			case int:
				gologger.Info().Msgf("[%s] ✓ Extracted status code from InternalEvent: %d", result.TemplateID, v)
				return v
			case float64:
				code := int(v)
				gologger.Info().Msgf("[%s] ✓ Extracted status code from InternalEvent (float64): %d", result.TemplateID, code)
				return code
			}
		}
		gologger.Debug().Msgf("[%s] InternalEvent keys: %v", result.TemplateID, getKeys(internalEvent))
	}

	// Method 2: Parse from result.Response string (fallback)
	gologger.Debug().Msgf("[%s] Response length: %d bytes", result.TemplateID, len(result.Response))
	if result.Response == "" {
		gologger.Warning().Msgf("[%s] Response field is EMPTY! Cannot extract status code.", result.TemplateID)
		gologger.Debug().Msgf("[%s] Request: %d bytes", result.TemplateID, len(result.Request))
		return 0
	}

	// Show first 200 chars of response for debugging
	preview := result.Response
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	gologger.Debug().Msgf("[%s] Response preview: %s", result.TemplateID, preview)

	// Parse from Response string
	lines := strings.Split(result.Response, "\n")
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(strings.TrimRight(lines[0], "\r"))
		gologger.Debug().Msgf("[%s] First line: '%s'", result.TemplateID, firstLine)

		if strings.HasPrefix(firstLine, "HTTP/") {
			parts := strings.Fields(firstLine)
			gologger.Debug().Msgf("[%s] Parsed parts: %v", result.TemplateID, parts)

			if len(parts) >= 2 {
				var code int
				n, err := fmt.Sscanf(parts[1], "%d", &code)
				if err == nil && n == 1 && code > 0 {
					gologger.Info().Msgf("[%s] ✓ Extracted status code from Response: %d", result.TemplateID, code)
					return code
				} else {
					gologger.Warning().Msgf("[%s] Failed to parse status code from '%s': err=%v, n=%d", result.TemplateID, parts[1], err, n)
				}
			}
		} else {
			gologger.Warning().Msgf("[%s] First line doesn't start with 'HTTP/': %s", result.TemplateID, firstLine)
		}
	}

	gologger.Warning().Msgf("[%s] ✗ Returning status code 0", result.TemplateID)
	return 0
}

// Helper function to get keys from map
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (ne *NucleiExecutor) extractWAFStatus(result *output.ResultEvent, internalEvent map[string]interface{}) string {
	// Method 1: Extract from InternalEvent (headers are stored here)
	if internalEvent != nil {
		// Try x_waf_status directly
		if val, ok := internalEvent["x_waf_status"]; ok {
			if s, ok := val.(string); ok && s != "" {
				gologger.Debug().Msgf("[%s] Found WAF status in InternalEvent: %s", result.TemplateID, s)
				return s
			}
		}
	}

	// Method 2: Try ResultEvent.Metadata (unlikely but check)
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
		if len(parts) >= 2 {
			return parts[1]
		}
		return result.Request
	}
	if result.Matched != "" {
		return result.Matched
	}
	return ""
}

func (ne *NucleiExecutor) Close() error { return nil }

type VoidWriter struct{}

func (w *VoidWriter) Close()                                                              {}
func (w *VoidWriter) Colorizer() aurora.Aurora                                            { return nil }
func (w *VoidWriter) Write(*output.ResultEvent) error                                     { return nil }
func (w *VoidWriter) WriteFailure(*output.InternalWrappedEvent) error                     { return nil }
func (w *VoidWriter) Request(templateID, url, requestType string, err error)              {}
func (w *VoidWriter) RequestStatsLog(statusCode, response string)                         {}
func (w *VoidWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
func (w *VoidWriter) ResultCount() int                                                    { return 0 }

type VoidProgress struct{}

func (p *VoidProgress) Stop()                                                    {}
func (p *VoidProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (p *VoidProgress) AddToTotal(delta int64)                                   {}
func (p *VoidProgress) IncrementRequests()                                       {}
func (p *VoidProgress) SetRequests(count uint64)                                 {}
func (p *VoidProgress) IncrementMatched()                                        {}
func (p *VoidProgress) IncrementErrorsBy(count int64)                            {}
func (p *VoidProgress) IncrementFailedRequestsBy(count int64)                    {}
