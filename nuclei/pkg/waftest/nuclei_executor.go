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

	modBytesList, err := ne.preprocessTemplate(rawBytes, templatePath)
	if err != nil {
		gologger.Warning().Msgf("[%s] Failed to preprocess: %v", templateID, err)
		modBytesList = [][]byte{rawBytes} // Fallback to raw bytes
	}

	for chunkIdx, modBytes := range modBytesList {
		// Log chunk progress if there are multiple chunks
		if len(modBytesList) > 1 {
			gologger.Info().Msgf("[%s] Processing chunk %d/%d...", templateID, chunkIdx+1, len(modBytesList))
		}

		// Create temp file for this chunk
		tmpFile, err := os.CreateTemp(filepath.Dir(templatePath), "waf-test-*.yaml")
		if err != nil {
			ne.stateManager.RecordFailed(templateID, fmt.Sprintf("temp file error: %v", err))
			continue
		}

		if _, err := tmpFile.Write(modBytes); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			ne.stateManager.RecordFailed(templateID, fmt.Sprintf("write error: %v", err))
			continue
		}
		tmpFile.Close()

		// Parse template
		template, err := templates.Parse(tmpFile.Name(), nil, ne.executorOpts)
		if err != nil {
			os.Remove(tmpFile.Name())
			// Check if interactsh-related error
			if strings.Contains(err.Error(), "interactsh") ||
				strings.Contains(err.Error(), "oast") ||
				strings.Contains(err.Error(), "unresolved variables") {
				gologger.Debug().Msgf("[%s] Skipping: requires interactsh", templateID)
				ne.stateManager.RecordSkipped(templateID, "requires interactsh")
				continue
			}

			gologger.Warning().Msgf("[%s] Parse error: %v", templateID, err)
			ne.stateManager.RecordFailed(templateID, fmt.Sprintf("parse error: %v", err))
			continue
		}
		template.Path = templatePath

		if template == nil {
			os.Remove(tmpFile.Name())
			continue
		}

		// Create scan context for this specific chunk run
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = ne.target

		ctxArgs := contextargs.New(ctx)
		ctxArgs.MetaInput = metaInput
		scanCtx := scan.NewScanContext(ctx, ctxArgs)

		var flowResults []*output.ResultEvent
		var internalEvents []*output.InternalWrappedEvent

		scanCtx.OnResult = func(event *output.InternalWrappedEvent) {
			if event != nil {
				internalEvents = append(internalEvents, event)
				if event.Results != nil {
					flowResults = append(flowResults, event.Results...)
				}
			}
		}

		// Execute
		gologger.Info().Msgf("[%s] Executing template chunk %d (Batched)...", template.ID, chunkIdx+1)
		results, err := template.Executer.ExecuteWithResults(scanCtx)
		if err != nil {
			gologger.Warning().Msgf("[%s] Execution error: %v", template.ID, err)
		}

		// Deduplication Logic
		uniqueResults := make(map[string]*output.ResultEvent)
		genKey := func(r *output.ResultEvent) string {
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

		// Create enrichment map
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
		} else {
			total := len(results)
			for i, result := range results {
				key := fmt.Sprintf("%s|%s", result.TemplateID, result.Matched)
				internalEvent := enrichmentMap[key]
				ne.processResult(result, i+1, total, internalEvent)
			}
		}

		// Cleanup temp file after we are done executing the chunk
		os.Remove(tmpFile.Name())

		// Explicitly flush to disk after all results for this chunk are processed
		if err := ne.csvWriter.Flush(); err != nil {
			gologger.Warning().Msgf("[%s] Failed to explicitly flush CSV writer: %v", templateID, err)
		}
	}

	// Final explicit flush to make absolutely sure any lingering buffers in CSV are written
	if err := ne.csvWriter.Flush(); err != nil {
		gologger.Warning().Msgf("[%s] Failed to explicitly flush CSV writer: %v", templateID, err)
	}

	// Finalize template stats for this batched template run (across all chunks)
	ne.stateManager.FinalizeTemplate(templateID)

	return nil
}

// preprocessTemplate removes Flow logic and dynamically splits payload lists if they are large,
// returning an array of modified template bytes (one for each split payload chunk).
func (ne *NucleiExecutor) preprocessTemplate(data []byte, templatePath string) ([][]byte, error) {
	var baseTpl map[string]interface{}
	if err := yaml.Unmarshal(data, &baseTpl); err != nil {
		return nil, err
	}

	// 1. Remove 'flow' key to standardise execution as sequential HTTP requests
	delete(baseTpl, "flow")
	// Ensure we don't stop early
	baseTpl["stop-at-first-match"] = false

	// Helper to resolve payload paths and return them as an absolute file path
	resolvePayloadPath := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(filepath.Dir(templatePath), path)
	}

	// Find payload variables and split them if necessary
	var resolvedVarPaths []string
	var targetVarName string

	if vars, ok := baseTpl["variables"]; ok {
		if varsMap, ok := vars.(map[interface{}]interface{}); ok {
			for k, v := range varsMap {
				if strVal, ok := v.(string); ok && (strings.HasSuffix(strVal, ".txt") || strings.Contains(strVal, "/payloads/")) {
					resolvedPath := resolvePayloadPath(strVal)
					// Arbitrary limit: 5000 payloads per batched execution to protect RAM
					chunks, err := SplitPayloadFile(resolvedPath, 1500)
					if err != nil {
						gologger.Warning().Msgf("[%s] Failed to split payload file %s: %v", filepath.Base(templatePath), resolvedPath, err)
						chunks = []string{resolvedPath} // Fallback to original
					} else if len(chunks) > 1 {
						gologger.Info().Msgf("[%s] Dynamically split massive payload file %s into %d chunks of ~5000 items each.", filepath.Base(templatePath), resolvedPath, len(chunks))
					}

					// We currently support splitting only ONE massive variable per template effectively
					targetVarName = k.(string)
					resolvedVarPaths = chunks
					break // Only split the first payload variable found
				}
			}
		}
	}

	// If no payload variables were found, process normally with 1 chunk
	if len(resolvedVarPaths) == 0 {
		resolvedVarPaths = append(resolvedVarPaths, "")
	}

	var resultingTemplates [][]byte

	for _, chunkPath := range resolvedVarPaths {
		// Deep copy the base template for this chunk using YAML marshal/unmarshal
		var tpl map[string]interface{}
		tmpBytes, _ := yaml.Marshal(baseTpl)
		yaml.Unmarshal(tmpBytes, &tpl)

		varMapCache := make(map[string]interface{})

		// Re-inject the specific chunk path into the variables
		if vars, ok := tpl["variables"]; ok {
			if varsMap, ok := vars.(map[interface{}]interface{}); ok {
				for k, v := range varsMap {
					if ks, ok := k.(string); ok {
						if ks == targetVarName && chunkPath != "" {
							varsMap[k] = chunkPath
							varMapCache[ks] = chunkPath
						} else if strVal, ok := v.(string); ok && (strings.HasSuffix(strVal, ".txt") || strings.Contains(strVal, "/payloads/")) {
							// For secondary payload files not split, just resolve them
							resolvedPath := resolvePayloadPath(strVal)
							varsMap[k] = resolvedPath
							varMapCache[ks] = resolvedPath
						} else {
							varMapCache[ks] = v
						}
					}
				}
			}
		}

		// 2. Inject Catch-All Matchers & Clean Payloads
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

					// Evaluate payloads block
					if p, ok := reqMap["payloads"]; ok {
						if payloadsMap, ok := p.(map[interface{}]interface{}); ok {
							for k, v := range payloadsMap {

								// Check if the payload value is a slice/array
								if arrVal, isArr := v.([]interface{}); isArr {
									// Flatten single-item arrays that are variables or strings back into a flat string so `load.go` reads it as a file
									if len(arrVal) == 1 {
										if strItem, isItemStr := arrVal[0].(string); isItemStr {
											// If it's a variable reference, extract the var name and see if it's in our cache
											if strings.HasPrefix(strItem, "{{") && strings.HasSuffix(strItem, "}}") {
												varName := strings.TrimSuffix(strings.TrimPrefix(strItem, "{{"), "}}")
												if resolvedVarPath, exists := varMapCache[varName].(string); exists && strings.HasSuffix(resolvedVarPath, ".txt") {
													// CRITICAL: Must assign as pure Go string type to trigger 'case string' in Nuclei's load.go
													payloadsMap[k] = string(resolvedVarPath)
													gologger.Info().Msgf("[%s] Flattened payload array %s using cached variable path: %s", filepath.Base(templatePath), k, resolvedVarPath)
													continue
												}
											} else if !strings.Contains(strItem, "\n") { // if it's a flat string without newlines it might be a direct path
												resolvedDirectPath := resolvePayloadPath(strItem)
												payloadsMap[k] = string(resolvedDirectPath)
												gologger.Info().Msgf("[%s] Flattened payload array %s to direct file path: %s", filepath.Base(templatePath), k, resolvedDirectPath)
												continue
											}
										}
									}

									// If it couldn't be flattened or is a multi-item array, we must leave it alone or resolve items
									for i, item := range arrVal {
										if strItem, isItemStr := item.(string); isItemStr {
											if !strings.HasPrefix(strItem, "{{") {
												arrVal[i] = resolvePayloadPath(strItem)
											}
										}
									}
									payloadsMap[k] = arrVal

								} else if strVal, isStr := v.(string); isStr {
									// If it's already a single string, just resolve the path
									payloadsMap[k] = string(resolvePayloadPath(strVal))
									gologger.Debug().Msgf("[%s] Resolved payload string %s to: %s", filepath.Base(templatePath), k, payloadsMap[k])
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
		if err == nil {
			resultingTemplates = append(resultingTemplates, bytes)
		} else {
			gologger.Warning().Msgf("[%s] YAML Marshal error on sub-template chunk: %v", filepath.Base(templatePath), err)
		}
	}

	if len(resultingTemplates) == 0 {
		return nil, fmt.Errorf("failed to generate any template chunks")
	}

	return resultingTemplates, nil
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
