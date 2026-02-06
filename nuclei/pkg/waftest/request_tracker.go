package waftest

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RequestTracker tracks all HTTP requests made during template execution
type RequestTracker struct {
	detector     *WAFBypassDetector
	csvWriter    *output.CSVWriter
	stateManager *StateManager
	mu           sync.Mutex
	
	// Track requests that have been processed
	processedRequests map[string]bool
}

// NewRequestTracker creates a new request tracker
func NewRequestTracker(detector *WAFBypassDetector, csvWriter *output.CSVWriter, stateManager *StateManager) *RequestTracker {
	return &RequestTracker{
		detector:          detector,
		csvWriter:         csvWriter,
		stateManager:      stateManager,
		processedRequests: make(map[string]bool),
	}
}

// TrackRequest records an HTTP request/response pair
func (rt *RequestTracker) TrackRequest(
	templateID string,
	templateName string,
	severity string,
	targetURL string,
	statusCode int,
	responseHeaders http.Header,
	payload string,
) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Create unique key for this request
	requestKey := templateID + "|" + targetURL
	if rt.processedRequests[requestKey] {
		// Already processed this request
		return
	}
	rt.processedRequests[requestKey] = true

	// Extract WAF status header
	wafStatus := responseHeaders.Get("X-WAF-Status")

	// Check if bypassed
	bypassed := rt.detector.IsBypassed(statusCode, wafStatus)

	// Determine status
	status := "blocked"
	if bypassed {
		status = "bypassed"
	}

	// Create WAF result
	result := &output.WAFResult{
		TemplateID:      templateID,
		TemplateName:    templateName,
		Severity:        severity,
		TargetURL:       targetURL,
		Status:          status,
		HTTPStatusCode:  statusCode,
		WAFStatusHeader: wafStatus,
		Timestamp:       time.Now(),
		Payload:         payload,
	}

	// Write to CSV
	if err := rt.csvWriter.Write(result); err != nil {
		gologger.Warning().Msgf("Failed to write request to CSV: %v", err)
	}

	// Record in state
	rt.stateManager.RecordResult(bypassed)

	// Log if bypassed
	if bypassed {
		gologger.Info().Msgf("[%s] WAF BYPASSED: %s (Status: %d, Header: %s)", 
			templateID, targetURL, statusCode, wafStatus)
	} else {
		gologger.Debug().Msgf("[%s] WAF BLOCKED: %s (Status: %d)", 
			templateID, targetURL, statusCode)
	}
}

// WAFOutputWriter is a custom output writer that intercepts all results
type WAFOutputWriter struct {
	tracker *RequestTracker
}

// NewWAFOutputWriter creates a new WAF output writer
func NewWAFOutputWriter(tracker *RequestTracker) *WAFOutputWriter {
	return &WAFOutputWriter{
		tracker: tracker,
	}
}

// Write implements output.Writer interface
func (w *WAFOutputWriter) Write(event *output.ResultEvent) error {
	// Extract information from result event
	templateID := event.TemplateID
	templateName := event.Info.Name
	if templateName == "" {
		templateName = templateID
	}
	
	severity := "unknown"
	if event.Info.SeverityHolder.Severity != 0 {
		severity = event.Info.SeverityHolder.Severity.String()
	}

	targetURL := event.Matched
	if targetURL == "" {
		targetURL = event.Host
	}

	// Extract status code from metadata
	statusCode := 0
	if event.Metadata != nil {
		if sc, ok := event.Metadata["status_code"].(int); ok {
			statusCode = sc
		} else if sc, ok := event.Metadata["status"].(int); ok {
			statusCode = sc
		}
	}

	// Extract response headers
	responseHeaders := http.Header{}
	if event.Metadata != nil {
		if headers, ok := event.Metadata["response_headers"].(http.Header); ok {
			responseHeaders = headers
		} else if headers, ok := event.Metadata["headers"].(http.Header); ok {
			responseHeaders = headers
		}
	}

	// Extract payload
	payload := ""
	if event.Request != "" {
		// Try to extract payload from request
		lines := strings.Split(event.Request, "\n")
		if len(lines) > 0 {
			// First line is usually the HTTP method and path
			payload = lines[0]
		}
	}

	// Track this request
	w.tracker.TrackRequest(
		templateID,
		templateName,
		severity,
		targetURL,
		statusCode,
		responseHeaders,
		payload,
	)

	return nil
}

// Close implements output.Writer interface
func (w *WAFOutputWriter) Close() {}

// Colorizer implements output.Writer interface
func (w *WAFOutputWriter) Colorizer() aurora.Aurora {
	return nil
}

// WriteFailure implements output.Writer interface
func (w *WAFOutputWriter) WriteFailure(event *output.InternalWrappedEvent) error {
	// For WAF testing, we want to track failures too
	// as they might indicate blocked requests
	
	if event == nil || event.InternalEvent == nil {
		return nil
	}

	// Extract basic info
	templateID := ""
	if tid, ok := event.InternalEvent["template-id"].(string); ok {
		templateID = tid
	}

	targetURL := ""
	if url, ok := event.InternalEvent["host"].(string); ok {
		targetURL = url
	} else if url, ok := event.InternalEvent["url"].(string); ok {
		targetURL = url
	}

	// For failures, assume blocked (non-200 status)
	statusCode := 403
	if sc, ok := event.InternalEvent["status_code"].(int); ok {
		statusCode = sc
	}

	w.tracker.TrackRequest(
		templateID,
		"",
		"unknown",
		targetURL,
		statusCode,
		http.Header{},
		"",
	)

	return nil
}

// Request implements output.Writer interface
func (w *WAFOutputWriter) Request(templateID, url, requestType string, err error) {}

// WriteStoreDebugData implements output.Writer interface  
func (w *WAFOutputWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
