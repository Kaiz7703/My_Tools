package waftest

import (
	"net/http"
	"strings"
)

// WAFBypassDetector checks if a response indicates successful WAF bypass
type WAFBypassDetector struct {
	// HeaderName is the name of the header to check (default: X-WAF-Status)
	HeaderName string
	// PassedValue is the value that indicates bypass success (default: Passed)
	PassedValue string
	// Mode determines detection strategy: "strict" (default) or "header"
	Mode string
}

// NewWAFBypassDetector creates a new WAF bypass detector with default settings
func NewWAFBypassDetector(mode string) *WAFBypassDetector {
	if mode == "" {
		mode = "strict"
	}
	return &WAFBypassDetector{
		HeaderName:  "X-WAF-Status",
		PassedValue: "Passed",
		Mode:        mode,
	}
}

// CheckBypass checks if the response indicates a successful WAF bypass
// Returns true if:
// 1. HTTP status code is 200 (in strict mode)
// 2. Response header X-WAF-Status equals "Passed"
func (d *WAFBypassDetector) CheckBypass(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check X-WAF-Status header
	headerValue := resp.Header.Get(d.HeaderName)
	if headerValue == "" {
		return false
	}

	headerPassed := strings.EqualFold(strings.TrimSpace(headerValue), d.PassedValue)
	if !headerPassed {
		return false
	}

	// If mode is header-only, we are done
	if d.Mode == "header" {
		return true
	}

	// Default/Strict: Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return false
	}

	return true
}

// IsBypassed checks bypass status using raw values
func (d *WAFBypassDetector) IsBypassed(statusCode int, wafStatus string) bool {
	// Check X-WAF-Status header
	if wafStatus == "" {
		return false
	}

	headerPassed := strings.EqualFold(strings.TrimSpace(wafStatus), d.PassedValue)
	if !headerPassed {
		return false
	}

	// If mode is header-only, we are done
	if d.Mode == "header" {
		return true
	}

	// Default/Strict: Check HTTP status code
	if statusCode != http.StatusOK {
		return false
	}

	return true
}

// GetBypassStatus returns a human-readable status string
func (d *WAFBypassDetector) GetBypassStatus(resp *http.Response) string {
	if d.CheckBypass(resp) {
		return "Bypassed"
	}
	return "Blocked"
}
