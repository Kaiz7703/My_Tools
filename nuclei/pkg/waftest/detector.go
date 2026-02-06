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
}

// NewWAFBypassDetector creates a new WAF bypass detector with default settings
func NewWAFBypassDetector() *WAFBypassDetector {
	return &WAFBypassDetector{
		HeaderName:  "X-WAF-Status",
		PassedValue: "Passed",
	}
}

// CheckBypass checks if the response indicates a successful WAF bypass
// Returns true if:
// 1. HTTP status code is 200
// 2. Response header X-WAF-Status equals "Passed"
func (d *WAFBypassDetector) CheckBypass(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Check X-WAF-Status header
	headerValue := resp.Header.Get(d.HeaderName)
	if headerValue == "" {
		return false
	}

	// Case-insensitive comparison
	return strings.EqualFold(strings.TrimSpace(headerValue), d.PassedValue)
}

// IsBypassed checks bypass status using raw values
func (d *WAFBypassDetector) IsBypassed(statusCode int, wafStatus string) bool {
	// Check HTTP status code
	if statusCode != http.StatusOK {
		return false
	}

	// Check X-WAF-Status header
	if wafStatus == "" {
		return false
	}

	// Case-insensitive comparison
	return strings.EqualFold(strings.TrimSpace(wafStatus), d.PassedValue)
}

// GetBypassStatus returns a human-readable status string
func (d *WAFBypassDetector) GetBypassStatus(resp *http.Response) string {
	if d.CheckBypass(resp) {
		return "Bypassed"
	}
	return "Blocked"
}
