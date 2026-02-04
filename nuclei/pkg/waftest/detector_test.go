package waftest

import (
	"net/http"
	"testing"
)

func TestNewWAFBypassDetector(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	if detector.HeaderName != "X-WAF-Status" {
		t.Errorf("Expected HeaderName to be 'X-WAF-Status', got '%s'", detector.HeaderName)
	}
	
	if detector.PassedValue != "Passed" {
		t.Errorf("Expected PassedValue to be 'Passed', got '%s'", detector.PassedValue)
	}
}

func TestCheckBypass_Success(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	// Create response with HTTP 200 and X-WAF-Status: Passed
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-WAF-Status", "Passed")
	
	if !detector.CheckBypass(resp) {
		t.Error("Expected CheckBypass to return true for HTTP 200 + X-WAF-Status: Passed")
	}
}

func TestCheckBypass_MissingHeader(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	// Create response with HTTP 200 but missing X-WAF-Status header
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	
	if detector.CheckBypass(resp) {
		t.Error("Expected CheckBypass to return false when X-WAF-Status header is missing")
	}
}

func TestCheckBypass_WrongStatusCode(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	// Create response with HTTP 403 and X-WAF-Status: Passed
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-WAF-Status", "Passed")
	
	if detector.CheckBypass(resp) {
		t.Error("Expected CheckBypass to return false for HTTP 403 even with X-WAF-Status: Passed")
	}
}

func TestCheckBypass_WrongHeaderValue(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	// Create response with HTTP 200 and X-WAF-Status: Blocked
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-WAF-Status", "Blocked")
	
	if detector.CheckBypass(resp) {
		t.Error("Expected CheckBypass to return false for X-WAF-Status: Blocked")
	}
}

func TestCheckBypass_CaseInsensitive(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	testCases := []struct {
		name        string
		headerValue string
		expected    bool
	}{
		{"lowercase", "passed", true},
		{"uppercase", "PASSED", true},
		{"mixed case", "PaSsEd", true},
		{"with spaces", "  Passed  ", true},
		{"wrong value", "failed", false},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}
			resp.Header.Set("X-WAF-Status", tc.headerValue)
			
			result := detector.CheckBypass(resp)
			if result != tc.expected {
				t.Errorf("For header value '%s', expected %v, got %v", tc.headerValue, tc.expected, result)
			}
		})
	}
}

func TestCheckBypass_NilResponse(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	if detector.CheckBypass(nil) {
		t.Error("Expected CheckBypass to return false for nil response")
	}
}

func TestGetBypassStatus(t *testing.T) {
	detector := NewWAFBypassDetector()
	
	// Test bypassed status
	respBypassed := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	respBypassed.Header.Set("X-WAF-Status", "Passed")
	
	if status := detector.GetBypassStatus(respBypassed); status != "Bypassed" {
		t.Errorf("Expected status 'Bypassed', got '%s'", status)
	}
	
	// Test blocked status
	respBlocked := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     make(http.Header),
	}
	
	if status := detector.GetBypassStatus(respBlocked); status != "Blocked" {
		t.Errorf("Expected status 'Blocked', got '%s'", status)
	}
}
