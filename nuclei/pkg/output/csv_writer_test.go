package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCSVWriter(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")
	bypassPath := filepath.Join(tempDir, "bypassed.csv")

	writer, err := NewCSVWriter(compPath, bypassPath)
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}
	defer writer.Close()

	// Verify files were created
	if _, err := os.Stat(compPath); os.IsNotExist(err) {
		t.Error("Comprehensive CSV file was not created")
	}

	if _, err := os.Stat(bypassPath); os.IsNotExist(err) {
		t.Error("Bypassed CSV file was not created")
	}
}

func TestNewCSVWriter_AutoGenerateBypassedPath(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")

	writer, err := NewCSVWriter(compPath, "")
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}
	defer writer.Close()

	comp, bypass := writer.GetPaths()
	expectedBypass := filepath.Join(tempDir, "results_bypassed.csv")

	if comp != compPath {
		t.Errorf("Expected comprehensive path '%s', got '%s'", compPath, comp)
	}

	if bypass != expectedBypass {
		t.Errorf("Expected bypassed path '%s', got '%s'", expectedBypass, bypass)
	}
}

func TestCSVWriter_Write(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")
	bypassPath := filepath.Join(tempDir, "bypassed.csv")

	writer, err := NewCSVWriter(compPath, bypassPath)
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}

	// Write a bypassed result
	result := &WAFResult{
		TemplateID:      "CVE-2016-0001",
		TemplateName:    "SQL Injection Test",
		Severity:        "high",
		TargetURL:       "http://testapp.local/search",
		Status:          "Bypassed",
		HTTPStatusCode:  200,
		WAFStatusHeader: "Passed",
		Timestamp:       time.Now(),
		Payload:         "' OR '1'='1",
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	writer.Close()

	// Read comprehensive file
	compData, err := os.ReadFile(compPath)
	if err != nil {
		t.Fatalf("Failed to read comprehensive file: %v", err)
	}

	compContent := string(compData)
	if !strings.Contains(compContent, "CVE-2016-0001") {
		t.Error("Comprehensive file does not contain template ID")
	}

	// Read bypassed file
	bypassData, err := os.ReadFile(bypassPath)
	if err != nil {
		t.Fatalf("Failed to read bypassed file: %v", err)
	}

	bypassContent := string(bypassData)
	if !strings.Contains(bypassContent, "CVE-2016-0001") {
		t.Error("Bypassed file does not contain template ID")
	}
}

func TestCSVWriter_WriteBlocked(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")
	bypassPath := filepath.Join(tempDir, "bypassed.csv")

	writer, err := NewCSVWriter(compPath, bypassPath)
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}

	// Write a blocked result
	result := &WAFResult{
		TemplateID:      "CVE-2016-0002",
		TemplateName:    "XSS Test",
		Severity:        "medium",
		TargetURL:       "http://testapp.local/page",
		Status:          "Blocked",
		HTTPStatusCode:  403,
		WAFStatusHeader: "",
		Timestamp:       time.Now(),
		Payload:         "<script>alert(1)</script>",
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	writer.Close()

	// Read comprehensive file
	compData, err := os.ReadFile(compPath)
	if err != nil {
		t.Fatalf("Failed to read comprehensive file: %v", err)
	}

	compContent := string(compData)
	if !strings.Contains(compContent, "CVE-2016-0002") {
		t.Error("Comprehensive file does not contain blocked template")
	}

	// Read bypassed file
	bypassData, err := os.ReadFile(bypassPath)
	if err != nil {
		t.Fatalf("Failed to read bypassed file: %v", err)
	}

	bypassContent := string(bypassData)
	if strings.Contains(bypassContent, "CVE-2016-0002") {
		t.Error("Bypassed file should not contain blocked template")
	}
}

func TestCSVWriter_WriteMultiple(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")
	bypassPath := filepath.Join(tempDir, "bypassed.csv")

	writer, err := NewCSVWriter(compPath, bypassPath)
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}

	results := []*WAFResult{
		{
			TemplateID:      "CVE-2016-0001",
			TemplateName:    "Test 1",
			Severity:        "high",
			TargetURL:       "http://test.local/1",
			Status:          "Bypassed",
			HTTPStatusCode:  200,
			WAFStatusHeader: "Passed",
			Timestamp:       time.Now(),
			Payload:         "payload1",
		},
		{
			TemplateID:      "CVE-2016-0002",
			TemplateName:    "Test 2",
			Severity:        "medium",
			TargetURL:       "http://test.local/2",
			Status:          "Blocked",
			HTTPStatusCode:  403,
			WAFStatusHeader: "",
			Timestamp:       time.Now(),
			Payload:         "payload2",
		},
		{
			TemplateID:      "CVE-2016-0003",
			TemplateName:    "Test 3",
			Severity:        "high",
			TargetURL:       "http://test.local/3",
			Status:          "Bypassed",
			HTTPStatusCode:  200,
			WAFStatusHeader: "Passed",
			Timestamp:       time.Now(),
			Payload:         "payload3",
		},
	}

	if err := writer.WriteMultiple(results); err != nil {
		t.Fatalf("WriteMultiple failed: %v", err)
	}

	// Check counts
	if writer.GetResultCount() != 3 {
		t.Errorf("Expected result count 3, got %d", writer.GetResultCount())
	}

	if writer.GetBypassedCount() != 2 {
		t.Errorf("Expected bypassed count 2, got %d", writer.GetBypassedCount())
	}

	writer.Close()
}

func TestCSVWriter_Headers(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")
	bypassPath := filepath.Join(tempDir, "bypassed.csv")

	writer, err := NewCSVWriter(compPath, bypassPath)
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}
	writer.Close()

	// Read comprehensive file
	compData, err := os.ReadFile(compPath)
	if err != nil {
		t.Fatalf("Failed to read comprehensive file: %v", err)
	}

	compContent := string(compData)
	expectedHeaders := []string{
		"Template ID",
		"Template Name",
		"Severity",
		"Target URL",
		"Status",
		"HTTP Status Code",
		"X-WAF-Status Header",
		"Timestamp",
		"Payload",
	}

	for _, header := range expectedHeaders {
		if !strings.Contains(compContent, header) {
			t.Errorf("Comprehensive file missing header: %s", header)
		}
	}

	// Read bypassed file
	bypassData, err := os.ReadFile(bypassPath)
	if err != nil {
		t.Fatalf("Failed to read bypassed file: %v", err)
	}

	bypassContent := string(bypassData)
	for _, header := range expectedHeaders {
		if !strings.Contains(bypassContent, header) {
			t.Errorf("Bypassed file missing header: %s", header)
		}
	}
}

func TestCSVWriter_NilResult(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "results.csv")

	writer, err := NewCSVWriter(compPath, "")
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}
	defer writer.Close()

	// Try to write nil result
	err = writer.Write(nil)
	if err == nil {
		t.Error("Expected error when writing nil result")
	}
}

func TestCSVWriter_CreateNestedDirectories(t *testing.T) {
	tempDir := t.TempDir()
	compPath := filepath.Join(tempDir, "nested", "dir", "results.csv")

	writer, err := NewCSVWriter(compPath, "")
	if err != nil {
		t.Fatalf("NewCSVWriter failed: %v", err)
	}
	defer writer.Close()

	// Verify file was created in nested directory
	if _, err := os.Stat(compPath); os.IsNotExist(err) {
		t.Error("CSV file was not created in nested directory")
	}
}
