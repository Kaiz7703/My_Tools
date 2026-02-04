package waftest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStateManager(t *testing.T) {
	sm := NewStateManager("test_state.json")
	
	if sm.filePath != "test_state.json" {
		t.Errorf("Expected filePath 'test_state.json', got '%s'", sm.filePath)
	}
	
	if len(sm.state.CompletedTemplates) != 0 {
		t.Error("Expected empty CompletedTemplates for new state")
	}
}

func TestLoadState_NewFile(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "state.json")
	sm := NewStateManager(tempFile)
	
	// Load non-existent file should not error
	if err := sm.LoadState(); err != nil {
		t.Errorf("LoadState should not error on non-existent file: %v", err)
	}
	
	// Should have default state
	if len(sm.state.CompletedTemplates) != 0 {
		t.Error("Expected empty state for new file")
	}
}

func TestSaveAndLoadState(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "state.json")
	sm := NewStateManager(tempFile)
	
	// Add some data
	sm.state.CompletedTemplates = []string{"template1", "template2"}
	sm.state.TotalTemplates = 10
	sm.state.BypassedCount = 5
	sm.state.BlockedCount = 3
	
	// Save state
	if err := sm.SaveState(); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}
	
	// Create new manager and load
	sm2 := NewStateManager(tempFile)
	if err := sm2.LoadState(); err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	
	// Verify data
	if len(sm2.state.CompletedTemplates) != 2 {
		t.Errorf("Expected 2 completed templates, got %d", len(sm2.state.CompletedTemplates))
	}
	
	if sm2.state.TotalTemplates != 10 {
		t.Errorf("Expected TotalTemplates 10, got %d", sm2.state.TotalTemplates)
	}
	
	if sm2.state.BypassedCount != 5 {
		t.Errorf("Expected BypassedCount 5, got %d", sm2.state.BypassedCount)
	}
	
	if sm2.state.BlockedCount != 3 {
		t.Errorf("Expected BlockedCount 3, got %d", sm2.state.BlockedCount)
	}
}

func TestGetNextBatch(t *testing.T) {
	sm := NewStateManager("test.json")
	
	allTemplates := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"}
	
	// First batch
	batch1 := sm.GetNextBatch(allTemplates, 3)
	if len(batch1) != 3 {
		t.Errorf("Expected batch size 3, got %d", len(batch1))
	}
	
	// Mark first batch as completed
	sm.MarkCompleted(batch1)
	
	// Second batch
	batch2 := sm.GetNextBatch(allTemplates, 3)
	if len(batch2) != 3 {
		t.Errorf("Expected batch size 3, got %d", len(batch2))
	}
	
	// Verify no overlap
	for _, t1 := range batch1 {
		for _, t2 := range batch2 {
			if t1 == t2 {
				t.Errorf("Found duplicate template %s in batches", t1)
			}
		}
	}
	
	// Mark all as completed
	sm.MarkCompleted(allTemplates)
	
	// Should return empty batch
	batch3 := sm.GetNextBatch(allTemplates, 3)
	if len(batch3) != 0 {
		t.Errorf("Expected empty batch when all completed, got %d", len(batch3))
	}
}

func TestGetNextBatch_SmallRemaining(t *testing.T) {
	sm := NewStateManager("test.json")
	
	allTemplates := []string{"t1", "t2", "t3"}
	
	// Request batch of 10, but only 3 available
	batch := sm.GetNextBatch(allTemplates, 10)
	if len(batch) != 3 {
		t.Errorf("Expected batch size 3 (all remaining), got %d", len(batch))
	}
}

func TestMarkCompleted(t *testing.T) {
	sm := NewStateManager("test.json")
	
	templates := []string{"t1", "t2", "t3"}
	sm.MarkCompleted(templates)
	
	if len(sm.state.CompletedTemplates) != 3 {
		t.Errorf("Expected 3 completed templates, got %d", len(sm.state.CompletedTemplates))
	}
	
	if sm.state.LastBatchIndex != 3 {
		t.Errorf("Expected LastBatchIndex 3, got %d", sm.state.LastBatchIndex)
	}
}

func TestRecordResult(t *testing.T) {
	sm := NewStateManager("test.json")
	
	// Record some bypasses
	sm.RecordResult(true)
	sm.RecordResult(true)
	sm.RecordResult(true)
	
	// Record some blocks
	sm.RecordResult(false)
	sm.RecordResult(false)
	
	if sm.state.BypassedCount != 3 {
		t.Errorf("Expected BypassedCount 3, got %d", sm.state.BypassedCount)
	}
	
	if sm.state.BlockedCount != 2 {
		t.Errorf("Expected BlockedCount 2, got %d", sm.state.BlockedCount)
	}
}

func TestGetProgress(t *testing.T) {
	sm := NewStateManager("test.json")
	
	sm.state.CompletedTemplates = []string{"t1", "t2", "t3"}
	sm.state.TotalTemplates = 10
	sm.state.BypassedCount = 7
	sm.state.BlockedCount = 3
	
	completed, total, bypassed, blocked := sm.GetProgress()
	
	if completed != 3 {
		t.Errorf("Expected completed 3, got %d", completed)
	}
	
	if total != 10 {
		t.Errorf("Expected total 10, got %d", total)
	}
	
	if bypassed != 7 {
		t.Errorf("Expected bypassed 7, got %d", bypassed)
	}
	
	if blocked != 3 {
		t.Errorf("Expected blocked 3, got %d", blocked)
	}
}

func TestGetBypassRate(t *testing.T) {
	sm := NewStateManager("test.json")
	
	// Test with no results
	rate := sm.GetBypassRate()
	if rate != 0.0 {
		t.Errorf("Expected bypass rate 0.0 for no results, got %.2f", rate)
	}
	
	// Test with 75% bypass rate
	sm.state.BypassedCount = 15
	sm.state.BlockedCount = 5
	
	rate = sm.GetBypassRate()
	if rate != 75.0 {
		t.Errorf("Expected bypass rate 75.0, got %.2f", rate)
	}
}

func TestIsComplete(t *testing.T) {
	sm := NewStateManager("test.json")
	
	sm.state.CompletedTemplates = []string{"t1", "t2", "t3"}
	
	if sm.IsComplete(5) {
		t.Error("Expected IsComplete to return false when 3/5 completed")
	}
	
	if !sm.IsComplete(3) {
		t.Error("Expected IsComplete to return true when 3/3 completed")
	}
	
	if !sm.IsComplete(2) {
		t.Error("Expected IsComplete to return true when completed exceeds total")
	}
}

func TestReset(t *testing.T) {
	sm := NewStateManager("test.json")
	
	// Add some data
	sm.state.CompletedTemplates = []string{"t1", "t2"}
	sm.state.BypassedCount = 5
	sm.state.BlockedCount = 3
	
	// Reset
	sm.Reset()
	
	// Verify reset
	if len(sm.state.CompletedTemplates) != 0 {
		t.Error("Expected empty CompletedTemplates after reset")
	}
	
	if sm.state.BypassedCount != 0 {
		t.Error("Expected BypassedCount 0 after reset")
	}
	
	if sm.state.BlockedCount != 0 {
		t.Error("Expected BlockedCount 0 after reset")
	}
}

func TestSaveState_CreatesDirectory(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "subdir", "nested", "state.json")
	
	sm := NewStateManager(stateFile)
	sm.state.CompletedTemplates = []string{"t1"}
	
	// Save should create nested directories
	if err := sm.SaveState(); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}
	
	// Verify file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Error("State file was not created")
	}
}
