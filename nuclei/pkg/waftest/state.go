package waftest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

// StateManager manages the state of template execution for progressive testing
type StateManager struct {
	filePath string
	state    *ExecutionState
}

// ExecutionState represents the current state of template execution
type ExecutionState struct {
	CompletedTemplates []string  `json:"completed_templates"`
	LastBatchIndex     int       `json:"last_batch_index"`
	TotalTemplates     int       `json:"total_templates"`
	LastUpdated        time.Time `json:"last_updated"`
	BypassedCount      int       `json:"bypassed_count"`
	BlockedCount       int       `json:"blocked_count"`
}

// NewStateManager creates a new state manager
func NewStateManager(filePath string) *StateManager {
	return &StateManager{
		filePath: filePath,
		state: &ExecutionState{
			CompletedTemplates: []string{},
			LastBatchIndex:     0,
			TotalTemplates:     0,
			LastUpdated:        time.Now(),
			BypassedCount:      0,
			BlockedCount:       0,
		},
	}
}

// LoadState loads the state from file, creates new if not exists
func (sm *StateManager) LoadState() error {
	// Check if file exists
	if _, err := os.Stat(sm.filePath); os.IsNotExist(err) {
		// File doesn't exist, use default state
		return nil
	}

	// Read file
	data, err := os.ReadFile(sm.filePath)
	if err != nil {
		return errors.Wrap(err, "failed to read state file")
	}

	// Parse JSON
	var state ExecutionState
	if err := json.Unmarshal(data, &state); err != nil {
		return errors.Wrap(err, "failed to parse state file")
	}

	sm.state = &state
	return nil
}

// SaveState saves the current state to file
func (sm *StateManager) SaveState() error {
	// Update timestamp
	sm.state.LastUpdated = time.Now()

	// Marshal to JSON
	data, err := json.MarshalIndent(sm.state, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal state")
	}

	// Ensure directory exists
	dir := filepath.Dir(sm.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrap(err, "failed to create state directory")
	}

	// Write to file
	if err := os.WriteFile(sm.filePath, data, 0644); err != nil {
		return errors.Wrap(err, "failed to write state file")
	}

	return nil
}

// GetNextBatch returns the next batch of templates to execute
// Returns empty slice if all templates are completed
func (sm *StateManager) GetNextBatch(allTemplates []string, batchSize int) []string {
	sm.state.TotalTemplates = len(allTemplates)

	// Create a map of completed templates for quick lookup
	completed := make(map[string]bool)
	for _, tmpl := range sm.state.CompletedTemplates {
		completed[tmpl] = true
	}

	// Find uncompleted templates
	var uncompleted []string
	for _, tmpl := range allTemplates {
		if !completed[tmpl] {
			uncompleted = append(uncompleted, tmpl)
		}
	}

	// Return next batch
	if len(uncompleted) == 0 {
		return []string{}
	}

	if len(uncompleted) < batchSize {
		return uncompleted
	}

	return uncompleted[:batchSize]
}

// MarkCompleted marks templates as completed
func (sm *StateManager) MarkCompleted(templates []string) {
	// Add to completed list
	sm.state.CompletedTemplates = append(sm.state.CompletedTemplates, templates...)
	sm.state.LastBatchIndex = len(sm.state.CompletedTemplates)
}

// RecordResult records the result of a template execution
func (sm *StateManager) RecordResult(bypassed bool) {
	if bypassed {
		sm.state.BypassedCount++
	} else {
		sm.state.BlockedCount++
	}
}

// GetProgress returns the current progress statistics
func (sm *StateManager) GetProgress() (completed, total, bypassed, blocked int) {
	return len(sm.state.CompletedTemplates),
		sm.state.TotalTemplates,
		sm.state.BypassedCount,
		sm.state.BlockedCount
}

// GetBypassRate returns the bypass rate as a percentage
func (sm *StateManager) GetBypassRate() float64 {
	total := sm.state.BypassedCount + sm.state.BlockedCount
	if total == 0 {
		return 0.0
	}
	return float64(sm.state.BypassedCount) / float64(total) * 100.0
}

// GetSummary returns a formatted summary string
func (sm *StateManager) GetSummary() string {
	completed, total, bypassed, blocked := sm.GetProgress()
	rate := sm.GetBypassRate()
	
	return fmt.Sprintf(
		"Progress: %d/%d templates | Bypassed: %d | Blocked: %d | Bypass Rate: %.1f%%",
		completed, total, bypassed, blocked, rate,
	)
}

// IsComplete returns true if all templates have been executed
func (sm *StateManager) IsComplete(totalTemplates int) bool {
	return len(sm.state.CompletedTemplates) >= totalTemplates
}

// Reset resets the state to initial values
func (sm *StateManager) Reset() {
	sm.state = &ExecutionState{
		CompletedTemplates: []string{},
		LastBatchIndex:     0,
		TotalTemplates:     0,
		LastUpdated:        time.Now(),
		BypassedCount:      0,
		BlockedCount:       0,
	}
}
