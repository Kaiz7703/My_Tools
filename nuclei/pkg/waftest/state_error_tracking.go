package waftest

// RecordSkipped records a template that was skipped due to incompatibility
func (sm *StateManager) RecordSkipped(templateID, reason string) {
	if sm.state.SkippedTemplates == nil {
		sm.state.SkippedTemplates = make(map[string]string)
	}
	sm.state.SkippedTemplates[templateID] = reason
}

// RecordFailed records a template that failed during execution
func (sm *StateManager) RecordFailed(templateID, errorMsg string) {
	if sm.state.FailedTemplates == nil {
		sm.state.FailedTemplates = make(map[string]string)
	}
	sm.state.FailedTemplates[templateID] = errorMsg
}

// GetErrorStats returns lists of skipped and failed template IDs
func (sm *StateManager) GetErrorStats() (skipped, failed []string) {
	for id := range sm.state.SkippedTemplates {
		skipped = append(skipped, id)
	}
	for id := range sm.state.FailedTemplates {
		failed = append(failed, id)
	}
	return skipped, failed
}
