package waftest

// GetTemplateStats returns template-level statistics
func (sm *StateManager) GetTemplateStats() (bypassedTemplates, blockedTemplates, totalTemplates int) {
	return len(sm.state.BypassedTemplates),
		len(sm.state.BlockedTemplates),
		len(sm.state.CompletedTemplates)
}

// GetTemplateBypassRate returns the template bypass rate as a percentage
func (sm *StateManager) GetTemplateBypassRate() float64 {
	total := len(sm.state.BypassedTemplates) + len(sm.state.BlockedTemplates)
	if total == 0 {
		return 0.0
	}
	return float64(len(sm.state.BypassedTemplates)) / float64(total) * 100.0
}

// GetTemplateRequestStats returns detailed request statistics for a specific template
func (sm *StateManager) GetTemplateRequestStats(templateID string) *TemplateStats {
	return sm.state.TemplateRequests[templateID]
}

// IsTemplateBypassed returns true if the template was classified as fully bypassed
func (sm *StateManager) IsTemplateBypassed(templateID string) bool {
	return sm.state.BypassedTemplates[templateID]
}
