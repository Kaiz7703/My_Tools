// extractStatusCode extracts HTTP status code from result metadata
// NOTE: ResultEvent.Metadata does NOT contain status_code from InternalEvent!
// It only contains OperatorsResult.PayloadValues (extractor variables).
// We must parse from result.Response string instead.
func (ne *NucleiExecutor) extractStatusCode(result *output.ResultEvent) int {
	// Method 1: Parse from Response string (MOST RELIABLE - do this first!)
	if result.Response != "" {
		// Response format: "HTTP/1.1 200 OK\r\n..."
		lines := strings.Split(result.Response, "\n")
		if len(lines) > 0 {
			firstLine := strings.TrimSpace(lines[0])
			// Remove carriage return if present
			firstLine = strings.TrimRight(firstLine, "\r")
			
			if strings.HasPrefix(firstLine, "HTTP/") {
				parts := strings.Fields(firstLine)
				if len(parts) >= 2 {
					var code int
					if _, err := fmt.Sscanf(parts[1], "%d", &code); err == nil && code > 0 {
						gologger.Debug().Msgf("[%s] Extracted status code from response: %d", result.TemplateID, code)
						return code
					}
				}
			}
		}
	}
	
	// Method 2: Try Metadata (unlikely to work, but check anyway as fallback)
	if result.Metadata != nil {
		for _, key := range []string{"status_code", "status-code", "statuscode"} {
			if val, ok := result.Metadata[key]; ok {
				switch v := val.(type) {
				case int: 
					gologger.Debug().Msgf("[%s] Found status_code in metadata: %d", result.TemplateID, v)
					return v
				case float64: 
					return int(v)
				case string:
					var i int
					fmt.Sscanf(v, "%d", &i)
					return i
				}
			}
		}
	}
	
	gologger.Debug().Msgf("[%s] Could not extract status code (Response: %d bytes)", result.TemplateID, len(result.Response))
	return 0
}
