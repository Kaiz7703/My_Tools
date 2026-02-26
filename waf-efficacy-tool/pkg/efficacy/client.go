package efficacy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPClient struct {
	client  *http.Client
	baseURL string
	verbose bool
	debug   bool
}

func NewHTTPClient(baseURL string, timeout int, verbose bool, debug bool) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		verbose: verbose,
		debug:   debug,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (hc *HTTPClient) SendRequest(ctx context.Context, payload Payload) (int, bool, error) {
	url := hc.baseURL + payload.URL

	var body io.Reader
	if payload.Data != "" {
		body = strings.NewReader(payload.Data)
	}

	req, err := http.NewRequestWithContext(ctx, payload.Method, url, body)
	if err != nil {
		if hc.verbose {
			fmt.Printf("[ERROR] Failed to create request: %v\n", err)
		}
		return 0, false, err
	}

	// Set headers
	for k, v := range payload.Headers {
		req.Header.Set(k, v)
	}

	// Debug: Print full request
	if hc.debug {
		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Printf("📤 REQUEST\n")
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("%s %s\n", payload.Method, url)
		fmt.Println("\nHeaders:")
		for k, v := range payload.Headers {
			fmt.Printf("  %s: %s\n", k, v)
		}
		if payload.Data != "" {
			fmt.Printf("\nBody:\n%s\n", payload.Data)
		}
		fmt.Println(strings.Repeat("-", 70))
	} else if hc.verbose {
		fmt.Printf("[DEBUG] %s %s\n", payload.Method, url)
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		if hc.verbose || hc.debug {
			fmt.Printf("[ERROR] Request failed: %v\n", err)
		}
		return 0, false, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if hc.verbose {
			fmt.Printf("[ERROR] Failed to read response body: %v\n", err)
		}
	}

	// Detection logic: 200 = allowed, 400/403 = blocked
	isBlocked := resp.StatusCode == 400 || resp.StatusCode == 403

	// Debug: Print full response
	if hc.debug {
		fmt.Printf("📥 RESPONSE\n")
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("Status: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		fmt.Println("\nHeaders:")
		for k, v := range resp.Header {
			fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
		}
		fmt.Printf("\nBody (%d bytes):\n", len(respBody))
		if len(respBody) > 0 {
			// Limit body output to 500 chars
			bodyStr := string(respBody)
			if len(bodyStr) > 500 {
				fmt.Printf("%s\n... (truncated)\n", bodyStr[:500])
			} else {
				fmt.Printf("%s\n", bodyStr)
			}
		}
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("Result: isBlocked=%t\n", isBlocked)
		fmt.Println(strings.Repeat("=", 70))
	} else if hc.verbose {
		fmt.Printf("[DEBUG] Response: %d (blocked=%t)\n", resp.StatusCode, isBlocked)
	}

	return resp.StatusCode, isBlocked, nil
}
