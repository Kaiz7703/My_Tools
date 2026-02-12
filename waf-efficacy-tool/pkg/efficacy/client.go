package efficacy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPClient struct {
	client  *http.Client
	baseURL string
}

func NewHTTPClient(baseURL string, timeout int) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
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
		return 0, false, err
	}

	// Set headers
	for k, v := range payload.Headers {
		req.Header.Set(k, v)
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	// Detection logic: 200 = allowed, 400/403 = blocked
	isBlocked := resp.StatusCode == 400 || resp.StatusCode == 403

	return resp.StatusCode, isBlocked, nil
}
