package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	apiKey string
	http   *http.Client
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

type SearchResponse struct {
	Total   int           `json:"total"`
	Matches []SearchMatch `json:"matches"`
	Error   string        `json:"error,omitempty"`
}

type SearchMatch struct {
	IPStr     string         `json:"ip_str"`
	Port      int            `json:"port"`
	Hostnames []string       `json:"hostnames"`
	Data      string         `json:"data"`
	Location  map[string]any `json:"location"`
	Org       string         `json:"org"`
	Product   string         `json:"product"`
}

// Search executes a Shodan host-search query with automatic exponential
// backoff on HTTP 429 rate-limit responses.  Delays: 1s, 2s, 4s, 8s, 16s
// (up to 5 attempts total).  Non-429 errors are returned immediately.
func (c *Client) Search(ctx context.Context, query string, limit int) (*SearchResponse, error) {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sr, err := c.doSearch(ctx, query, limit)
		if err == nil {
			return sr, nil
		}
		if !strings.Contains(err.Error(), "429") {
			return nil, err
		}
		// Rate-limited — back off exponentially then retry.
		delay := time.Duration(1<<uint(attempt)) * time.Second // 1, 2, 4, 8, 16 s
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("shodan: rate-limited after %d retries", maxAttempts)
}

// doSearch performs a single Shodan API request without retry logic.
func (c *Client) doSearch(ctx context.Context, query string, limit int) (*SearchResponse, error) {
	params := url.Values{}
	params.Set("key", c.apiKey)
	params.Set("query", query)
	params.Set("minify", "true")
	if limit > 0 {
		params.Set("page", "1")
	}

	endpoint := "https://api.shodan.io/shodan/host/search?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid API key")
	}
	if resp.StatusCode == 402 {
		return nil, fmt.Errorf("query requires paid Shodan plan")
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("shodan: 429 rate-limited")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan returned HTTP %s", strconv.Itoa(resp.StatusCode))
	}

	var sr SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, err
	}
	if sr.Error != "" {
		return nil, fmt.Errorf("shodan error: %s", sr.Error)
	}

	if limit > 0 && len(sr.Matches) > limit {
		sr.Matches = sr.Matches[:limit]
	}

	return &sr, nil
}
