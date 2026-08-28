package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.github.com/"
	userAgent      = "go-github"
)

// Client manages communication with the GitHub API.
type Client struct {
	client    *http.Client
	BaseURL   *url.URL
	UserAgent string

	Apps *AppsService
}

// Response is a GitHub API response. This wraps the standard http.Response
// and provides convenient access to metadata.
type Response struct {
	*http.Response
}

// Timestamp represents a time that can be unmarshaled from a JSON string
// formatted according to RFC3339.
type Timestamp struct {
	time.Time
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	if str == "null" || str == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// TokenTransport is an http.RoundTripper that authenticates HTTP requests
// using a GitHub token (e.g. Personal Access Token or Installation Token).
type TokenTransport struct {
	Token     string
	Transport http.RoundTripper
}

// RoundTrip executes a single HTTP transaction, adding the Authorization header.
func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	if t.Token != "" {
		if strings.HasPrefix(t.Token, "ghs_") || strings.HasPrefix(t.Token, "ghu_") || strings.HasPrefix(t.Token, "ghp_") || strings.HasPrefix(t.Token, "gho_") || strings.HasPrefix(t.Token, "ghr_") || strings.HasPrefix(t.Token, "github_pat_") {
			req2.Header.Set("Authorization", "Bearer "+t.Token)
		} else {
			req2.Header.Set("Authorization", "token "+t.Token)
		}
	}
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req2)
}

// Client returns an *http.Client configured with TokenTransport.
func (t *TokenTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

// NewClient returns a new GitHub API client.
func NewClient(httpClient *http.Client)
*Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	baseURL, _ := url.Parse(defaultBaseURL)

	c := &Client{
		client:    httpClient,
		BaseURL:   baseURL,
		UserAgent: userAgent,
	}
	c.Apps = &AppsService{client: c}
	return c
}

// NewTokenClient returns a new GitHub API client authenticated with the provided token.
func NewTokenClient(ctx context.Context, token string) *Client {
	t := &TokenTransport{Token: token}
	return NewClient(t.Client())
}

// NewRequest creates an API request.
func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	return req, nil
}

// Do sends an API request and returns the API response.
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*Response, error) {
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	response := &Response{Response: resp}

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return response, fmt.Errorf("github API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, err = io.Copy(w, resp.Body)
		} else {
			decErr := json.NewDecoder(resp.Body).Decode(v)
			if decErr == io.EOF {
				decErr = nil
			}
		err = decErr
		}
	}
	return response, err
}
