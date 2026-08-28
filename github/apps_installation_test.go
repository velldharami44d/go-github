package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateInstallationToken(t *testing.T)

tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "legacy stateful token (36 chars after prefix)",
			token:   "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
			wantErr: false,
		},
		{
			name:    "stateless token (>250 chars with base64url characters)",
			token:   "ghs_" + strings.Repeat("AbcDeF-123_456.", 25),
			wantErr: false,
		},
		{
			name:    "stateless token with realistic payload",
			token:   "ghs_eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsYXRpb25faWQiOjEyMzQ1NiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_long_signature_part_here_exceeding_standard_length_bounds_for_legacy_tokens",
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid prefix",
			token:   "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			token:   "ghs_invalid!@#$%^&*()",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInstallationToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInstallationToken(%q) error = %v, wantErr %v", tt.token, err, tt.wantErr)
			}
		})
	}
}

func TestCreateInstallationToken_StatelessToken(t *testing.T) {
	statelessToken := "ghs_" + strings.Repeat("eyJhbGciOiJSUzI1NiJ9.", 15) + "signature_blob_123-456_789"
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/12345/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"token": %q,
			"expires_at": %q,
			"permissions": {"issues": "write", "contents": "read"},
			"repository_selection": "all"
		}`, statelessToken, expiresAt.Format(time.RFC3339))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(nil)
	client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

	token, resp, err := client.Apps.CreateInstallationToken(context.Background(), 12345, &InstallationTokenOptions{})
	if err != nil {
		t.Fatalf("CreateInstallationToken returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	if token.Token == nil || *token.Token != statelessToken {
		t.Errorf("Expected token %q, got %v", statelessToken, token.Token)
	}

	if token.ExpiresAt == nil || !token.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Expected expires_at %v, got %v", expiresAt, token.ExpiresAt)
	}

	if token.Permissions == nil || *token.Permissions.Issues != "write" {
		t.Errorf("Expected permissions.issues = 'write', got %v", token.Permissions)
	}
}

func TestTokenTransport_StatelessTokenAuthorizationHeader(t *testing.T) {
	statelessToken := "ghs_" + strings.Repeat("veryLongStatelessTokenPayloadPart_", 10)

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + statelessToken
		if authHeader != expectedAuth {
			http.Error(w, fmt.Sprintf("expected auth %s, got %s", expectedAuth, authHeader), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login": "octocat"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewTokenClient(context.Background(), statelessToken)
	client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

	req, err := client.NewRequest("GET", "user", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	var user map[string]interface{}
	resp, err := client.Do(context.Background(), req, &user)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if user["login"] != "octocat" {
		t.Errorf("Expected login 'octocat', got %v", user["login"])
	}
}

func TestTokenTransport_DifferentTokenTypes(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectedAuth string
	}{
		{
			name:         "ghs_ token",
			token:        "ghs_abc123",
			expectedAuth: "Bearer ghs_abc123",
		},
		{
			name:         "github_pat_ token",
			token:        "github_pat_11AAAAAA_longFineGrainedPATstring12345",
			expectedAuth: "Bearer github_pat_11AAAAAA_longFineGrainedPATstring12345",
		},
		{
			name:         "ghp_ token",
			token:        "ghp_1234567890abcdef",
			expectedAuth: "Bearer ghp_1234567890abcdef",
		},
		{
			name:         "legacy personal token without prefix",
			token:        "40charactertokenhexstring0123456789abcdef",
			expectedAuth: "token 40charactertokenhexstring0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != tt.expectedAuth {
					http.Error(w, fmt.Sprintf("expected %q, got %q", tt.expectedAuth, auth), http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			client := NewTokenClient(context.Background(), tt.token)
			client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

			req, err := client.NewRequest("GET", "test", nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}
			resp, err := client.Do(context.Background(), req, nil)
			if err != nil {
				t.Fatalf("Do failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}
		})
	}
}

func TestInstallationToken_JSONUnmarshal(t *testing.T) {
	longToken := "ghs_" + strings.Repeat("A1b2C3d4-", 40)
	rawJSON := fmt.Sprintf(`{
		"token": %q,
		"expires_at": "2030-01-01T00:00:00Z",
		"repositories": [{"id": 1, "name": "test-repo"}]
	}`, longToken)

	var it InstallationToken
	if err := json.Unmarshal([]byte(rawJSON), &it); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if it.Token == nil || *it.Token != longToken {
		t.Errorf("Token mismatch: got %v, want %q", it.Token, longToken)
	}
	if len(it.Repositories) != 1 || *it.Repositories[0].Name != "test-repo" {
		t.Errorf("Repositories mismatch: got %v", it.Repositories)
	}
}
