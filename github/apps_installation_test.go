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

func TestValidateInstallationToken(t *testing.T) {
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
			name:    "legacy stateful token (40 chars after prefix)",
			token:   "ghs_" + strings.Repeat("a1B2c3D4e5", 4),
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
			name:    "token with characters outside base64url (opaque value)",
			token:   "ghs_opaque+token/with=padding~and*other,chars",
			wantErr: false,
		},
		{
			name:    "token with future unknown prefix (opaque value)",
			token:   "ghx_someFutureTokenFormatThatDoesNotExistYet1234567890",
			wantErr: false,
		},
		{
			name:    "token with no prefix at all (opaque value)",
			token:   "0123456789abcdef0123456789abcdef01234567",
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
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

// TestCreateInstallationToken_AcceptsArbitraryTokens verifies that tokens
// returned by the API are surfaced verbatim regardless of length, character
// set, or prefix, so future token schema evolutions are not rejected.
func TestCreateInstallationToken_AcceptsArbitraryTokens(t *testing.T) {
	tokens := map[string]string{
		"legacy 40-char ghs_":            "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
		"stateless >255 base64url":       "ghs_" + strings.Repeat("AbcDeF-123_456.", 20),
		"stateless JWT-structured":       "ghs_eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("eyJzdWIiOiIxMjM0NTY3ODkwIn0.", 8) + strings.Repeat("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 4),
		"stateless with +/= chars":       "ghs_" + strings.Repeat("ab+cd/ef=", 35),
		"fine-grained PAT":               "github_pat_11ABCDEFG0" + strings.Repeat("h1JKLmn2OPQrs3TUVwx4YZab5cde", 3),
		"legacy PAT":                     "ghp_" + strings.Repeat("0123456789abcdef", 3),
		"oauth token":                    "gho_" + strings.Repeat("ABCDEF0123456789", 3),
		"user-to-server token":           "ghu_" + strings.Repeat("f0e1d2c3b4a59687", 3),
		"refresh token":                  "ghr_" + strings.Repeat("z9y8x7w6v5u4t3s2", 3),
		"unknown future prefix":          "ghx_" + strings.Repeat("FutureSchema123-_.", 15),
		"no known prefix":                strings.Repeat("0123456789abcdef", 20),
		"very long >512 chars":           "ghs_" + strings.Repeat("Ab3-_.xY9", 60),
	}

	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"token": %q, "expires_at": "2030-01-01T00:00:00Z"}`, tok)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := NewClient(nil)
			client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

			token, _, err := client.Apps.CreateInstallationToken(context.Background(), 42, &InstallationTokenOptions{})
			if err != nil {
				t.Fatalf("CreateInstallationToken rejected API-returned token: %v", err)
			}
			if token.Token == nil || *token.Token != tok {
				t.Errorf("token not surfaced verbatim: got %v, want %q", token.Token, tok)
			}
		})
	}
}

// TestCreateInstallationToken_EmptyTokenRejected verifies that an empty token
// from the API is still treated as an error.
func TestCreateInstallationToken_EmptyTokenRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/7/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token": "", "expires_at": "2030-01-01T00:00:00Z"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(nil)
	client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

	// An empty token string is a pointer to "", which must still be rejected.
	_, _, err := client.Apps.CreateInstallationToken(context.Background(), 7, &InstallationTokenOptions{})
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-token error, got: %v", err)
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

// TestTokenTransport_AuthorizationHeaderRoundTrip verifies the Authorization
// header carries the token verbatim (Bearer scheme, no truncation or
// manipulation) for every supported token type through a live HTTP server.
func TestTokenTransport_AuthorizationHeaderRoundTrip(t *testing.T) {
	tokens := map[string]string{
		"legacy 40-char ghs_":       "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
		"stateless >255 base64url":  "ghs_" + strings.Repeat("AbcDeF-123_456.", 20),
		"stateless with +/= chars":  "ghs_" + strings.Repeat("ab+cd/ef=", 35),
		"fine-grained PAT":          "github_pat_11ABCDEFG0" + strings.Repeat("h1JKLmn2OPQrs3TUVwx4YZab5cde", 3),
		"legacy PAT":                "ghp_" + strings.Repeat("0123456789abcdef", 3),
		"oauth token":               "gho_" + strings.Repeat("ABCDEF0123456789", 3),
		"user-to-server token":      "ghu_" + strings.Repeat("f0e1d2c3b4a59687", 3),
		"refresh token":             "ghr_" + strings.Repeat("z9y8x7w6v5u4t3s2", 3),
		"unknown format":            strings.Repeat("0123456789abcdef", 20),
	}

	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got := r.Header.Get("Authorization")
				want := "Bearer " + tok
				if got != want {
					t.Errorf("Authorization header mismatch:\n got: %q\nwant: %q", got, want)
				}
				if len(got) != len(want) {
					t.Errorf("Authorization header length mismatch: got %d, want %d (possible truncation)", len(got), len(want))
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			transport := &TokenTransport{Token: tok}
			req, err := http.NewRequest("GET", server.URL, nil)
			if err != nil {
				t.Fatalf("http.NewRequest failed: %v", err)
			}
			resp, err := transport.Client().Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected status: %d", resp.StatusCode)
			}
		})
	}
}

// TestTokenTransport_DoesNotMutateOriginalRequest verifies RoundTrip leaves
// the caller's request untouched.
func TestTokenTransport_DoesNotMutateOriginalRequest(t *testing.T) {
	tok := "ghs_" + strings.Repeat("AbcDeF-123_456.", 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest failed: %v", err)
	}

	transport := &TokenTransport{Token: tok}
	resp, err := transport.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("original request was mutated: Authorization = %q", got)
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

// TestInstallationToken_JSONRoundTrip verifies arbitrarily long and unusual
// tokens survive a full JSON marshal/unmarshal round-trip byte-for-byte.
func TestInstallationToken_JSONRoundTrip(t *testing.T) {
	tokens := map[string]string{
		"legacy 40-char":           "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
		"stateless >255 base64url": "ghs_" + strings.Repeat("AbcDeF-123_456.", 20),
		"stateless with +/= chars": "ghs_" + strings.Repeat("ab+cd/ef=", 35),
		"JWT-structured":           "ghs_eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("eyJzdWIiOiIxMjM0NTY3ODkwIn0.", 8) + "sig",
		"very long >1024 chars":    "ghs_" + strings.Repeat("x9Y8-_.Ab3", 110),
	}

	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			original := InstallationToken{Token: &tok}
			data, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			var decoded InstallationToken
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			if decoded.Token == nil || *decoded.Token != tok {
				t.Errorf("round-trip mismatch: got %v, want %q", decoded.Token, tok)
			}
			if len(*decoded.Token) != len(tok) {
				t.Errorf("length changed in round-trip: got %d, want %d", len(*decoded.Token), len(tok))
			}
		})
	}
}
