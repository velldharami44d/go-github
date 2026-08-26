package github

import (
	"context"
	"fmt"
	"regexp"
)

// AppsService provides access to installation and App-related functions in the GitHub API.
type AppsService struct {
	client *Client
}

// InstallationPermissions specifies the permissions granted to the installation token.
type InstallationPermissions struct {
	Issues        *string `json:"issues,omitempty"`
	Contents      *string `json:"contents,omitempty"`
	PullRequests  *string `json:"pull_requests,omitempty"`
	Metadata      *string `json:"metadata,omitempty"`
	Administration *string `json:"administration,omitempty"`
}

// Repository represents a GitHub repository referenced in an installation token.
type Repository struct {
	ID       *int64  `json:"id,omitempty"`
	NodeID   *string `json:"node_id,omitempty"`
	Name     *string `json:"name,omitempty"`
	FullName *string `json:"full_name,omitempty"`
	Private  *bool   `json:"private,omitempty"`
}

// InstallationToken represents an authentication token for a GitHub App installation.
type InstallationToken struct {
	Token                  *string                  `json:"token,omitempty"`
	ExpiresAt              *Timestamp               `json:"expires_at,omitempty"`
	Permissions            *InstallationPermissions `json:"permissions,omitempty"`
	Repositories           []*Repository            `json:"repositories,omitempty"`
	SingleFile             *string                  `json:"single_file,omitempty"`
	HasMultipleSingleFiles *bool                    `json:"has_multiple_single_files,omitempty"`
	SingleFiles            []string                 `json:"single_files,omitempty"`
	RepositorySelection    *string                  `json:"repository_selection,omitempty"`
}

// InstallationTokenOptions specifies the parameters for creating an installation token.
type InstallationTokenOptions struct {
	Repositories  []string                 `json:"repositories,omitempty"`
	RepositoryIDs []int64                  `json:"repository_ids,omitempty"`
	Permissions   *InstallationPermissions `json:"permissions,omitempty"`
}

// installationTokenRegex matches both legacy fixed-length and new variable-length stateless tokens.
// Stateless tokens start with `ghs_` and contain URL-safe base64 characters (including `-`, `_`, and `.`).
var installationTokenRegex = regexp.MustCompile(`^ghs_[A-Za-z0-9_.-]+$`)

// ValidateInstallationToken checks if the given token string conforms to valid GitHub App installation token format.
// It supports both legacy stateful tokens (e.g. ghs_36chars) and modern variable-length stateless tokens.
func ValidateInstallationToken(token string) error {
	if token == "" {
		return fmt.Errorf("installation token cannot be empty")
	}
	if !installationTokenRegex.MatchString(token) {
		return fmt.Errorf("invalid installation token format: token must start with 'ghs_' and contain only URL-safe characters")
	}
	return nil
}

// CreateInstallationToken creates an installation token for the specified installation.
func (s *AppsService) CreateInstallationToken(ctx context.Context, installationID int64, opts *InstallationTokenOptions) (*InstallationToken, *Response, error) {
	u := fmt.Sprintf("app/installations/%v/access_tokens", installationID)
	req, err := s.client.NewRequest("POST", u, opts)
	if err != nil {
		return nil, nil, err
	}

	token := new(InstallationToken)
	resp, err := s.client.Do(ctx, req, token)
	if err != nil {
		return nil, resp, err
	}

	if token.Token != nil {
		if err := ValidateInstallationToken(*token.Token); err != nil {
			return nil, resp, fmt.Errorf("received invalid installation token: %w", err)
		}
	}

	return token, resp, nil
}
