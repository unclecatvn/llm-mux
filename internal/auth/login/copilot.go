package login

import (
	"context"
	"fmt"
	"time"

	"github.com/nghyane/llm-mux/internal/auth/copilot"
	"github.com/nghyane/llm-mux/internal/browser"
	"github.com/nghyane/llm-mux/internal/config"
	"github.com/nghyane/llm-mux/internal/provider"
)

// CopilotAuthenticator implements OAuth device flow login for GitHub Copilot.
type CopilotAuthenticator struct{}

// NewCopilotAuthenticator constructs a new authenticator instance.
func NewCopilotAuthenticator() Authenticator { return &CopilotAuthenticator{} }

// Provider returns the provider key for GitHub Copilot.
func (CopilotAuthenticator) Provider() string { return "github-copilot" }

// RefreshLead instructs the manager to refresh five minutes before expiry.
func (CopilotAuthenticator) RefreshLead() *time.Duration {
	lead := 5 * time.Minute
	return &lead
}

// Login launches the GitHub device flow to obtain a Copilot access token.
func (CopilotAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*provider.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	copilotAuth := copilot.NewCopilotAuth(cfg)

	// Start device flow
	deviceCode, err := copilotAuth.StartDeviceFlow(ctx)
	if err != nil {
		return nil, fmt.Errorf("github-copilot: failed to start device flow: %w", err)
	}

	// Display device code and verification URL
	fmt.Println()
	fmt.Printf("To sign in, use a web browser to open the page %s\n", deviceCode.VerificationURI)
	fmt.Printf("and enter the code: %s\n", deviceCode.UserCode)
	fmt.Println()

	// Try to open browser automatically
	if !opts.NoBrowser {
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(deviceCode.VerificationURI); errOpen != nil {
				fmt.Println("Failed to open browser automatically. Please open the URL manually.")
			}
		}
	}

	fmt.Println("Waiting for authentication...")

	// Poll for authorization (returns CopilotCredentials directly)
	creds, err := copilotAuth.WaitForAuthorization(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("github-copilot: authentication failed: %w", err)
	}

	// Verify we can get a Copilot API token
	_, err = copilotAuth.GetCopilotAPIToken(ctx, creds.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("github-copilot: failed to verify copilot access: %w", err)
	}

	// Build metadata
	metadata := map[string]any{
		"type":         "github-copilot",
		"access_token": creds.AccessToken,
		"token_type":   creds.TokenType,
		"scope":        creds.Scope,
		"username":     creds.Username,
		"timestamp":    time.Now().UnixMilli(),
	}

	fileName := fmt.Sprintf("github-copilot-%s.json", creds.Username)
	label := creds.Username
	if label == "" {
		label = "github-copilot"
	}

	fmt.Printf("\nGitHub Copilot authentication successful! Logged in as: %s\n", creds.Username)
	return &provider.Auth{
		ID:       fileName,
		Provider: "github-copilot",
		FileName: fileName,
		Label:    label,
		Metadata: metadata,
	}, nil
}
