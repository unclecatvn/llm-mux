package oauth

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/nghyane/llm-mux/internal/logging"
)

// Service provides unified OAuth management for both CLI and Web UI modes.
type Service struct {
	registry        *Registry
	callbackManager *CallbackServersManager
	tokenExchangers map[string]TokenExchanger

	mu      sync.RWMutex
	started bool
}

// TokenExchanger handles provider-specific token exchange logic.
type TokenExchanger interface {
	// BuildAuthURL creates the authorization URL for the provider.
	BuildAuthURL(req *OAuthRequest) (string, error)
	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, req *OAuthRequest, code string) (*TokenResult, error)
	// GetProviderName returns the provider identifier.
	GetProviderName() string
}

// TokenResult contains the result of a successful token exchange.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	Email        string
	Metadata     map[string]any
}

// StartRequest contains parameters for starting an OAuth flow.
type StartRequest struct {
	Provider  string            // Provider name (claude, gemini, codex, etc.)
	Mode      RequestMode       // CLI or WebUI
	ProjectID string            // Optional project ID (for Gemini)
	Metadata  map[string]string // Additional metadata
}

// StartResponse contains the response from starting an OAuth flow.
type StartResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
	ID      string `json:"id"`
}

// NewService creates a new unified OAuth service.
func NewService() *Service {
	registry := NewRegistry()

	s := &Service{
		registry:        registry,
		tokenExchangers: make(map[string]TokenExchanger),
	}

	// Create callback manager with our handler
	s.callbackManager = NewCallbackServersManager(registry, s.handleCallback)

	return s
}

// RegisterExchanger registers a token exchanger for a provider.
func (s *Service) RegisterExchanger(provider string, exchanger TokenExchanger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenExchangers[provider] = exchanger
}

// Start initializes the OAuth service and starts necessary callback servers.
func (s *Service) Start(providers ...string) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()

	// Start callback servers for specified providers
	if len(providers) > 0 {
		if err := s.callbackManager.EnsureRunning(providers...); err != nil {
			return fmt.Errorf("failed to start callback servers: %w", err)
		}
	}

	log.Info("OAuth service started")
	return nil
}

// Stop gracefully shuts down the OAuth service.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	s.mu.Unlock()

	s.callbackManager.StopAll()
	log.Info("OAuth service stopped")
}

// StartFlow initiates an OAuth flow for the specified provider.
func (s *Service) StartFlow(ctx context.Context, req StartRequest) (*StartResponse, error) {
	// Ensure callback server is running for this provider
	if err := s.callbackManager.EnsureRunning(req.Provider); err != nil {
		return nil, fmt.Errorf("failed to ensure callback server: %w", err)
	}

	// Register the OAuth request
	oauthReq, err := s.registry.Register(req.Provider, req.Mode)
	if err != nil {
		return nil, fmt.Errorf("failed to register OAuth request: %w", err)
	}

	// Set redirect URI based on provider
	oauthReq.RedirectURI = GetRedirectURI(req.Provider)

	// Get the token exchanger for this provider
	s.mu.RLock()
	exchanger, hasExchanger := s.tokenExchangers[req.Provider]
	s.mu.RUnlock()

	if hasExchanger {
		// Use provider-specific URL builder
		authURL, err := exchanger.BuildAuthURL(oauthReq)
		if err != nil {
			s.registry.Remove(oauthReq.State)
			return nil, fmt.Errorf("failed to build auth URL: %w", err)
		}
		oauthReq.AuthURL = authURL
	}

	return &StartResponse{
		AuthURL: oauthReq.AuthURL,
		State:   oauthReq.State,
		ID:      oauthReq.ID,
	}, nil
}

// WaitForCallback blocks until the OAuth callback is received or timeout.
// This is used for CLI mode.
func (s *Service) WaitForCallback(ctx context.Context, state string, timeout time.Duration) (*OAuthResult, error) {
	req := s.registry.Get(state)
	if req == nil {
		return nil, fmt.Errorf("unknown OAuth state: %s", state)
	}

	timeoutChan := time.After(timeout)

	select {
	case result := <-req.ResultChan:
		if result.Error != "" {
			return nil, fmt.Errorf("OAuth error: %s", result.Error)
		}
		return result, nil
	case <-timeoutChan:
		s.registry.Fail(state, "timeout")
		return nil, fmt.Errorf("OAuth timeout after %v", timeout)
	case <-ctx.Done():
		s.registry.Cancel(state)
		return nil, ctx.Err()
	}
}

// GetStatus returns the current status of an OAuth request.
func (s *Service) GetStatus(state string) (*StatusResponse, error) {
	req := s.registry.Get(state)
	if req == nil {
		return nil, fmt.Errorf("unknown OAuth state: %s", state)
	}

	return &StatusResponse{
		State:    req.State,
		Provider: req.Provider,
		Status:   string(req.Status),
		Mode:     string(req.Mode),
	}, nil
}

// StatusResponse contains the status of an OAuth request.
type StatusResponse struct {
	State    string `json:"state"`
	Provider string `json:"provider"`
	Status   string `json:"status"`
	Mode     string `json:"mode"`
	Error    string `json:"error,omitempty"`
}

// Cancel cancels a pending OAuth request.
func (s *Service) Cancel(state string) error {
	if !s.registry.Cancel(state) {
		return fmt.Errorf("failed to cancel OAuth request: %s", state)
	}
	return nil
}

// handleCallback is called when an OAuth callback is received.
// It returns HTML to display in the browser.
func (s *Service) handleCallback(provider, code, state, errStr string) string {
	// Lookup the pending request
	req := s.registry.Get(state)
	if req == nil {
		log.Warnf("OAuth callback received with unknown state: %s", state)
		return HTMLError("Invalid or expired authentication request")
	}

	// Handle error from OAuth provider
	if errStr != "" {
		s.registry.Fail(state, errStr)
		if req.Mode == ModeWebUI {
			return HTMLErrorWithPostMessage(provider, state, errStr)
		}
		return HTMLError(errStr)
	}

	// Validate state matches
	if req.State != state {
		s.registry.Fail(state, "state mismatch")
		if req.Mode == ModeWebUI {
			return HTMLErrorWithPostMessage(provider, state, "State validation failed")
		}
		return HTMLError("State validation failed")
	}

	// Complete the request with the authorization code
	result := &OAuthResult{
		Code:  code,
		State: state,
	}
	s.registry.Complete(state, result)

	// Return appropriate HTML based on mode
	if req.Mode == ModeWebUI {
		return HTMLSuccessWithPostMessage(provider, state)
	}
	return HTMLSuccess()
}

// Registry returns the underlying OAuth registry.
func (s *Service) Registry() *Registry {
	return s.registry
}

// CallbackManager returns the callback servers manager.
func (s *Service) CallbackManager() *CallbackServersManager {
	return s.callbackManager
}
