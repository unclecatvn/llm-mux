package cmd

import (
	"github.com/nghyane/llm-mux/internal/auth/login"
)

// newAuthManager creates a new authentication manager instance with all supported
// authenticators and a file-based token store. It initializes authenticators for
// Gemini, Codex, Claude, and Qwen providers.
// Returns:
//   - *login.Manager: A configured authentication manager instance
func newAuthManager() *login.Manager {
	store := login.GetTokenStore()
	manager := login.NewManager(store,
		login.NewGeminiAuthenticator(),
		login.NewCodexAuthenticator(),
		login.NewClaudeAuthenticator(),
		login.NewQwenAuthenticator(),
		login.NewIFlowAuthenticator(),
		login.NewAntigravityAuthenticator(),
		login.NewClineAuthenticator(),
		login.NewKiroAuthenticator(),
		login.NewCopilotAuthenticator(),
	)
	return manager
}
