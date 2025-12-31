package login

import (
	"time"

	"github.com/nghyane/llm-mux/internal/provider"
)

func init() {
	registerRefreshLead("codex", func() Authenticator { return NewCodexAuthenticator() })
	registerRefreshLead("claude", func() Authenticator { return NewClaudeAuthenticator() })
	registerRefreshLead("qwen", func() Authenticator { return NewQwenAuthenticator() })
	registerRefreshLead("iflow", func() Authenticator { return NewIFlowAuthenticator() })
	registerRefreshLead("gemini", func() Authenticator { return NewGeminiAuthenticator() })
	registerRefreshLead("gemini-cli", func() Authenticator { return NewGeminiAuthenticator() })
	registerRefreshLead("antigravity", func() Authenticator { return NewAntigravityAuthenticator() })
	registerRefreshLead("cline", func() Authenticator { return NewClineAuthenticator() })
	registerRefreshLead("kiro", func() Authenticator { return NewKiroAuthenticator() })
	registerRefreshLead("github-copilot", func() Authenticator { return NewCopilotAuthenticator() })
}

func registerRefreshLead(providerName string, factory func() Authenticator) {
	provider.RegisterRefreshLeadProvider(providerName, func() *time.Duration {
		if factory == nil {
			return nil
		}
		auth := factory()
		if auth == nil {
			return nil
		}
		return auth.RefreshLead()
	})
}
