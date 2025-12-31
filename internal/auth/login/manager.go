package login

import (
	"context"
	"fmt"

	"github.com/nghyane/llm-mux/internal/config"
	"github.com/nghyane/llm-mux/internal/provider"
)

type Manager struct {
	authenticators map[string]Authenticator
	store          provider.Store
}

func NewManager(store provider.Store, authenticators ...Authenticator) *Manager {
	mgr := &Manager{
		authenticators: make(map[string]Authenticator),
		store:          store,
	}
	for i := range authenticators {
		mgr.Register(authenticators[i])
	}
	return mgr
}

func (m *Manager) Register(a Authenticator) {
	if a == nil {
		return
	}
	if m.authenticators == nil {
		m.authenticators = make(map[string]Authenticator)
	}
	m.authenticators[a.Provider()] = a
}

func (m *Manager) SetStore(store provider.Store) {
	m.store = store
}

func (m *Manager) Login(ctx context.Context, providerName string, cfg *config.Config, opts *LoginOptions) (*provider.Auth, string, error) {
	auth, ok := m.authenticators[providerName]
	if !ok {
		return nil, "", fmt.Errorf("cliproxy auth: authenticator %s not registered", providerName)
	}

	record, err := auth.Login(ctx, cfg, opts)
	if err != nil {
		return nil, "", err
	}
	if record == nil {
		return nil, "", fmt.Errorf("cliproxy auth: authenticator %s returned nil record", providerName)
	}

	if m.store == nil {
		return record, "", nil
	}

	if cfg != nil {
		if dirSetter, ok := m.store.(interface{ SetBaseDir(string) }); ok {
			dirSetter.SetBaseDir(cfg.AuthDir)
		}
	}

	savedPath, err := m.store.Save(ctx, record)
	if err != nil {
		return record, "", err
	}
	return record, savedPath, nil
}
