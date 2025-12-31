package login

import (
	"sync"

	"github.com/nghyane/llm-mux/internal/provider"
)

var (
	storeMu         sync.RWMutex
	registeredStore provider.Store
)

func RegisterTokenStore(store provider.Store) {
	storeMu.Lock()
	registeredStore = store
	storeMu.Unlock()
}

func GetTokenStore() provider.Store {
	storeMu.RLock()
	s := registeredStore
	storeMu.RUnlock()
	if s != nil {
		return s
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if registeredStore == nil {
		registeredStore = NewFileTokenStore()
	}
	return registeredStore
}
