package executor

import (
	"sync"
	"time"
)

type codexCache struct {
	ID     string
	Expire time.Time
}

var (
	codexCacheMap  = map[string]codexCache{}
	codexCacheMu   sync.RWMutex
	codexCacheOnce sync.Once
)

// initCodexCacheCleanup starts a background goroutine to periodically clean up expired cache entries.
func initCodexCacheCleanup() {
	codexCacheOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				cleanupExpiredCodexCache()
			}
		}()
	})
}

// cleanupExpiredCodexCache removes expired entries from the cache.
func cleanupExpiredCodexCache() {
	now := time.Now()
	codexCacheMu.Lock()
	defer codexCacheMu.Unlock()
	for key, cache := range codexCacheMap {
		if cache.Expire.Before(now) {
			delete(codexCacheMap, key)
		}
	}
}

// getCodexCache retrieves a cache entry if it exists and is not expired.
func getCodexCache(key string) (codexCache, bool) {
	initCodexCacheCleanup()
	codexCacheMu.RLock()
	defer codexCacheMu.RUnlock()
	c, ok := codexCacheMap[key]
	if !ok || c.Expire.Before(time.Now()) {
		return codexCache{}, false
	}
	return c, true
}

// setCodexCache stores a cache entry.
func setCodexCache(key string, c codexCache) {
	initCodexCacheCleanup()
	codexCacheMu.Lock()
	defer codexCacheMu.Unlock()
	codexCacheMap[key] = c
}
