// Package executor provides model fetching utilities shared across Gemini-family providers.
package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nghyane/llm-mux/internal/registry"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// =============================================================================
// Shared Constants
// =============================================================================

const (
	// cloudCodeModelsPath is the endpoint for fetching models from Cloud Code Assist.
	cloudCodeModelsPath = "/v1internal:fetchAvailableModels"

	// glAPIModelsPath is the endpoint for fetching models from Generative Language API.
	glAPIModelsPath = "/v1beta/models"
)

// =============================================================================
// Model Alias Functions
// =============================================================================

// ModelAliasFunc converts upstream model name to user-facing alias.
// Returns empty string if the model should be hidden.
type ModelAliasFunc func(upstreamName string) string

// DefaultGeminiAlias returns the model ID as-is (no transformation).
func DefaultGeminiAlias(upstreamName string) string {
	return upstreamName
}

// =============================================================================
// Cloud Code Assist Model Fetcher (Antigravity, Gemini CLI)
// =============================================================================

// CloudCodeFetchConfig holds configuration for fetching models from Cloud Code Assist.
type CloudCodeFetchConfig struct {
	BaseURLs     []string       // Fallback order of base URLs
	Token        string         // Bearer token
	ProviderType string         // Provider type (e.g., "antigravity", "gemini-cli")
	UserAgent    string         // User-Agent header
	Host         string         // Optional Host header override
	AliasFunc    ModelAliasFunc // Function to convert upstream name to alias
}

// FetchCloudCodeModels fetches models from Cloud Code Assist endpoint.
// This is shared between Antigravity and Gemini CLI providers.
func FetchCloudCodeModels(ctx context.Context, httpClient *http.Client, cfg CloudCodeFetchConfig) []*registry.ModelInfo {
	if cfg.Token == "" || len(cfg.BaseURLs) == 0 {
		return nil
	}

	aliasFunc := cfg.AliasFunc
	if aliasFunc == nil {
		aliasFunc = DefaultGeminiAlias
	}

	handler := NewRetryHandler(AntigravityRetryConfig())

	for idx := 0; idx < len(cfg.BaseURLs); idx++ {
		baseURL := cfg.BaseURLs[idx]
		hasNext := idx+1 < len(cfg.BaseURLs)

		modelsURL := baseURL + cloudCodeModelsPath
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, modelsURL, bytes.NewReader([]byte(`{}`)))
		if err != nil {
			log.Errorf("%s: failed to create models request: %v", cfg.ProviderType, err)
			return nil
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+cfg.Token)
		if cfg.UserAgent != "" {
			httpReq.Header.Set("User-Agent", cfg.UserAgent)
		}
		if cfg.Host != "" {
			httpReq.Host = cfg.Host
		}

		httpResp, err := httpClient.Do(httpReq)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				log.Errorf("%s: request timed out", cfg.ProviderType)
				return nil
			}
			action, _ := handler.HandleError(ctx, err, hasNext)
			if action == RetryActionContinueNext {
				log.Debugf("%s: models request error on %s, retrying with fallback", cfg.ProviderType, baseURL)
				continue
			}
			return nil
		}

		bodyBytes, errRead := io.ReadAll(httpResp.Body)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("%s: close response body error: %v", cfg.ProviderType, errClose)
		}
		if errRead != nil {
			if hasNext {
				log.Debugf("%s: models read error on %s, retrying with fallback", cfg.ProviderType, baseURL)
				continue
			}
			return nil
		}

		action, _ := handler.HandleResponse(ctx, httpResp.StatusCode, bodyBytes, hasNext)
		if action == RetryActionContinueNext {
			log.Debugf("%s: models request status %d on %s, trying next", cfg.ProviderType, httpResp.StatusCode, baseURL)
			continue
		}
		if action != RetryActionSuccess {
			return nil
		}

		return ParseCloudCodeModels(bodyBytes, cfg.ProviderType, aliasFunc)
	}
	return nil
}

// ParseCloudCodeModels parses Cloud Code Assist response format.
// Response format: {"models": {"model-id": {...}, ...}} (MAP)
func ParseCloudCodeModels(body []byte, providerType string, aliasFunc ModelAliasFunc) []*registry.ModelInfo {
	result := gjson.GetBytes(body, "models")
	if !result.Exists() {
		return nil
	}

	if aliasFunc == nil {
		aliasFunc = DefaultGeminiAlias
	}

	now := time.Now().Unix()
	models := make([]*registry.ModelInfo, 0, len(result.Map()))

	for originalName := range result.Map() {
		aliasName := aliasFunc(originalName)
		if aliasName == "" {
			continue
		}

		modelInfo := &registry.ModelInfo{
			ID:           aliasName,
			Name:         aliasName,
			Object:       "model",
			Created:      now,
			OwnedBy:      providerType,
			Type:         providerType,
			UpstreamName: originalName,
		}

		// Apply shared Gemini metadata (handles display name, thinking, limits)
		registry.ApplyGeminiMeta(modelInfo)

		models = append(models, modelInfo)
	}
	return models
}

// =============================================================================
// Generative Language API Model Fetcher (Gemini, Vertex, AIStudio)
// =============================================================================

// GLAPIFetchConfig holds configuration for fetching models from Generative Language API.
type GLAPIFetchConfig struct {
	BaseURL      string // Base URL (e.g., "https://generativelanguage.googleapis.com")
	APIKey       string // API key (mutually exclusive with Bearer)
	Bearer       string // Bearer token (mutually exclusive with APIKey)
	ProviderType string // Provider type (e.g., "gemini", "vertex", "aistudio")
}

// FetchGLAPIModels fetches models from the Generative Language API.
// Used by Gemini (API key), Vertex (API key mode), and AIStudio providers.
func FetchGLAPIModels(ctx context.Context, httpClient *http.Client, cfg GLAPIFetchConfig) []*registry.ModelInfo {
	if cfg.APIKey == "" && cfg.Bearer == "" {
		return nil
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = GeminiDefaultBaseURL
	}

	modelsURL := baseURL + glAPIModelsPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		log.Errorf("%s: failed to create models request: %v", cfg.ProviderType, err)
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		httpReq.Header.Set("x-goog-api-key", cfg.APIKey)
	} else {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.Bearer)
	}

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Errorf("%s: request timed out", cfg.ProviderType)
			return nil
		}
		log.Errorf("%s: models request error: %v", cfg.ProviderType, err)
		return nil
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		log.Errorf("%s: models request failed with status %d", cfg.ProviderType, httpResp.StatusCode)
		return nil
	}

	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("%s: failed to read models response: %v", cfg.ProviderType, err)
		return nil
	}

	return ParseGLAPIModels(bodyBytes, cfg.ProviderType)
}

// ParseGLAPIModels parses Generative Language API response format.
// Response format: {"models": [{...}, ...]} (ARRAY)
func ParseGLAPIModels(body []byte, providerType string) []*registry.ModelInfo {
	modelsArray := gjson.GetBytes(body, "models")
	if !modelsArray.Exists() || !modelsArray.IsArray() {
		return nil
	}

	now := time.Now().Unix()
	var models []*registry.ModelInfo

	modelsArray.ForEach(func(_, value gjson.Result) bool {
		// Name format: "models/gemini-2.5-flash"
		fullName := value.Get("name").String()
		modelID := strings.TrimPrefix(fullName, "models/")
		if modelID == "" {
			return true
		}

		// Skip non-gemini models (e.g., text-embedding, imagen)
		if !strings.HasPrefix(modelID, "gemini-") {
			return true
		}

		displayName := value.Get("displayName").String()
		description := value.Get("description").String()
		version := value.Get("version").String()
		inputTokenLimit := value.Get("inputTokenLimit").Int()
		outputTokenLimit := value.Get("outputTokenLimit").Int()

		modelInfo := &registry.ModelInfo{
			ID:               modelID,
			Name:             modelID,
			Object:           "model",
			Created:          now,
			OwnedBy:          providerType,
			Type:             providerType,
			DisplayName:      displayName,
			Description:      description,
			Version:          version,
			InputTokenLimit:  int(inputTokenLimit),
			OutputTokenLimit: int(outputTokenLimit),
		}

		// Apply shared Gemini metadata (handles thinking support, upstream mapping, etc.)
		registry.ApplyGeminiMeta(modelInfo)

		models = append(models, modelInfo)
		return true
	})

	return models
}
