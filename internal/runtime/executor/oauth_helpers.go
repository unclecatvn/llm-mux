package executor

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nghyane/llm-mux/internal/json"
)

// TokenExpiry extracts the token expiration time from auth metadata.
// It checks for "expired" (RFC3339 string) or calculates from "expires_in" + "timestamp".
// Returns zero time if no valid expiry information is found.
func TokenExpiry(metadata map[string]any) time.Time {
	if metadata == nil {
		return time.Time{}
	}

	if expStr, ok := metadata["expired"].(string); ok {
		expStr = strings.TrimSpace(expStr)
		if expStr != "" {
			if parsed, errParse := time.Parse(time.RFC3339, expStr); errParse == nil {
				return parsed
			}
		}
	}

	expiresIn, hasExpires := Int64Value(metadata["expires_in"])
	tsMs, hasTimestamp := Int64Value(metadata["timestamp"])
	if hasExpires && hasTimestamp {
		return time.Unix(0, tsMs*int64(time.Millisecond)).Add(time.Duration(expiresIn) * time.Second)
	}

	return time.Time{}
}

// MetaStringValue safely retrieves a trimmed string value from metadata map.
// Returns empty string if metadata is nil or key doesn't exist.
func MetaStringValue(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata[key]; ok {
		switch typed := v.(type) {
		case string:
			return strings.TrimSpace(typed)
		case []byte:
			return strings.TrimSpace(string(typed))
		}
	}
	return ""
}

// Int64Value converts various numeric types to int64.
// Supports int, int64, float64, json.Number, and numeric strings.
func Int64Value(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	case json.Number:
		if i, errParse := typed.Int64(); errParse == nil {
			return i, true
		}
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, false
		}
		if i, errParse := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); errParse == nil {
			return i, true
		}
	}
	return 0, false
}

// ResolveHost extracts host from URL string for HTTP Host header.
func ResolveHost(base string) string {
	parsed, errParse := url.Parse(base)
	if errParse != nil {
		return ""
	}
	if parsed.Host != "" {
		return parsed.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
}

// CloneMap creates a shallow copy of a map[string]any.
func CloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// AttrStringValue safely retrieves a trimmed string value from attributes map.
func AttrStringValue(attrs map[string]string, key string) string {
	if attrs == nil {
		return ""
	}
	return strings.TrimSpace(attrs[key])
}
