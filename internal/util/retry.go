package util

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

func WithRetry[T any](ctx context.Context, maxRetries int, logPrefix string, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}

		lastErr = err
		slog.Warn(fmt.Sprintf("%s attempt %d failed: %v", logPrefix, attempt+1, err))
	}

	return zero, fmt.Errorf("%s failed after %d attempts: %w", logPrefix, maxRetries, lastErr)
}
