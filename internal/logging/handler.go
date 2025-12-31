package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type CustomHandler struct {
	w         io.Writer
	level     *slog.LevelVar
	addSource bool
	mu        *sync.Mutex
}

func NewCustomHandler(w io.Writer, level *slog.LevelVar, addSource bool) *CustomHandler {
	return &CustomHandler{
		w:         w,
		level:     level,
		addSource: addSource,
		mu:        &sync.Mutex{},
	}
}

func (h *CustomHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *CustomHandler) Handle(_ context.Context, r slog.Record) error {
	timeStr := r.Time.Format("2006-01-02 15:04:05")
	levelStr := strings.ToLower(r.Level.String())

	var source string
	if h.addSource && r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		source = fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
	}

	var attrs strings.Builder
	r.Attrs(func(a slog.Attr) bool {
		if attrs.Len() > 0 {
			attrs.WriteString(" ")
		}
		attrs.WriteString(a.Key)
		attrs.WriteString("=")
		attrs.WriteString(fmt.Sprintf("%v", a.Value.Any()))
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()

	if source != "" {
		if attrs.Len() > 0 {
			_, err := fmt.Fprintf(h.w, "[%s] [%s] [%s] %s | %s\n", timeStr, levelStr, source, r.Message, attrs.String())
			return err
		}
		_, err := fmt.Fprintf(h.w, "[%s] [%s] [%s] %s\n", timeStr, levelStr, source, r.Message)
		return err
	}

	if attrs.Len() > 0 {
		_, err := fmt.Fprintf(h.w, "[%s] [%s] %s | %s\n", timeStr, levelStr, r.Message, attrs.String())
		return err
	}
	_, err := fmt.Fprintf(h.w, "[%s] [%s] %s\n", timeStr, levelStr, r.Message)
	return err
}

func (h *CustomHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *CustomHandler) WithGroup(name string) slog.Handler {
	return h
}
