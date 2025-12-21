package util

import (
	"testing"

	"github.com/nghyane/llm-mux/internal/translator/ir"
)

func TestCountTokensFromIR_NonGemini(t *testing.T) {
	req := &ir.UnifiedChatRequest{
		Messages: []ir.Message{
			{
				Role: ir.RoleUser,
				Content: []ir.ContentPart{
					{Type: ir.ContentTypeText, Text: "Hello, world!"},
				},
			},
		},
	}

	tests := []struct {
		model    string
		expected int64
		min      int64
	}{
		// GPT-4o uses o200k_base
		{"gpt-4o", 10, 8},
		// Claude uses o200k_base (approx)
		{"claude-3-opus", 10, 8},
		// Legacy GPT-4 uses cl100k_base
		{"gpt-4", 10, 8},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			count := CountTokensFromIR(tt.model, req)
			if count == 0 {
				t.Errorf("Expected tokens > 0 for %s, got 0", tt.model)
			}
			if count < tt.min {
				t.Errorf("Expected tokens >= %d for %s, got %d", tt.min, tt.model, count)
			}
			t.Logf("Model %s token count: %d", tt.model, count)
		})
	}
}

func TestCountTokensFromIR_ClaudeTools(t *testing.T) {
	req := &ir.UnifiedChatRequest{
		Messages: []ir.Message{
			{
				Role: ir.RoleUser,
				Content: []ir.ContentPart{
					{Type: ir.ContentTypeText, Text: "What is the weather?"},
				},
			},
		},
		Tools: []ir.ToolDefinition{
			{
				Name:        "get_weather",
				Description: "Get weather info",
			},
		},
	}

	count := CountTokensFromIR("claude-3-sonnet", req)
	if count <= 15 {
		t.Errorf("Expected tokens > 15 (with tools overhead), got %d", count)
	}
	t.Logf("Claude with tools token count: %d", count)
}
