// Package to_ir converts provider-specific API formats into unified format.
package to_ir

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/nghyane/llm-mux/internal/translator/ir"
)

// OllamaStreamState tracks state for streaming response parsing.
// Maintains accumulated content and tool calls across multiple streaming chunks.
type OllamaStreamState struct {
	AccumulatedContent  string
	AccumulatedThinking string
	ToolCalls           []ir.ToolCall
	ToolCallIndex       int
	FinishReason        ir.FinishReason
}

// NewOllamaStreamState creates a new streaming state for Ollama response parsing.
func NewOllamaStreamState() *OllamaStreamState {
	return &OllamaStreamState{
		ToolCalls:     make([]ir.ToolCall, 0),
		ToolCallIndex: 0,
	}
}

// Finalize returns the complete message accumulated during streaming.
// Should be called after all chunks have been processed.
func (s *OllamaStreamState) Finalize() *ir.Message {
	msg := &ir.Message{Role: ir.RoleAssistant}

	// Add thinking/reasoning content first (if present)
	if s.AccumulatedThinking != "" {
		msg.Content = append(msg.Content, ir.ContentPart{
			Type:      ir.ContentTypeReasoning,
			Reasoning: s.AccumulatedThinking,
		})
	}

	// Add text content
	if s.AccumulatedContent != "" {
		msg.Content = append(msg.Content, ir.ContentPart{
			Type: ir.ContentTypeText,
			Text: s.AccumulatedContent,
		})
	}

	// Add accumulated tool calls
	msg.ToolCalls = s.ToolCalls

	return msg
}

// DetermineFinishReason returns the appropriate finish reason based on accumulated state.
func (s *OllamaStreamState) DetermineFinishReason() ir.FinishReason {
	if s.FinishReason != "" {
		return s.FinishReason
	}
	if len(s.ToolCalls) > 0 {
		return ir.FinishReasonToolCalls
	}
	return ir.FinishReasonStop
}

// Request Parsing (Client → Unified)

// ParseOllamaRequest parses incoming Ollama API request into unified format.
// Supports both /api/chat and /api/generate endpoints.
func ParseOllamaRequest(rawJSON []byte) (*ir.UnifiedChatRequest, error) {
	root, err := ir.ParseAndValidateJSON(rawJSON)
	if err != nil {
		return nil, err
	}

	req := &ir.UnifiedChatRequest{
		Model:    root.Get("model").String(),
		Metadata: make(map[string]any, 4), // Pre-allocate for common metadata
	}

	// Parse options (temperature, top_p, etc.)
	parseOllamaOptions(root.Get("options"), req)

	// Determine endpoint type and parse messages
	if msgs := root.Get("messages"); msgs.Exists() && msgs.IsArray() {
		// /api/chat endpoint
		req.Messages = parseOllamaMessages(msgs.Array())
		req.Metadata["ollama_endpoint"] = "chat"
	} else if prompt := root.Get("prompt"); prompt.Exists() {
		// /api/generate endpoint
		req.Messages = []ir.Message{createOllamaUserMessage(prompt.String(), root.Get("images"))}
		req.Metadata["ollama_endpoint"] = "generate"
	}

	// System prompt (override or prepend)
	if sys := root.Get("system"); sys.Exists() && sys.String() != "" {
		req.Messages = append([]ir.Message{{
			Role:    ir.RoleSystem,
			Content: []ir.ContentPart{{Type: ir.ContentTypeText, Text: sys.String()}},
		}}, req.Messages...)
	}

	// Tools
	if tools := root.Get("tools"); tools.IsArray() {
		for _, t := range tools.Array() {
			if tool := parseOllamaTool(t); tool != nil {
				req.Tools = append(req.Tools, *tool)
			}
		}
	}

	// Metadata fields
	for _, key := range []string{"format", "keep_alive"} {
		if val := root.Get(key); val.Exists() {
			req.Metadata["ollama_"+key] = val.String()
		}
	}
	if stream := root.Get("stream"); stream.Exists() {
		req.Metadata["stream"] = stream.Bool()
	}

	return req, nil
}

// Response Parsing (Ollama API → Unified)

// ParseOllamaResponse parses non-streaming Ollama API response.
// Supports both /api/chat and /api/generate response formats.
func ParseOllamaResponse(rawJSON []byte) ([]ir.Message, *ir.Usage, error) {
	root, err := ir.ParseAndValidateJSON(rawJSON)
	if err != nil {
		return nil, nil, err
	}

	usage := parseOllamaUsage(root)
	msg := ir.Message{Role: ir.RoleAssistant}

	// Extract content (supports both chat 'message' and generate 'response')
	if message := root.Get("message"); message.Exists() {
		// /api/chat
		parseOllamaContent(message, &msg)
		msg.ToolCalls = ir.ParseOpenAIStyleToolCalls(message.Get("tool_calls").Array())
	} else {
		// /api/generate (root level fields)
		parseOllamaContent(root, &msg)
	}

	if len(msg.Content) == 0 && len(msg.ToolCalls) == 0 {
		return nil, usage, nil
	}
	return []ir.Message{msg}, usage, nil
}

// ParseOllamaChunk parses streaming Ollama API chunk into events (stateless version).
// For multi-tool call tracking, use ParseOllamaChunkWithState instead.
// Handles both /api/chat and /api/generate streaming formats.
func ParseOllamaChunk(rawJSON []byte) ([]ir.UnifiedEvent, error) {
	return ParseOllamaChunkWithState(rawJSON, nil)
}

// ParseOllamaChunkWithState parses streaming Ollama API chunk into events with state tracking.
// Maintains state for multi-tool call accumulation across chunks.
// If state is nil, operates in stateless mode (backward compatible with ParseOllamaChunk).
func ParseOllamaChunkWithState(rawJSON []byte, state *OllamaStreamState) ([]ir.UnifiedEvent, error) {
	// Ollama uses newline-delimited JSON (not SSE)
	rawJSON = []byte(strings.TrimSpace(string(rawJSON)))
	if len(rawJSON) == 0 {
		return nil, nil
	}
	// Parse and validate in one step
	root, err := ir.ParseAndValidateJSON(rawJSON)
	if err != nil {
		return nil, nil // Ignore invalid chunks in streaming
	}

	var events []ir.UnifiedEvent

	// Determine content source
	source := root
	if msg := root.Get("message"); msg.Exists() {
		source = msg // /api/chat
	}

	// 1. Reasoning/Thinking
	if thinking := source.Get("thinking"); thinking.Exists() && thinking.String() != "" {
		thinkingText := thinking.String()
		if state != nil {
			state.AccumulatedThinking += thinkingText
		}
		events = append(events, ir.UnifiedEvent{Type: ir.EventTypeReasoning, Reasoning: thinkingText})
	}

	// 2. Content (Text)
	// /api/chat uses 'content', /api/generate uses 'response'
	content := source.Get("content")
	if !content.Exists() {
		content = root.Get("response")
	}
	if content.Exists() && content.String() != "" {
		contentText := content.String()
		if state != nil {
			state.AccumulatedContent += contentText
		}
		events = append(events, ir.UnifiedEvent{Type: ir.EventTypeToken, Content: contentText})
	}

	// 3. Tool Calls (only in /api/chat usually)
	if tcs := source.Get("tool_calls"); tcs.IsArray() {
		for _, tc := range tcs.Array() {
			// Ollama supports both formats:
			// 1. OpenAI-style: {"type": "function", "function": {"name": "...", "arguments": "..."}}
			// 2. Simplified: {"function": {"name": "...", "arguments": {...}}}
			funcData := tc.Get("function")
			if !funcData.Exists() {
				continue
			}

			name := funcData.Get("name").String()
			if name == "" {
				continue
			}

			// Get arguments - can be string or object
			args := funcData.Get("arguments")
			argsStr := ""
			if args.IsObject() {
				argsStr = args.Raw
			} else {
				argsStr = args.String()
			}
			if argsStr == "" {
				argsStr = "{}"
			}

			// Generate or use existing tool call ID
			toolID := tc.Get("id").String()
			if toolID == "" {
				if state != nil {
					toolID = fmt.Sprintf("call_%d", state.ToolCallIndex)
				} else {
					toolID = ir.GenToolCallID()
				}
			}

			toolCall := ir.ToolCall{
				ID:   toolID,
				Name: name,
				Args: argsStr,
			}

			// Track in state if available
			toolCallIndex := 0
			if state != nil {
				toolCallIndex = state.ToolCallIndex
				state.ToolCalls = append(state.ToolCalls, toolCall)
				state.ToolCallIndex++
			}

			events = append(events, ir.UnifiedEvent{
				Type:          ir.EventTypeToolCall,
				ToolCall:      &toolCall,
				ToolCallIndex: toolCallIndex,
			})
		}
	}

	// 4. Finish / Done
	if root.Get("done").Bool() {
		finishReason := mapOllamaDoneReason(root.Get("done_reason").String())

		// Override finish reason if we have tool calls
		if state != nil && len(state.ToolCalls) > 0 && finishReason == ir.FinishReasonStop {
			finishReason = ir.FinishReasonToolCalls
		}

		if state != nil {
			state.FinishReason = finishReason
		}

		events = append(events, ir.UnifiedEvent{
			Type:         ir.EventTypeFinish,
			FinishReason: finishReason,
			Usage:        parseOllamaUsage(root),
		})
	}

	return events, nil
}

// Helper Functions

func parseOllamaUsage(root gjson.Result) *ir.Usage {
	p := root.Get("prompt_eval_count").Int()
	c := root.Get("eval_count").Int()
	if p == 0 && c == 0 {
		return nil
	}
	return &ir.Usage{
		PromptTokens:     p,
		CompletionTokens: c,
		TotalTokens:      p + c,
	}
}

func parseOllamaContent(source gjson.Result, msg *ir.Message) {
	if thinking := source.Get("thinking"); thinking.Exists() && thinking.String() != "" {
		msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeReasoning, Reasoning: thinking.String()})
	}
	// 'content' for chat, 'response' for generate
	text := source.Get("content").String()
	if text == "" {
		text = source.Get("response").String()
	}
	if text != "" {
		msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeText, Text: text})
	}
}

func parseOllamaOptions(opts gjson.Result, req *ir.UnifiedChatRequest) {
	if !opts.Exists() {
		return
	}
	if v := opts.Get("temperature"); v.Exists() {
		f := v.Float()
		req.Temperature = &f
	}
	if v := opts.Get("top_p"); v.Exists() {
		f := v.Float()
		req.TopP = &f
	}
	if v := opts.Get("top_k"); v.Exists() {
		i := int(v.Int())
		req.TopK = &i
	}
	if v := opts.Get("num_predict"); v.Exists() {
		i := int(v.Int())
		req.MaxTokens = &i
	}
	if v := opts.Get("stop"); v.Exists() {
		if v.IsArray() {
			for _, s := range v.Array() {
				req.StopSequences = append(req.StopSequences, s.String())
			}
		} else {
			req.StopSequences = append(req.StopSequences, v.String())
		}
	}
	// Metadata options
	if v := opts.Get("seed"); v.Exists() {
		req.Metadata["ollama_seed"] = v.Int()
	}
	if v := opts.Get("num_ctx"); v.Exists() {
		req.Metadata["ollama_num_ctx"] = v.Int()
	}
}

func parseOllamaMessages(msgs []gjson.Result) []ir.Message {
	var res []ir.Message
	for _, m := range msgs {
		msg := ir.Message{Role: ir.MapStandardRole(m.Get("role").String())}

		// Handle content and images
		content := m.Get("content").String()
		images := m.Get("images")

		if images.IsArray() && len(images.Array()) > 0 {
			if content != "" {
				msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeText, Text: content})
			}
			for _, img := range images.Array() {
				if part := parseOllamaImage(img.String()); part != nil {
					msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeImage, Image: part})
				}
			}
		} else if content != "" {
			msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeText, Text: content})
		}

		// Tool calls
		if msg.Role == ir.RoleAssistant {
			msg.ToolCalls = ir.ParseOpenAIStyleToolCalls(m.Get("tool_calls").Array())
		}
		// Tool results
		if msg.Role == ir.RoleTool {
			id := m.Get("tool_call_id").String()
			if id == "" {
				id = m.Get("tool_name").String()
			} // Fallback
			if id != "" {
				msg.Content = append(msg.Content, ir.ContentPart{
					Type:       ir.ContentTypeToolResult,
					ToolResult: &ir.ToolResultPart{ToolCallID: id, Result: ir.SanitizeText(content)},
				})
			}
		}

		if len(msg.Content) > 0 || len(msg.ToolCalls) > 0 {
			res = append(res, msg)
		}
	}
	return res
}

func createOllamaUserMessage(prompt string, images gjson.Result) ir.Message {
	msg := ir.Message{Role: ir.RoleUser, Content: []ir.ContentPart{{Type: ir.ContentTypeText, Text: prompt}}}
	if images.IsArray() {
		for _, img := range images.Array() {
			if part := parseOllamaImage(img.String()); part != nil {
				msg.Content = append(msg.Content, ir.ContentPart{Type: ir.ContentTypeImage, Image: part})
			}
		}
	}
	return msg
}

func parseOllamaTool(t gjson.Result) *ir.ToolDefinition {
	if t.Get("type").String() != "function" {
		return nil
	}
	fn := t.Get("function")
	name := fn.Get("name").String()
	if name == "" {
		return nil
	}

	var params map[string]any
	if p := fn.Get("parameters"); p.Exists() {
		json.Unmarshal([]byte(p.Raw), &params)
		params = ir.CleanJsonSchema(params)
	}
	if params == nil {
		params = make(map[string]any)
	}

	return &ir.ToolDefinition{
		Name:        name,
		Description: fn.Get("description").String(),
		Parameters:  params,
	}
}

func parseOllamaImage(data string) *ir.ImagePart {
	if data == "" {
		return nil
	}
	if !strings.HasPrefix(data, "data:") {
		data = "data:image/png;base64," + data
	}
	parts := strings.SplitN(data, ",", 2)
	if len(parts) != 2 {
		return nil
	}

	mime := "image/png"
	if idx := strings.Index(parts[0], ";"); idx > 5 {
		mime = parts[0][5:idx]
	}
	return &ir.ImagePart{MimeType: mime, Data: parts[1]}
}

func mapOllamaDoneReason(r string) ir.FinishReason {
	switch r {
	case "stop":
		return ir.FinishReasonStop
	case "length":
		return ir.FinishReasonMaxTokens // Ollama "length" = IR "max_tokens"
	case "tool_calls":
		return ir.FinishReasonToolCalls
	default:
		return ir.FinishReasonStop
	}
}
