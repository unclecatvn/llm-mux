package util

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/nghyane/llm-mux/internal/translator/ir"
	"github.com/tiktoken-go/tokenizer"
)

var (
	tiktokenCache   = make(map[tokenizer.Encoding]tokenizer.Codec)
	tiktokenCacheMu sync.RWMutex
)

var (
	roleTokenCache   = make(map[string]int64)
	roleTokenCacheMu sync.RWMutex
)

const ImageTokenCostOpenAI = 255

const (
	DocTokenCost   = 500
	AudioTokenCost = 300
	VideoTokenCost = 2000
)

var stringBuilderPool = sync.Pool{
	New: func() any {
		sb := &strings.Builder{}
		sb.Grow(1024)
		return sb
	},
}

func CountTiktokenTokens(model string, req *ir.UnifiedChatRequest) int64 {
	if req == nil {
		return 0
	}

	encodingName := getTiktokenEncodingName(model)
	enc, err := getTiktokenCodec(encodingName)
	if err != nil {
		return 0
	}

	var totalTokens int64

	const tokensPerMessage int64 = 3

	if req.Instructions != "" {
		totalTokens += countTokens(enc, req.Instructions) + tokensPerMessage
	}

	for i := range req.Messages {
		totalTokens += tokensPerMessage

		totalTokens += countRoleTokens(enc, string(req.Messages[i].Role))

		contentStr, imageCount, docCount, audioCount, videoCount := irMessageToStringPooled(&req.Messages[i])
		if contentStr != "" {
			totalTokens += countTokens(enc, contentStr)
		}
		totalTokens += int64(imageCount*ImageTokenCostOpenAI +
			docCount*DocTokenCost +
			audioCount*AudioTokenCost +
			videoCount*VideoTokenCost)
	}

	if len(req.Tools) > 0 {
		totalTokens += countJSONTokens(enc, req.Tools) + 10
	}

	if len(req.MCPServers) > 0 {
		totalTokens += countJSONTokens(enc, req.MCPServers) + 20
	}

	if req.Metadata != nil {
		for _, key := range []string{ir.MetaGoogleSearch, ir.MetaClaudeComputer, ir.MetaClaudeBash, ir.MetaClaudeTextEditor} {
			if val, ok := req.Metadata[key]; ok {
				totalTokens += countJSONTokens(enc, val) + 15
			}
		}
	}

	totalTokens += 3

	return totalTokens
}

func countTokens(enc tokenizer.Codec, s string) int64 {
	ids, _, _ := enc.Encode(s)
	return int64(len(ids))
}

func countJSONTokens(enc tokenizer.Codec, v any) int64 {
	data, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	ids, _, _ := enc.Encode(string(data))
	return int64(len(ids))
}

func countRoleTokens(enc tokenizer.Codec, role string) int64 {
	roleTokenCacheMu.RLock()
	count, ok := roleTokenCache[role]
	roleTokenCacheMu.RUnlock()
	if ok {
		return count
	}

	ids, _, _ := enc.Encode(role)
	count = int64(len(ids))

	roleTokenCacheMu.Lock()
	roleTokenCache[role] = count
	roleTokenCacheMu.Unlock()

	return count
}

func getTiktokenCodec(encoding tokenizer.Encoding) (tokenizer.Codec, error) {
	tiktokenCacheMu.RLock()
	codec, ok := tiktokenCache[encoding]
	tiktokenCacheMu.RUnlock()
	if ok {
		return codec, nil
	}

	tiktokenCacheMu.Lock()
	defer tiktokenCacheMu.Unlock()

	if codec, ok := tiktokenCache[encoding]; ok {
		return codec, nil
	}

	codec, err := tokenizer.Get(encoding)
	if err != nil {
		return nil, err
	}

	tiktokenCache[encoding] = codec
	return codec, nil
}

func getTiktokenEncodingName(model string) tokenizer.Encoding {
	lower := strings.ToLower(model)

	switch {
	case strings.Contains(lower, "gpt-5"),
		strings.Contains(lower, "gpt-4o"),
		strings.Contains(lower, "claude"),
		strings.Contains(lower, "qwen"),
		strings.Contains(lower, "antigravity"):
		return tokenizer.O200kBase

	case strings.Contains(lower, "gpt-4"),
		strings.Contains(lower, "gpt-3.5"),
		strings.Contains(lower, "turbo"):
		return tokenizer.Cl100kBase

	default:
		return tokenizer.O200kBase
	}
}

func irMessageToStringPooled(msg *ir.Message) (string, int, int, int, int) {
	sb := stringBuilderPool.Get().(*strings.Builder)
	sb.Reset()
	defer stringBuilderPool.Put(sb)

	imageCount := 0
	docCount := 0
	audioCount := 0
	videoCount := 0

	for i := range msg.Content {
		part := &msg.Content[i]
		switch part.Type {
		case ir.ContentTypeText:
			if part.Text != "" {
				sb.WriteString(part.Text)
			}
		case ir.ContentTypeReasoning:
			if part.Reasoning != "" {
				sb.WriteString(part.Reasoning)
			}
			if len(part.ThoughtSignature) > 0 {
				sb.Write(part.ThoughtSignature)
			}
		case ir.ContentTypeCodeResult:
			if part.CodeExecution != nil && part.CodeExecution.Output != "" {
				sb.WriteString(part.CodeExecution.Output)
			}
		case ir.ContentTypeExecutableCode:
			if part.CodeExecution != nil && part.CodeExecution.Code != "" {
				sb.WriteString(part.CodeExecution.Code)
			}
		case ir.ContentTypeImage:
			if part.Image != nil {
				imageCount++
			}
		case ir.ContentTypeFile:
			if part.File != nil {
				if part.File.FileData != "" {
					sb.WriteString(part.File.FileData)
				} else if part.File.FileURL != "" || part.File.FileID != "" {
					docCount++
				}
			}
		case ir.ContentTypeAudio:
			if part.Audio != nil {
				if part.Audio.Transcript != "" {
					sb.WriteString(part.Audio.Transcript)
				}
				audioCount++
			}
		case ir.ContentTypeVideo:
			if part.Video != nil {
				videoCount++
			}
		case ir.ContentTypeToolResult:
			if part.ToolResult != nil {
				sb.WriteString("\nTool ")
				sb.WriteString(part.ToolResult.ToolCallID)
				sb.WriteString(" result: ")
				sb.WriteString(part.ToolResult.Result)
				imageCount += len(part.ToolResult.Images)
			}
		}
	}

	for i := range msg.ToolCalls {
		tc := &msg.ToolCalls[i]
		sb.WriteString("\nCall tool ")
		sb.WriteString(tc.Name)
		sb.WriteByte('(')
		sb.WriteString(tc.Args)
		sb.WriteByte(')')
	}

	return sb.String(), imageCount, docCount, audioCount, videoCount
}
