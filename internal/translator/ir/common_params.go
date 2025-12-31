package ir

import "github.com/tidwall/gjson"

// ExtractTemperature extracts temperature from gjson.Result, returns nil if not present.
func ExtractTemperature(root gjson.Result, keys ...string) *float64 {
	if len(keys) == 0 {
		keys = []string{"temperature"}
	}
	for _, k := range keys {
		if v := root.Get(k); v.Exists() {
			return Ptr(v.Float())
		}
	}
	return nil
}

// ExtractTopP extracts top_p from gjson.Result, returns nil if not present.
func ExtractTopP(root gjson.Result, keys ...string) *float64 {
	if len(keys) == 0 {
		keys = []string{"top_p", "topP"}
	}
	for _, k := range keys {
		if v := root.Get(k); v.Exists() {
			return Ptr(v.Float())
		}
	}
	return nil
}

// ExtractTopK extracts top_k from gjson.Result, returns nil if not present.
func ExtractTopK(root gjson.Result, keys ...string) *int {
	if len(keys) == 0 {
		keys = []string{"top_k", "topK"}
	}
	for _, k := range keys {
		if v := root.Get(k); v.Exists() {
			return Ptr(int(v.Int()))
		}
	}
	return nil
}

// ExtractMaxTokens extracts max tokens from gjson.Result using multiple key variants.
func ExtractMaxTokens(root gjson.Result, keys ...string) *int {
	if len(keys) == 0 {
		keys = []string{"max_tokens", "max_output_tokens", "max_completion_tokens", "maxOutputTokens"}
	}
	for _, k := range keys {
		if v := root.Get(k); v.Exists() {
			return Ptr(int(v.Int()))
		}
	}
	return nil
}

// ExtractStopSequences extracts stop sequences as array or single string.
func ExtractStopSequences(root gjson.Result, keys ...string) []string {
	if len(keys) == 0 {
		keys = []string{"stop", "stop_sequences", "stopSequences"}
	}
	for _, k := range keys {
		if v := root.Get(k); v.Exists() {
			if v.IsArray() {
				var result []string
				for _, s := range v.Array() {
					result = append(result, s.String())
				}
				return result
			}
			if s := v.String(); s != "" {
				return []string{s}
			}
		}
	}
	return nil
}

// ExtractFrequencyPenalty extracts frequency_penalty from gjson.Result.
func ExtractFrequencyPenalty(root gjson.Result) *float64 {
	if v := root.Get("frequency_penalty"); v.Exists() {
		return Ptr(v.Float())
	}
	return nil
}

// ExtractPresencePenalty extracts presence_penalty from gjson.Result.
func ExtractPresencePenalty(root gjson.Result) *float64 {
	if v := root.Get("presence_penalty"); v.Exists() {
		return Ptr(v.Float())
	}
	return nil
}

// ExtractLogprobs extracts logprobs boolean from gjson.Result.
func ExtractLogprobs(root gjson.Result) *bool {
	if v := root.Get("logprobs"); v.Exists() {
		return Ptr(v.Bool())
	}
	return nil
}

// ExtractTopLogprobs extracts top_logprobs count from gjson.Result.
func ExtractTopLogprobs(root gjson.Result) *int {
	if v := root.Get("top_logprobs"); v.Exists() {
		return Ptr(int(v.Int()))
	}
	return nil
}

// ExtractCandidateCount extracts n (candidate count) from gjson.Result.
func ExtractCandidateCount(root gjson.Result) *int {
	if v := root.Get("n"); v.Exists() {
		return Ptr(int(v.Int()))
	}
	return nil
}

// ApplyCommonParams applies common LLM parameters to UnifiedChatRequest.
// This is a convenience function that applies temperature, top_p, top_k, max_tokens, and stop sequences.
func ApplyCommonParams(req *UnifiedChatRequest, root gjson.Result) {
	req.Temperature = ExtractTemperature(root)
	req.TopP = ExtractTopP(root)
	req.TopK = ExtractTopK(root)
	req.MaxTokens = ExtractMaxTokens(root)
	req.StopSequences = ExtractStopSequences(root)
}

// ApplyOpenAIExtendedParams applies OpenAI-specific extended parameters.
func ApplyOpenAIExtendedParams(req *UnifiedChatRequest, root gjson.Result) {
	req.FrequencyPenalty = ExtractFrequencyPenalty(root)
	req.PresencePenalty = ExtractPresencePenalty(root)
	req.Logprobs = ExtractLogprobs(root)
	req.TopLogprobs = ExtractTopLogprobs(root)
	req.CandidateCount = ExtractCandidateCount(root)
}
