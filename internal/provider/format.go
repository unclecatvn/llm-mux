package provider

// Format represents the API format for request/response translation.
type Format string

const (
	FormatUnknown     Format = ""
	FormatOpenAI      Format = "openai"
	FormatClaude      Format = "claude"
	FormatGemini      Format = "gemini"
	FormatOllama      Format = "ollama"
	FormatGeminiCLI   Format = "gemini-cli"
	FormatCodex       Format = "codex"
	FormatAntigravity Format = "antigravity"
)

// FromString converts an arbitrary identifier to a Format.
func FromString(v string) Format {
	return Format(v)
}

func (f Format) String() string {
	return string(f)
}
