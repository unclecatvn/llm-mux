# llm-mux

Multi-provider LLM gateway with unified OpenAI-compatible API.

## Features

- **Multi-provider support** - Gemini, Claude, OpenAI, Vertex AI, and more
- **Unified API** - OpenAI-compatible endpoints for all providers
- **OAuth authentication** - Gemini CLI, AI Studio, Antigravity, Claude, Codex
- **IR-based translation** - Canonical intermediate representation for clean format conversion
- **Load balancing** - Intelligent provider selection with performance tracking
- **Streaming** - SSE and NDJSON streaming support

## Quick Start

```bash
# Install via Homebrew (coming soon)
brew tap nghyane/tap
brew install llm-mux

# Or build from source
go build -o llm-mux ./cmd/server/
./llm-mux -config config.yaml
```

## Configuration

```yaml
port: 8318
auth-dir: "~/.llm-mux"
use-canonical-translator: true

# API keys (optional - can also use OAuth)
api-keys:
  - "your-api-key"
```

## Supported Providers

| Provider | Auth Method | Models |
|----------|-------------|--------|
| Gemini CLI | OAuth | gemini-2.5-pro, gemini-2.5-flash |
| AI Studio | OAuth | gemini-2.5-pro, gemini-2.5-flash |
| Antigravity | OAuth | Claude Sonnet 4.5, Gemini models |
| Claude | OAuth | claude-sonnet-4, claude-opus-4 |
| Codex | OAuth | gpt-5.1, gpt-5-codex |
| Vertex AI | Service Account | Gemini, Claude |
| OpenAI Compatible | API Key | Any OpenAI-compatible API |

## API Endpoints

```
POST /v1/chat/completions     # OpenAI Chat API
POST /v1/completions          # OpenAI Completions API
GET  /v1/models               # List available models
POST /api/chat                # Ollama-compatible API
```

## Architecture

```
    OpenAI ─────┐                       ┌───── Gemini
    Claude ─────┤                       ├───── Claude
    Ollama ─────┼─────► Canonical ◄─────┼───── OpenAI
      Kiro ─────┤       IR              ├───── Vertex
     Cline ─────┘                       └───── Codex
```

**Hub-and-spoke design** - All formats convert through unified IR, minimizing code duplication.

## Authentication

```bash
# OAuth login for providers
./llm-mux login gemini-cli
./llm-mux login claude
./llm-mux login codex
```

## SDK Usage

```go
import "github.com/nghyane/llm-mux/sdk/cliproxy"

svc, _ := cliproxy.NewBuilder().
    WithConfig(cfg).
    Build()

svc.Run(ctx)
```

See [examples/custom-provider](examples/custom-provider) for custom provider integration.

## License

MIT License - see [LICENSE](LICENSE)
