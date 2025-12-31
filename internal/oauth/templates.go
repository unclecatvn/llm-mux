package oauth

import (
	"embed"
	"html/template"
	"sync"

	"github.com/nghyane/llm-mux/internal/translator/ir"
)

//go:embed templates/*.html
var templateFS embed.FS

// Template data structures
type successData struct{}

type errorData struct {
	Message string
}

type webUIData struct {
	Provider string
	State    string
	Message  string
}

// Parsed templates (initialized once)
var (
	tmplOnce      sync.Once
	tmplSuccess   *template.Template
	tmplError     *template.Template
	tmplSuccessWU *template.Template
	tmplErrorWU   *template.Template
	tmplInitErr   error
)

// initTemplates parses all templates once at first use.
func initTemplates() {
	tmplOnce.Do(func() {
		// Parse base template
		base, err := template.ParseFS(templateFS, "templates/base.html")
		if err != nil {
			tmplInitErr = err
			return
		}

		// Clone and parse each page template
		tmplSuccess, err = template.Must(base.Clone()).ParseFS(templateFS, "templates/success.html")
		if err != nil {
			tmplInitErr = err
			return
		}

		tmplError, err = template.Must(base.Clone()).ParseFS(templateFS, "templates/error.html")
		if err != nil {
			tmplInitErr = err
			return
		}

		tmplSuccessWU, err = template.Must(base.Clone()).ParseFS(templateFS, "templates/success_webui.html")
		if err != nil {
			tmplInitErr = err
			return
		}

		tmplErrorWU, err = template.Must(base.Clone()).ParseFS(templateFS, "templates/error_webui.html")
		if err != nil {
			tmplInitErr = err
			return
		}
	})
}

// RenderSuccess renders the CLI success page.
func RenderSuccess() (string, error) {
	initTemplates()
	if tmplInitErr != nil {
		return "", tmplInitErr
	}

	buf := ir.GetBuffer()
	defer ir.PutBuffer(buf)
	if err := tmplSuccess.ExecuteTemplate(buf, "base", successData{}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderError renders the CLI error page.
func RenderError(message string) (string, error) {
	initTemplates()
	if tmplInitErr != nil {
		return "", tmplInitErr
	}

	buf := ir.GetBuffer()
	defer ir.PutBuffer(buf)
	if err := tmplError.ExecuteTemplate(buf, "base", errorData{Message: message}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderSuccessWebUI renders the WebUI success page with postMessage.
func RenderSuccessWebUI(provider, state string) (string, error) {
	initTemplates()
	if tmplInitErr != nil {
		return "", tmplInitErr
	}

	buf := ir.GetBuffer()
	defer ir.PutBuffer(buf)
	data := webUIData{Provider: provider, State: state}
	if err := tmplSuccessWU.ExecuteTemplate(buf, "base", data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderErrorWebUI renders the WebUI error page with postMessage.
func RenderErrorWebUI(provider, state, message string) (string, error) {
	initTemplates()
	if tmplInitErr != nil {
		return "", tmplInitErr
	}

	buf := ir.GetBuffer()
	defer ir.PutBuffer(buf)
	data := webUIData{Provider: provider, State: state, Message: message}
	if err := tmplErrorWU.ExecuteTemplate(buf, "base", data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
