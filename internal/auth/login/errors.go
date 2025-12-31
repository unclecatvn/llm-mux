package login

import (
	"fmt"

	"github.com/nghyane/llm-mux/internal/interfaces"
)

type ProjectSelectionError struct {
	Email    string
	Projects []interfaces.GCPProjectProjects
}

func (e *ProjectSelectionError) Error() string {
	if e == nil {
		return "cliproxy auth: project selection required"
	}
	return fmt.Sprintf("cliproxy auth: project selection required for %s", e.Email)
}

func (e *ProjectSelectionError) ProjectsDisplay() []interfaces.GCPProjectProjects {
	if e == nil {
		return nil
	}
	return e.Projects
}

type EmailRequiredError struct {
	Prompt string
}

func (e *EmailRequiredError) Error() string {
	if e == nil || e.Prompt == "" {
		return "cliproxy auth: email is required"
	}
	return e.Prompt
}
