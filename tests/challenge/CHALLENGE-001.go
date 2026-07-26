// Challenge case: constant-path delete in Cleanup method.
// Seeded from anthropic-sdk-go skills.go:65.
// See CHALLENGE-001.yml for metadata.

package main

import (
	"os"
	"path/filepath"

	"github.com/anthropics/anthropic-sdk-go"
)

type AgentToolContext struct {
	Workdir string
}

// Cleanup removes the skills subdirectory under Workdir.
// The path is a compile-time constant ("skills") joined onto a
// server-configured value — no model-controlled input reaches it.
func (e *AgentToolContext) Cleanup() error {
	if e.Workdir == "" {
		return nil
	}
	return os.RemoveAll(filepath.Join(e.Workdir, "skills"))
}
