// Package sessions provides persistence of HTTP requests for a given URL.
package sessions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// A Session represents a single session configuration.
type Session struct {
	Headers map[string][]string `json:"headers"`
}

// NewSession creates a new Session.
func NewSession() *Session {
	return &Session{
		Headers: make(map[string][]string),
	}
}

type sessionsFile struct {
	Sessions map[string]Session `json:"sessions"`
}

// A Manager manages sessions data.
type Manager struct {
	sessions        map[string]Session
	path            string
	writableHeaders map[string]struct{}
}

// NewManager creates a new Sessions.
func NewManager() (*Manager, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	configDir := filepath.Join(configHome, "get")
	sessionsPath := filepath.Join(configDir, "sessions.json")

	if _, err := os.Stat(configDir); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat sessions path: %w", err)
		}

		if err := os.MkdirAll(configDir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir all config dir: %w", err)
		}
	}

	manager := Manager{
		sessions: make(map[string]Session),
		path:     sessionsPath,
		writableHeaders: map[string]struct{}{
			http.CanonicalHeaderKey("Authorization"): {},
		},
	}

	if _, err := os.Stat(sessionsPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat sessions path: %w", err)
		}

		if err := manager.Write(); err != nil {
			return nil, fmt.Errorf("write sessions: %w", err)
		}

		return &manager, nil
	}

	b, err := os.ReadFile(manager.path)
	if err != nil {
		return nil, fmt.Errorf("read sessions path: %w", err)
	}

	var sessionsFile sessionsFile
	if err := json.Unmarshal(b, &sessionsFile); err != nil {
		return nil, fmt.Errorf("unmarshal sessions: %w", err)
	}

	manager.sessions = sessionsFile.Sessions

	return &manager, nil
}

// Write writes the sessions to the sessions file.
func (m *Manager) Write() error {
	b, err := json.MarshalIndent(sessionsFile{Sessions: m.sessions}, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal sessions: %w", err)
	}

	if err := os.WriteFile(m.path, b, 0o600); err != nil {
		return fmt.Errorf("write sessions: %w", err)
	}

	return nil
}

// WriteRequest writes the session for a given request.
func (m *Manager) WriteRequest(r *http.Request) error {
	session := m.Get(r.URL.Host)
	if session == nil {
		session = NewSession()
	}

	for k, v := range r.Header {
		if _, ok := m.writableHeaders[http.CanonicalHeaderKey(k)]; ok {
			session.Headers[k] = v
		}
	}

	m.sessions[r.URL.Host] = *session

	if err := m.Write(); err != nil {
		return err
	}

	return nil
}

// Get gets a session for a given host (or host:port).
func (m *Manager) Get(host string) *Session {
	session, ok := m.sessions[host]
	if !ok {
		return nil
	}

	return &session
}
