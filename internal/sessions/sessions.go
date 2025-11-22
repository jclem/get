// Package sessions provides lightweight persistence of selected request headers
// across runs, keyed by a session name (defaults to the request host). Sessions
// are stored at ${XDG_CONFIG_HOME}/get/sessions.json and currently only persist
// a subset of headers (e.g., Authorization) by default.
package sessions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// WithSessionsPath sets the path to the sessions file.
func WithSessionsPath(s string) func(*Manager) {
	return func(o *Manager) {
		o.path = s
	}
}

// NewManager creates a new Sessions.
func NewManager(mOpts ...func(*Manager)) (*Manager, error) {
	manager := Manager{
		sessions: make(map[string]Session),
		path:     "",
		writableHeaders: map[string]struct{}{
			http.CanonicalHeaderKey("Authorization"): {},
		},
	}

	for _, opt := range mOpts {
		opt(&manager)
	}

	if manager.path == "" { //nolint:nestif // easier to nest this
		configHome := os.Getenv("XDG_CONFIG_HOME")
		configDir := filepath.Join(configHome, "get")
		manager.path = filepath.Join(configDir, "sessions.json")

		if _, err := os.Stat(configDir); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("stat sessions path: %w", err)
			}

			if err := os.MkdirAll(configDir, 0o700); err != nil {
				return nil, fmt.Errorf("mkdir all config dir: %w", err)
			}
		}
	}

	if _, err := os.Stat(manager.path); err != nil {
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

// Path returns the full path to the sessions file on disk.
func (m *Manager) Path() string {
	return m.path
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

// GetAll returns a deep copy of all sessions. If reveal is false, header values
// are redacted by replacing each value with asterisks of the same length.
func (m *Manager) GetAll(reveal bool) map[string]Session {
	out := make(map[string]Session, len(m.sessions))
	for name, sess := range m.sessions {
		out[name] = copySession(sess, reveal)
	}
	return out
}

// Delete removes a session by name and persists the change.
func (m *Manager) Delete(name string) error {
	if _, ok := m.sessions[name]; !ok {
		return fmt.Errorf("session not found: %s", name)
	}
	delete(m.sessions, name)
	if err := m.Write(); err != nil {
		return err
	}
	return nil
}

func copySession(s Session, reveal bool) Session {
	headers := make(map[string][]string, len(s.Headers))
	for k, vals := range s.Headers {
		// Copy the slice
		dst := make([]string, len(vals))
		for i, v := range vals {
			if reveal {
				dst[i] = v
				continue
			}
			dst[i] = strings.Repeat("*", len(v))
		}
		headers[http.CanonicalHeaderKey(k)] = dst
	}
	return Session{Headers: headers}
}

// Clear removes all sessions and persists the change.
func (m *Manager) Clear() error {
	m.sessions = make(map[string]Session)
	if err := m.Write(); err != nil {
		return err
	}
	return nil
}

type writeRequestOpts struct {
	saveAllHeaders bool
	sessionName    string
}

// WithSaveAllHeaders sets whether to save all headers to the session.
func WithSaveAllHeaders(b bool) func(*writeRequestOpts) {
	return func(o *writeRequestOpts) {
		o.saveAllHeaders = b
	}
}

// WithSessionName sets the session name to use.
func WithSessionName(s string) func(*writeRequestOpts) {
	return func(o *writeRequestOpts) {
		o.sessionName = s
	}
}

// WriteRequest writes the session for a given request.
func (m *Manager) WriteRequest(r *http.Request, writeOpts ...func(*writeRequestOpts)) error {
	opts := writeRequestOpts{
		saveAllHeaders: false,
		sessionName:    r.URL.Host,
	}

	for _, opt := range writeOpts {
		opt(&opts)
	}

	session := m.Get(opts.sessionName)
	if session == nil {
		session = NewSession()
	}

	for k, v := range r.Header {
		if opts.saveAllHeaders {
			session.Headers[k] = v
			continue
		}

		if _, ok := m.writableHeaders[http.CanonicalHeaderKey(k)]; ok {
			session.Headers[k] = v
		}
	}

	// If no headers were saved, don't persist the session.
	if len(session.Headers) == 0 {
		return nil
	}

	m.sessions[opts.sessionName] = *session

	if err := m.Write(); err != nil {
		return err
	}

	return nil
}

// Get gets a session for a given session name.
func (m *Manager) Get(sessionName string) *Session {
	session, ok := m.sessions[sessionName]
	if !ok {
		return nil
	}

	return &session
}
