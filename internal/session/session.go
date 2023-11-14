// Package session manages the session configuration for a given host.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
)

var configHome = os.Getenv("XDG_DATA_HOME")
var configDir = path.Join(configHome, "get")
var sessionsPath = path.Join(configDir, "sessions.json")

// A Config represents the overall configuration file that stores all sessions.
type Config struct {
	Sessions map[string]Session `json:"sessions"`
}

func newConfig() Config {
	return Config{Sessions: map[string]Session{}}
}

// A Session represents a single session configuration.
type Session struct {
	Headers map[string][]string `json:"headers"`
}

func newSession() Session {
	return Session{Headers: make(map[string][]string)}
}

// ErrNoSession is returned when a session does not exist for a given host.
var ErrNoSession = errors.New("no session")

// ReadSession reads a session from the configuration file for the given
// request.
func ReadSession(r *http.Request) (*Session, error) {
	cfg, err := getConfiguration()
	if err != nil {
		return nil, err
	}

	ssn, ok := cfg.Sessions[r.URL.Host]
	if !ok {
		return nil, ErrNoSession
	}

	return &ssn, nil
}

var writableHeaders = map[string]struct{}{
	http.CanonicalHeaderKey("authorization"): {},
}

// IsWritableHeader returns whether or not a header is writable.
func IsWritableHeader(h string) bool {
	can := http.CanonicalHeaderKey(h)

	_, ok := writableHeaders[can]
	return ok
}

// WriteSession writes a session to the configuration file for the given
// request.
func WriteSession(req *http.Request) error {
	cfg, err := getConfiguration()
	if err != nil {
		return err
	}

	sess, ok := cfg.Sessions[req.URL.Host]
	if !ok {
		sess = newSession()
	}

	for k, v := range req.Header {
		if IsWritableHeader(k) {
			sess.Headers[k] = v
		}
	}

	cfg.Sessions[req.URL.Host] = sess

	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("could not marshal config: %w", err)
	}

	if err := os.WriteFile(sessionsPath, b, 0o600); err != nil {
		return fmt.Errorf("could not write sessions file: %w", err)
	}

	return nil
}

func getConfiguration() (*Config, error) {
	// Create the config directory if it doesn't exist.
	if _, err := os.Stat(configDir); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("could not stat config directory: %w", err)
		}

		if err := os.MkdirAll(configDir, 0o700); err != nil {
			return nil, fmt.Errorf("could not create config directory: %w", err)
		}
	}

	// Create the file if it doesn't exist.
	if _, err := os.Stat(sessionsPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("could not stat sessions file: %w", err)
		}

		b, err := json.Marshal(newConfig())
		if err != nil {
			return nil, fmt.Errorf("could not marshal config: %w", err)
		}

		if err := os.WriteFile(sessionsPath, b, 0o600); err != nil {
			return nil, fmt.Errorf("could not create sessions file: %w", err)
		}
	}

	// Read the file.
	b, err := os.ReadFile(sessionsPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("could not read sessions file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("could not unmarshal sessions file: %w", err)
	}

	return &cfg, nil
}
