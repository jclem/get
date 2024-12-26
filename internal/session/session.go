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

var configHome = os.Getenv("XDG_DATA_HOME")              //nolint:gochecknoglobals
var configDir = path.Join(configHome, "get")             //nolint:gochecknoglobals
var sessionsPath = path.Join(configDir, "sessions.json") //nolint:gochecknoglobals

// SessionsPath returns the path to the sessions configuration file.
func SessionsPath() string {
	return sessionsPath
}

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
	Scheme  string              `json:"scheme"`
}

// New returns a new empty session.
func New() *Session {
	return &Session{
		Headers: make(map[string][]string),
		Scheme:  "",
	}
}

// ErrNoSession is returned when a session does not exist for a given host.
var ErrNoSession = errors.New("no session")

// ReadSession reads a session from the configuration file for the given
// request.
//
// When no session is found an empty session and ErrNoSession are returned.
func ReadSession(name string) (*Session, error) {
	cfg, err := ReadConfig()
	if err != nil {
		return nil, err
	}

	ssn, ok := cfg.Sessions[name]
	if !ok {
		return New(), ErrNoSession
	}

	return &ssn, nil
}

var writableHeaders = map[string]struct{}{ //nolint:gochecknoglobals
	http.CanonicalHeaderKey("Authorization"): {},
}

// IsWritableHeader returns whether or not a header is writable.
func IsWritableHeader(h string) bool {
	can := http.CanonicalHeaderKey(h)

	_, ok := writableHeaders[can]
	return ok
}

// WriteSessionOpts are options for writing a session.
type WriteSessionOpts struct {
	// SaveAllHeaders specifies whether or not all headers should be saved.
	SaveAllHeaders bool
}

// WriteSession writes a session to the configuration file for the given
// request.
func WriteSession(name string, req *http.Request, opts WriteSessionOpts) error {
	cfg, err := ReadConfig()
	if err != nil {
		return err
	}

	sess, ok := cfg.Sessions[name]
	if !ok {
		sess = *New()
		cfg.Sessions[name] = sess
	}

	for k, v := range req.Header {
		if IsWritableHeader(k) || opts.SaveAllHeaders {
			sess.Headers[k] = v
		}
	}

	if req.URL.Scheme == "http" {
		sess.Scheme = "http"
	}

	cfg.Sessions[name] = sess

	return WriteConfig(cfg)
}

// ReadConfig returns the configuration file.
func ReadConfig() (*Config, error) {
	// Create the config directory if it doesn't exist.
	if _, err := os.Stat(configDir); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat config directory: %w", err)
		}

		if err := os.MkdirAll(configDir, 0o700); err != nil { //nolint:mnd // 700 is the correct mode
			return nil, fmt.Errorf("create config directory: %w", err)
		}
	}

	// Create the file if it doesn't exist.
	if _, err := os.Stat(sessionsPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat sessions file: %w", err)
		}

		cfg := newConfig()
		if err := WriteConfig(&cfg); err != nil {
			return nil, err
		}
	}

	// Read the file.
	b, err := os.ReadFile(sessionsPath)
	if err != nil {
		return nil, fmt.Errorf("read sessions file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal sessions file: %w", err)
	}

	return &cfg, nil
}

// WriteConfig writes the configuration file.
func WriteConfig(cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(sessionsPath, b, 0o600); err != nil { //nolint:mnd // 600 is the correct mode
		return fmt.Errorf("write sessions file: %w", err)
	}

	return nil
}
