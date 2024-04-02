package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
)

var configHome = os.Getenv("XDG_CONFIG_HOME")
var configDir = path.Join(configHome, "get")
var configPath = path.Join(configDir, "config.json")

// A Config represents configuration for the get CLI.
type Config struct {
	// FallbackHostname is the hostname to use when no hostname is specified (for
	// example, if the host is simply ":3000").
	FallbackHostname string `json:"fallback_hostname"`
	// HTTPHostnames is a list of hostnames that are considered HTTP hostnames.
	// By default, these hosts will use HTTP unless otherwise noted in a session.
	HTTPHostnames []string `json:"http_hostnames"`
}

func newConfig() Config {
	return Config{HTTPHostnames: make([]string, 0)}
}

// Read returns the configuration file.
func Read() (*Config, error) {
	// Read the file.
	b, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := newConfig()
			return &cfg, nil
		}

		return nil, fmt.Errorf("could not read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("could not unmarshal config file: %w", err)
	}

	return &cfg, nil
}
