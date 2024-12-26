package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
)

// A Config represents configuration for the get CLI.
type Config struct {
	// FallbackHostname is the hostname to use when no hostname is specified (for
	// example, if the host is simply ":3000").
	FallbackHostname string `json:"fallback_hostname"`

	// HTTPHostnames is a list of hostnames that are considered HTTP hostnames.
	// By default, these hosts will use HTTP unless otherwise noted in a session.
	HTTPHostnames []string `json:"http_hostnames"`
}

// Read returns the configuration file.
func Read(overridePath string) (*Config, error) {
	readFrom := overridePath
	if readFrom == "" {
		configHome := os.Getenv("XDG_CONFIG_HOME")
		configDir := path.Join(configHome, "get")
		configPath := path.Join(configDir, "config.json")
		readFrom = configPath
	}

	// Read the file.
	b, err := os.ReadFile(readFrom)
	if err != nil {
		if overridePath == "" && errors.Is(err, os.ErrNotExist) {
			cfg := Config{
				FallbackHostname: "localhost",
				HTTPHostnames:    []string{"localhost"},
			}

			return &cfg, nil
		}

		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
