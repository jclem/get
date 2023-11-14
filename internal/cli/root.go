package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var isHeaderOpt = regexp.MustCompile(`^[a-zA-Z0-9-]+:.+$`)

var rootCmd = &cobra.Command{
	Use:   "get <url>",
	Short: "Get is a command-line interface for making HTTP requests",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		url := args[0]

		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			url = "https://" + url
		}

		method, err := getMethod(cmd)
		if err != nil {
			return err
		}

		data, err := cmd.Flags().GetString(flagData)
		if err != nil {
			return fmt.Errorf("could not get data flag: %w", err)
		}

		var bodyReader io.Reader
		if data != "" {
			bodyReader = strings.NewReader(data)
		}

		req, err := http.NewRequestWithContext(cmd.Context(), method, url, bodyReader)
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
		}

		noSession, err := cmd.Flags().GetBool(flagNoSession)
		if err != nil {
			return fmt.Errorf("could not get no-session flag: %w", err)
		}

		wroteHeader := false

		if len(args[1:]) > 0 {
			for _, arg := range args[1:] {
				if !isHeaderOpt.MatchString(arg) {
					continue
				}

				wroteHeader = true
				parts := strings.SplitN(arg, ":", 2)
				req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}

			if wroteHeader && !noSession {
				if err := writeSession(req); err != nil {
					return err
				}
			}
		}

		if !noSession && !wroteHeader {
			ssn, err := readSession(req)
			if err != nil && !errors.Is(err, errNoSession) {
				return err
			}

			if ssn != nil {
				for k, v := range ssn.Headers {
					for _, v := range v {
						req.Header.Add(k, v)
					}
				}
			}
		}

		verbose, err := cmd.Flags().GetBool(flagVerbose)
		if err != nil {
			return fmt.Errorf("could not get verbose flag: %w", err)
		}

		if verbose {
			if _, err := color.New(color.FgGreen).
				Fprintf(cmd.OutOrStdout(), "%s %s %s\n", req.Method, req.URL.Path, req.Proto); err != nil {
				return fmt.Errorf("could not write response proto: %w", err)
			}

			for k, v := range req.Header {
				if _, err := color.New(color.FgRed).Fprintf(cmd.OutOrStdout(), "%s: ", k); err != nil {
					return fmt.Errorf("could not write response header: %w", err)
				}

				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", strings.Join(v, ", ")); err != nil {
					return fmt.Errorf("could not write response header: %w", err)
				}
			}

			if data != "" {
				if _, err := color.New(color.FgBlue).Fprintf(cmd.OutOrStdout(), "\n%s\n", data); err != nil {
					return fmt.Errorf("could not write request body: %w", err)
				}
			}

			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("could not write newline: %w", err)
			}
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not make request: %w", err)
		}

		defer func() {
			if cerr := resp.Body.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()

		noHeaders, err := cmd.Flags().GetBool(flagNoHeaders)
		if err != nil {
			return fmt.Errorf("could not get no-headers flag: %w", err)
		}

		if !noHeaders {
			if _, err := color.New(color.FgGreen).Fprintf(cmd.OutOrStdout(), "%s %s\n", resp.Proto, resp.Status); err != nil {
				return fmt.Errorf("could not write response proto: %w", err)
			}

			for k, v := range resp.Header {
				if _, err := color.New(color.FgRed).Fprintf(cmd.OutOrStdout(), "%s: ", k); err != nil {
					return fmt.Errorf("could not write response header: %w", err)
				}

				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", strings.Join(v, ", ")); err != nil {
					return fmt.Errorf("could not write response header: %w", err)
				}
			}

			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("could not write newline: %w", err)
			}
		}

		noBody, err := cmd.Flags().GetBool(flagNoBody)
		if err != nil {
			return fmt.Errorf("could not get no-body flag: %w", err)
		}

		if !noBody {
			if _, err := io.Copy(cmd.OutOrStdout(), resp.Body); err != nil {
				return fmt.Errorf("could not write response body: %w", err)
			}
		}

		return nil
	},
}

const flagNoBody = "no-body"
const flagNoHeaders = "no-headers"
const flagNoSession = "no-session"
const flagMethod = "method"
const flagVerbose = "verbose"
const flagData = "data"

// Execute runs the root command.
func Execute(ctx context.Context) error {
	rootCmd.Flags().BoolP(flagNoBody, "B", false, "Do not print the response body")
	rootCmd.Flags().BoolP(flagNoHeaders, "H", false, "Do not print the response headers")
	rootCmd.Flags().BoolP(flagNoSession, "S", false, "Do not use a stored session if one exists for this host")
	rootCmd.Flags().StringP(flagMethod, "X", http.MethodGet, "HTTP method to use")
	rootCmd.Flags().BoolP(flagVerbose, "v", false, "Print verbose output")
	rootCmd.Flags().StringP(flagData, "d", "", "Data to send in the request body")

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("could not execute root command: %w", err)
	}

	return nil
}

type unknownMethodError struct {
	Method string
}

func (e *unknownMethodError) Error() string {
	return fmt.Sprintf("unknown method: %q", e.Method)
}

func newUnknownMethodError(method string) error {
	return &unknownMethodError{Method: method}
}

func getMethod(cmd *cobra.Command) (string, error) {
	method, err := cmd.Flags().GetString(flagMethod)
	if err != nil {
		return "", fmt.Errorf("could not get method flag: %w", err)
	}

	method = strings.ToUpper(method)

	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return method, nil
	default:
		return "", newUnknownMethodError(method)
	}
}

type config struct {
	Sessions map[string]session `json:"sessions"`
}

type session struct {
	Headers map[string][]string `json:"headers"`
}

var configHome = os.Getenv("XDG_DATA_HOME")
var configDir = path.Join(configHome, "get")
var sessionsPath = path.Join(configDir, "sessions.json")

func getConfiguration() (*config, error) {
	configHome := os.Getenv("XDG_DATA_HOME")
	configDir := path.Join(configHome, "get")
	sessionsPath := path.Join(configDir, "sessions.json")

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

		cfg := config{Sessions: map[string]session{}}
		b, err := json.Marshal(cfg)
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

	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("could not unmarshal sessions file: %w", err)
	}

	return &cfg, nil
}

var errNoSession = errors.New("no session")

func readSession(req *http.Request) (*session, error) {
	cfg, err := getConfiguration()
	if err != nil {
		return nil, err
	}

	ssn, ok := cfg.Sessions[req.URL.Host]
	if !ok {
		return nil, errNoSession
	}

	return &ssn, nil
}

func writeSession(req *http.Request) error {
	cfg, err := getConfiguration()
	if err != nil {
		return err
	}

	// Find the session, if it exists.
	sess, ok := cfg.Sessions[req.URL.Host]
	if !ok {
		sess = session{
			Headers: make(map[string][]string),
		}
	}

	// Replace the headers in the session.
	sess.Headers = make(map[string][]string)

	for k, v := range req.Header {
		sess.Headers[k] = v
	}

	// Write the session.
	cfg.Sessions[req.URL.Host] = sess

	// Write the file.
	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("could not marshal config: %w", err)
	}

	if err := os.WriteFile(sessionsPath, b, 0o600); err != nil {
		return fmt.Errorf("could not write sessions file: %w", err)
	}

	return nil
}
