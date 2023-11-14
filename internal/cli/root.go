package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jclem/get/internal/session"
	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
)

var isHeaderOpt = regexp.MustCompile(`^[a-zA-Z0-9-]+:.+$`)

const flagNoBody = "no-body"
const flagNoHeaders = "no-headers"
const flagNoSession = "no-session"
const flagMethod = "method"
const flagVerbose = "verbose"
const flagData = "data"

var rootCmd = &cobra.Command{
	Use:   "get <url>",
	Short: "Get is a command-line interface for making HTTP requests",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		out := writer.NewWriter(cmd.OutOrStdout())

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

		req, err := http.NewRequestWithContext(cmd.Context(), method, url, strings.NewReader(data))
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
		}

		noSession, err := cmd.Flags().GetBool(flagNoSession)
		if err != nil {
			return fmt.Errorf("could not get no-session flag: %w", err)
		}

		if len(args[1:]) > 0 {
			for _, arg := range args[1:] {
				if !isHeaderOpt.MatchString(arg) {
					continue
				}

				parts := strings.SplitN(arg, ":", 2)
				req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}

			if !noSession {
				if err := session.WriteSession(req); err != nil {
					return fmt.Errorf("could not write session: %w", err)
				}
			}
		}

		if !noSession {
			ssn, err := session.ReadSession(req)
			if err != nil && !errors.Is(err, session.ErrNoSession) {
				return fmt.Errorf("could not read session: %w", err)
			}

			if ssn != nil {
				for k, v := range ssn.Headers {
					for _, v := range v {
						req.Header.Set(k, v)
					}
				}
			}
		}

		verbose, err := cmd.Flags().GetBool(flagVerbose)
		if err != nil {
			return fmt.Errorf("could not get verbose flag: %w", err)
		}

		if verbose {
			if err := out.PrintRequest(req); err != nil {
				return fmt.Errorf("could not print request: %w", err)
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

		noBody, err := cmd.Flags().GetBool(flagNoBody)
		if err != nil {
			return fmt.Errorf("could not get no-body flag: %w", err)
		}

		if err := out.PrintResponse(resp, writer.WithHeaders(!noHeaders), writer.WithBody(!noBody)); err != nil {
			return fmt.Errorf("could not print response: %w", err)
		}

		return nil
	},
}

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
