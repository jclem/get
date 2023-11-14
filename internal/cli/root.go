package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "get <url>",
	Short: "Get is a command-line interface for making HTTP requests",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		url := args[0]

		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			url = "https://" + url
		}

		method, err := getMethod(cmd)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(cmd.Context(), method, url, nil)
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
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

		noHeaders, err := cmd.Flags().GetBool("no-headers")
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
		}

		noBody, err := cmd.Flags().GetBool("no-body")
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

// Execute runs the root command.
func Execute(ctx context.Context) error {
	rootCmd.Flags().BoolP("no-body", "B", false, "Do not print the response body")
	rootCmd.Flags().BoolP("no-headers", "H", false, "Do not print the response headers")
	rootCmd.Flags().StringP("method", "X", http.MethodGet, "HTTP method to use")

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
	method, err := cmd.Flags().GetString("method")
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
