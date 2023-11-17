package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jclem/get/internal/parser"
	"github.com/jclem/get/internal/session"
	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
)

const flagNoBody = "no-body"
const flagNoHeaders = "no-headers"
const flagNoSession = "no-session"
const flagSession = "session"
const flagMethod = "method"
const flagVerbose = "verbose"
const flagData = "data"
const flagHTTP = "http"
const flagNoHighlight = "no-highlight"

var rootCmd = &cobra.Command{
	Use:   "get <url> [header:value] [queryParam==value] [bodyParam=value] [bodyParam:=rawValue]",
	Short: "Get is a command-line interface for making HTTP requests",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		out := writer.NewWriter(cmd.OutOrStdout())

		reqURL := args[0]
		if !strings.HasPrefix(reqURL, "https://") && !strings.HasPrefix(reqURL, "http://") {
			useHTTP, err := cmd.Flags().GetBool(flagHTTP)
			if err != nil {
				return fmt.Errorf("could not get http flag: %w", err)
			}

			if useHTTP {
				reqURL = "http://" + reqURL
			} else {
				reqURL = "https://" + reqURL
			}
		}

		input, err := parser.ParseInput(args[1:])
		if err != nil {
			return fmt.Errorf("could not parse input: %w", err)
		}

		method, err := getMethod(cmd)
		if err != nil {
			return err
		}

		data, err := cmd.Flags().GetString(flagData)
		if err != nil {
			return fmt.Errorf("could not get data flag: %w", err)
		}

		if data != "" && input.Body != nil {
			return errors.New("cannot specify both data and body")
		}

		if input.Body != nil {
			b, err := json.Marshal(input.Body)
			if err != nil {
				return fmt.Errorf("could not marshal body: %w", err)
			}

			data = string(b)
		}

		req, err := http.NewRequestWithContext(cmd.Context(), method, reqURL, strings.NewReader(data))
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
		}

		sessionName, err := cmd.Flags().GetString(flagSession)
		if err != nil {
			return fmt.Errorf("could not get session flag: %w", err)
		}

		if sessionName == "" {
			sessionName = req.URL.Host
		}

		if input.Body != nil {
			if !cmd.Flags().Changed(flagMethod) {
				req.Method = http.MethodPost
			}

			if req.Header.Get("content-type") == "" {
				req.Header.Set("content-type", "application/json")
			}
		}

		noSession, err := cmd.Flags().GetBool(flagNoSession)
		if err != nil {
			return fmt.Errorf("could not get no-session flag: %w", err)
		}

		for _, header := range input.Headers {
			req.Header.Add(header.Name, header.Value)
		}

		var shouldWriteSession bool
		for _, header := range input.Headers {
			if session.IsWritableHeader(header.Name) {
				shouldWriteSession = true
				break
			}
		}

		query := req.URL.Query()
		for _, qp := range input.QueryParams {
			query.Add(qp.Name, qp.Value)
		}
		req.URL.RawQuery = query.Encode()

		if !noSession && shouldWriteSession {
			if err := session.WriteSession(sessionName, req); err != nil {
				return fmt.Errorf("could not write session: %w", err)
			}
		}

		if !noSession {
			ssn, err := session.ReadSession(sessionName)
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

		noHighlight, err := cmd.Flags().GetBool(flagNoHighlight)
		if err != nil {
			return fmt.Errorf("could not get no-highlight flag: %w", err)
		}

		if verbose {
			if err := out.PrintRequest(req, !noHighlight); err != nil {
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
	rootCmd.Flags().Bool(flagHTTP, false, "Use HTTP instead of HTTPS")
	rootCmd.Flags().StringP(flagSession, "s", "", "Session name to use (defaults to URL host)")
	rootCmd.Flags().Bool(flagNoHighlight, false, "Do not format or highlight input or output")

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
