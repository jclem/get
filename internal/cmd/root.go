package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <url> [request-options]",
		Short: "Get is a CLI for making HTTP requests",
		Long: `Get is a CLI tool for making HTTP requests with intelligent URL parsing, method handling, and rich output formatting.

URL PARSING BEHAVIOR:
The tool automatically handles various URL formats to make requests more convenient:

  • Port-only (e.g., ":8080")     → http://localhost:8080
  • localhost (e.g., "localhost:3000") → http://localhost:3000  
  • Full URLs (e.g., "https://api.example.com") → Used as-is
  • Domain-only (e.g., "example.com") → https://example.com

METHOD PARSING:
Use the -X or --method flag to specify the HTTP method.
POST will be used by default if a body is provided and no explicit method is set.

OUTPUT FORMATTING:
The tool provides rich output formatting with syntax highlighting and structured display.
Use the various output control flags to customize what is displayed and how it's formatted.

EXAMPLES:
  # Basic GET request to a domain (defaults to HTTPS)
  get example.com

  # GET request to localhost on port 8080
  get :8080

  # POST request to an API endpoint
  get -X POST api.example.com/users

  # PUT request with full URL
  get -X PUT https://api.example.com/users/123

  # Request to localhost with explicit hostname
  get localhost:3000/api/health

  # HEAD request to check if resource exists
  get -X HEAD https://example.com/file.txt

  # Disable colors and headers for clean output
  get -C -H api.example.com/data

  # Stream a large response
  get -s https://api.example.com/large-dataset

  # Debug mode for troubleshooting
  get -d -X POST api.example.com/upload`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			debug, err := cmd.Flags().GetBool("debug")
			cobra.CheckErr(err)
			if debug {
				slog.SetLogLoggerLevel(slog.LevelDebug)
			}

			method, err := getMethod(cmd)
			cobra.CheckErr(err)

			url := getURL(args[0])

			req, err := http.NewRequestWithContext(ctx, method, url, nil)
			cobra.CheckErr(err)

			resp, err := http.DefaultClient.Do(req)
			cobra.CheckErr(err)
			defer func() { cobra.CheckErr(resp.Body.Close()) }()

			noColor := os.Getenv("NO_COLOR") != ""
			if cmd.Flags().Changed("no-color") {
				noColor, err = cmd.Flags().GetBool("no-color")
				cobra.CheckErr(err)
			}

			noHeaders, err := cmd.Flags().GetBool("no-headers")
			cobra.CheckErr(err)
			noBody, err := cmd.Flags().GetBool("no-body")
			cobra.CheckErr(err)
			noHighlight, err := cmd.Flags().GetBool("no-highlight")
			cobra.CheckErr(err)
			noFormat, err := cmd.Flags().GetBool("no-format")
			cobra.CheckErr(err)
			stream, err := cmd.Flags().GetBool("stream")
			cobra.CheckErr(err)

			w := writer.NewWriter(cmd.OutOrStdout(),
				writer.WithColor(!noColor))
			err = w.WriteResponse(resp,
				writer.WithHeaders(!noHeaders),
				writer.WithBody(!noBody),
				writer.WithHighlight(!noHighlight),
				writer.WithFormat(!noFormat),
				writer.WithStream(stream))
			cobra.CheckErr(err)
		},
	}

	cmd.Flags().StringP("method", "X", http.MethodGet, "The HTTP method to use")
	cmd.Flags().BoolP("no-color", "C", false, "Do not use color in the output (NO_COLOR is also respected)")
	cmd.Flags().BoolP("no-headers", "H", false, "Do not print the headers")
	cmd.Flags().BoolP("no-highlight", "L", false, "Do not highlight the response")
	cmd.Flags().BoolP("no-format", "F", false, "Do not format the response")
	cmd.Flags().BoolP("no-body", "B", false, "Do not print the body")
	cmd.Flags().BoolP("stream", "s", false, "Stream the response")
	cmd.Flags().BoolP("debug", "d", false, "Debug mode")

	return cmd
}

func getMethod(cmd *cobra.Command) (string, error) {
	methodFlag, err := cmd.Flags().GetString("method")
	cobra.CheckErr(err)

	method := strings.ToUpper(methodFlag)

	switch method {
	case "":
		fallthrough
	case http.MethodConnect:
		fallthrough
	case http.MethodDelete:
		fallthrough
	case http.MethodGet:
		fallthrough
	case http.MethodHead:
		fallthrough
	case http.MethodOptions:
		fallthrough
	case http.MethodPatch:
		fallthrough
	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		fallthrough
	case http.MethodTrace:
		return method, nil
	}

	return "", fmt.Errorf("invalid method: %s", methodFlag)
}

func getURL(arg string) string {
	switch {
	case strings.HasPrefix(arg, ":"): // Arg is just a port; use localhost.
		return "http://localhost" + arg
	case strings.HasPrefix(arg, "localhost"): // Add http:// to the beginning of localhost.
		return "http://" + arg
	case strings.HasPrefix(arg, "http") || strings.HasPrefix(arg, "https"): // Arg is already a valid URL.
		return arg
	default: // Arg is just a domain; use https.
		return "https://" + arg
	}
}
