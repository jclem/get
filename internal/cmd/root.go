package cmd

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jclem/get/internal/builder"
	"github.com/jclem/get/internal/parser"
	"github.com/jclem/get/internal/sessions"
	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type rootFlags struct {
	HTTPMethod     string `mapstructure:"method"`
	NoColor        bool   `mapstructure:"no-color"`
	Form           bool   `mapstructure:"form"`
	NoSession      bool   `mapstructure:"no-session"`
	SessionName    string `mapstructure:"session"`
	NoHeaders      bool   `mapstructure:"no-headers"`
	NoHighlight    bool   `mapstructure:"no-highlight"`
	NoRedirects    bool   `mapstructure:"no-redirects"`
	MaxRedirects   int    `mapstructure:"max-redirects"`
	NoFormat       bool   `mapstructure:"no-format"`
	NoBody         bool   `mapstructure:"no-body"`
	Stream         bool   `mapstructure:"stream"`
	Debug          bool   `mapstructure:"debug"`
	Verbose        bool   `mapstructure:"verbose"`
	DryRun         bool   `mapstructure:"dry-run"`
	SaveAllHeaders bool   `mapstructure:"save-all-headers"`
}

const (
	flagMethod         = "method"
	flagNoColor        = "no-color"
	flagForm           = "form"
	flagNoSession      = "no-session"
	flagSessionName    = "session"
	flagNoHeaders      = "no-headers"
	flagNoHighlight    = "no-highlight"
	flagNoRedirects    = "no-redirects"
	flagMaxRedirects   = "max-redirects"
	flagNoFormat       = "no-format"
	flagNoBody         = "no-body"
	flagStream         = "stream"
	flagDebug          = "debug"
	flagVerbose        = "verbose"
	flagDryRun         = "dry-run"
	flagSaveAllHeaders = "save-all-headers"
)

// NewRootCmd creates the root Cobra command for the get CLI.
func NewRootCmd() *cobra.Command {
	var flags rootFlags

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

SESSIONS:
By default, get persists a small subset of request headers (currently:
Authorization) between runs, keyed by a session name.

The default session name is the request host; use --session to override, or
-S/--no-session to disable reading and writing.  Sessions are stored at
${XDG_CONFIG_HOME}/get/sessions.json.

Use -A/--save-all-headers to persist all request headers for this run.

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
		PreRun: func(cmd *cobra.Command, _ []string) {
			// Using a new Viper instance allows for parallel testing.
			v := viper.New()

			err := v.BindPFlags(cmd.Flags())
			cobra.CheckErr(err)

			err = v.Unmarshal(&flags)
			cobra.CheckErr(err)

			if flags.SessionName != "" && flags.NoSession {
				cobra.CheckErr(errors.New("session name provided but session is disabled"))
			}

			if cmd.Flags().Changed(flagMaxRedirects) && cmd.Flags().Changed(flagNoRedirects) {
				cobra.CheckErr(errors.New("max redirects and no redirects cannot be used together"))
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if flags.Debug {
				slog.SetLogLoggerLevel(slog.LevelDebug)
			}

			reqURL, err := getURL(args[0])
			cobra.CheckErr(err)

			input, err := parser.ParseInput(args[1:])
			cobra.CheckErr(err)

			sessionManager, err := sessions.NewManager()
			cobra.CheckErr(err)

			sessionName := cmp.Or(flags.SessionName, reqURL.Host)

			var session *sessions.Session
			if !flags.NoSession {
				session = sessionManager.Get(sessionName)
			}

			method, err := getMethod(cmd, flags.HTTPMethod, input.Body != nil)
			cobra.CheckErr(err)

			req, err := builder.Build(ctx, *reqURL, *input,
				builder.WithHTTPMethod(method),
				builder.WithFormBody(flags.Form),
				builder.WithSession(session))
			cobra.CheckErr(err)

			if !flags.NoSession && !flags.DryRun {
				err = sessionManager.WriteRequest(req,
					sessions.WithSaveAllHeaders(flags.SaveAllHeaders),
					sessions.WithSessionName(sessionName))
				cobra.CheckErr(err)
			}

			noColor := os.Getenv("NO_COLOR") != ""
			if cmd.Flags().Changed(flagNoColor) {
				noColor = flags.NoColor
			}

			w := writer.NewWriter(cmd.OutOrStdout(),
				writer.WithColor(!noColor))

			if flags.Verbose || flags.DryRun {
				err := w.WriteRequest(req,
					writer.WithHighlight(!flags.NoHighlight),
					writer.WithFormat(!flags.NoFormat))
				cobra.CheckErr(err)
			}

			if flags.DryRun {
				return
			}

			client := getClient(flags)
			resp, err := client.Do(req)
			cobra.CheckErr(err)
			defer func() { cobra.CheckErr(resp.Body.Close()) }()

			err = w.WriteResponse(resp,
				writer.WithHeaders(!flags.NoHeaders),
				writer.WithBody(!flags.NoBody),
				writer.WithHighlight(!flags.NoHighlight),
				writer.WithFormat(!flags.NoFormat),
				writer.WithStream(flags.Stream))
			cobra.CheckErr(err)
		},
	}

	cmd.Flags().StringP(flagMethod, "X", http.MethodGet, "The HTTP method to use")
	cmd.Flags().BoolP(flagNoColor, "C", false, "Do not use color in the output (NO_COLOR is also respected)")
	cmd.Flags().Bool(flagForm, false, "Format the request body as a form, instead of JSON")
	cmd.Flags().BoolP(flagNoSession, "S", false, "Do not read or save the session")
	cmd.Flags().String(flagSessionName, "", "The name of the session to use")
	cmd.Flags().BoolP(flagNoHeaders, "H", false, "Do not print the response headers")
	cmd.Flags().BoolP(flagNoHighlight, "L", false, "Do not highlight the request/response body")
	cmd.Flags().BoolP(flagNoFormat, "F", false, "Do not format the request/response body")
	cmd.Flags().BoolP(flagNoRedirects, "R", false, "Do not follow redirects")
	cmd.Flags().Int(flagMaxRedirects, 10, "Maximum redirects to follow (0 means no max)")
	cmd.Flags().BoolP(flagNoBody, "B", false, "Do not print the response body")
	cmd.Flags().BoolP(flagStream, "s", false, "Stream the response")
	cmd.Flags().BoolP(flagDebug, "d", false, "Debug mode")
	cmd.Flags().BoolP(flagVerbose, "v", false, "Verbose mode (prints the request)")
	cmd.Flags().Bool(flagDryRun, false, "Dry-run mode (prints the request without sending it)")
	cmd.Flags().BoolP(flagSaveAllHeaders, "A", false, "Save all headers to the session")

	// Subcommands
	cmd.AddCommand(NewSessionsCmd())

	return cmd
}

func getMethod(cmd *cobra.Command, methodFlag string, hasBody bool) (string, error) {
	if !cmd.Flags().Changed(flagMethod) && hasBody {
		return http.MethodPost, nil
	}

	method := strings.ToUpper(methodFlag)

	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return method, nil
	}

	return "", fmt.Errorf("invalid method: %s", methodFlag)
}

func getURL(arg string) (*url.URL, error) {
	var urlStr string
	switch {
	case strings.HasPrefix(arg, ":"): // Arg is just a port; use localhost.
		urlStr = "http://localhost" + arg
	case strings.HasPrefix(arg, "localhost"): // Add http:// to the beginning of localhost.
		urlStr = "http://" + arg
	case strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://"): // Arg is already a valid URL.
		urlStr = arg
	default: // Arg is just a domain; use https.
		urlStr = "https://" + arg
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	return u, nil
}

func getClient(flags rootFlags) *http.Client {
	client := *http.DefaultClient

	if flags.NoRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		switch flags.MaxRedirects {
		case 0:
			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return nil }
		default:
			client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
				if len(via) > flags.MaxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			}
		}
	}

	return &client
}
