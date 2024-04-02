package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jclem/get/internal/config"
	"github.com/jclem/get/internal/parser"
	"github.com/jclem/get/internal/session"
	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
)

type flags struct {
	NoBody         bool   `mapstructure:"no-body"`
	NoHeaders      bool   `mapstructure:"no-headers"`
	NoSession      bool   `mapstructure:"no-session"`
	SessionName    string `mapstructure:"session"`
	HTTPMethod     string `mapstructure:"method"`
	Verbose        bool   `mapstructure:"verbose"`
	Data           string `mapstructure:"data"`
	UseHTTP        bool   `mapstructure:"http"`
	UseHTTPS       bool   `mapstructure:"https"`
	NoHighlight    bool   `mapstructure:"no-highlight"`
	StreamResponse bool   `mapstructure:"stream"`
	FormBody       bool   `mapstructure:"form"`
	SaveAllHeaders bool   `mapstructure:"save-all-headers"`
}

const (
	flagNoBody         = "no-body"
	flagNoHeaders      = "no-headers"
	flagNoSession      = "no-session"
	flagSession        = "session"
	flagMethod         = "method"
	flagVerbose        = "verbose"
	flagData           = "data"
	flagHTTP           = "http"
	flagHTTPS          = "https"
	flagNoHighlight    = "no-highlight"
	flagStream         = "stream"
	flagForm           = "form"
	flagSaveAllHeaders = "save-all-headers"
)

var rootCmd = &cobra.Command{
	Use:   "get <url> [request-options]",
	Short: "Get is a command-line interface for making HTTP requests",
	Long: `Get is a command-line interface for making HTTP requests.

It accepts a URL and a list of request options, and makes an HTTP request to the
specified URL. The request options can be used to specify headers, query
parameters, and a request body.

## Request Options

### Headers

HTTP headers are specified using Key:Value syntax. For example, to specify a
header named "Accept" with a value of "application/json", you would use:

    get example.com accept:application/json
	
Note that HTTP header names are canonicalized automatically, so "Accept" would
be sent, in this case, not "accept".

### Query Parameters

Query parameters are specified using Key==Value syntax. For example, to specify
a query parameter named "q" with a value of "foo", you would use:

	get example.com q==foo

### Request Body

Request bodies can be specified using the format "<path>[:]=<value>". For example,
to specify a request body of '{"foo":"bar"}', you would use:

	get example.com foo=bar

The value is parsed as a string, unless a colon is present, in which case the
value is parsed as JSON. For example, to specify a request body of
'{"foo": true}', you would use:

	get example.com foo:=true

Paths can be used to specify more complex request bodies, and they can be nested.

	foo[bar]=baz // {"foo":{"bar":"baz"}} Sets an object value.
	foo[]=bar    // {"foo":["bar"]} Pushes a value onto an array.
	foo[1]=bar   // {"foo":[null,"bar"]} Sets a value at a specific index in an array.

As a more complex example:

	get example.com foo[bar][baz]=qux foo[quux][]:='{"corge":"grault"}' foo[quux][0][graply]=waldo

Would result in the following request body:

	{
		"foo": {
			"bar": {
				"baz": "qux"
			},
			"quux": [
				{
					"corge": "grault",
					"graply": "waldo"
				}
			]
		}
	}
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Read our request configuration flags.
		f, err := loadAndValidateFlags()
		if err != nil {
			return err
		}

		// Read our config file.
		cfg, err := config.Read()
		if err != nil {
			return fmt.Errorf("could not read config: %w", err)
		}

		// First, do some basic URL parsing.
		userProvidedScheme := strings.HasPrefix(args[0], "http://") || strings.HasPrefix(args[0], "https://")
		reqURL, err := getBaseURL(args[0])
		if err != nil {
			return err
		}

		if reqURL.Hostname() == "" {
			reqURL.Host = fmt.Sprintf("%s:%s", cfg.FallbackHostname, reqURL.Port())
		}

		// Load the session, or use an empty one.
		ssn, err := loadSession(f, reqURL)
		if err != nil {
			return err
		}

		// Set our URL scheme, if the user didn't provide one, using flags or
		// the session.
		if !userProvidedScheme {
			if f.UseHTTP {
				reqURL.Scheme = "http"
			} else if f.UseHTTPS {
				reqURL.Scheme = "https"
			} else if ssn.Scheme != "" {
				reqURL.Scheme = ssn.Scheme
			} else if slices.Contains(cfg.HTTPHostnames, reqURL.Hostname()) {
				reqURL.Scheme = "http"
			} else {
				reqURL.Scheme = "https"
			}
		}

		// Load and parse our non-flag inputs.
		input, err := parser.ParseInput(args[1:])
		if err != nil {
			return fmt.Errorf("could not parse input: %w", err)
		}

		// Validate that we don't have both input data and a data flag.
		data := f.Data
		if data != "" && input.Body != nil {
			return errors.New("cannot specify both data and body")
		}

		// If given input body, marshal it as JSON or form data.
		if input.Body != nil {
			if f.FormBody {
				data, err = marshalFormBody(input.Body)
				if err != nil {
					return err
				}
			} else {
				b, err := json.Marshal(input.Body)
				if err != nil {
					return fmt.Errorf("could not marshal body: %w", err)
				}

				data = string(b)
			}
		}

		// Get our HTTP method (or default).
		method, err := getMethod(f.HTTPMethod, cmd.Flags().Changed(flagMethod), data != "")
		if err != nil {
			return err
		}

		// Create our request.
		req, err := http.NewRequestWithContext(cmd.Context(), method, reqURL.String(), strings.NewReader(data))
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
		}

		// First, set any headers from the session.
		for k, v := range ssn.Headers {
			for _, v := range v {
				req.Header.Set(k, v)
			}
		}

		// Then, overwrite using any headers from the input.
		for _, header := range input.Headers {
			req.Header.Set(header.Name, header.Value)
		}

		// Set content-type if it's not set and we have data.
		if req.Header.Get("content-type") == "" && data != "" {
			if f.FormBody {
				req.Header.Set("content-type", "application/x-www-form-urlencoded")
			} else {
				req.Header.Set("content-type", "application/json")
			}
		}

		// Set the host header if it's not set.
		if req.Header.Get("host") == "" {
			req.Header.Set("host", reqURL.Host)
		}

		// Set our query parameters.
		query := req.URL.Query()
		for _, qp := range input.QueryParams {
			query.Add(qp.Name, qp.Value)
		}
		req.URL.RawQuery = query.Encode()

		// Create a request/response writer struct.
		out := writer.NewWriter(cmd.OutOrStdout())

		// Print our request, if we need to.
		if f.Verbose {
			if err := out.PrintRequest(req, writer.WithHighlight(!f.NoHighlight)); err != nil {
				return fmt.Errorf("could not print request: %w", err)
			}
		}

		// Make our request.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not make request: %w", err)
		}

		defer func() {
			if cerr := resp.Body.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()

		// Print our response.
		if err := out.PrintResponse(resp,
			writer.WithHeaders(!f.NoHeaders),
			writer.WithBody(!f.NoBody),
			writer.WithHighlight(!f.NoHighlight),
			writer.WithStream(f.StreamResponse),
		); err != nil {
			return fmt.Errorf("could not print response: %w", err)
		}

		// Lastly, write the session if we need to.
		shouldWriteSession := f.UseHTTP // Write the session if the user specified non-default protocol.
		for _, header := range input.Headers {
			if session.IsWritableHeader(header.Name) || f.SaveAllHeaders {
				shouldWriteSession = true
				break
			}
		}

		if !f.NoSession && shouldWriteSession {
			if err := session.WriteSession(f.SessionName, req, session.WriteSessionOpts{SaveAllHeaders: f.SaveAllHeaders}); err != nil {
				return fmt.Errorf("could not write session: %w", err)
			}
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
	rootCmd.Flags().Bool(flagHTTP, false, "Use HTTP instead of HTTPS, regardless of session configuration")
	rootCmd.Flags().Bool(flagHTTPS, false, "Use HTTPS instead of HTTP, regardless of session configuration")
	rootCmd.Flags().StringP(flagSession, "s", "", "Session name to use (defaults to URL host)")
	rootCmd.Flags().Bool(flagNoHighlight, false, "Do not format or highlight input or output")
	rootCmd.Flags().BoolP(flagStream, "t", false, "Stream the response body (implies --no-highlight of output)")
	rootCmd.Flags().Bool(flagForm, false, "Send input as form data instead of JSON")
	rootCmd.Flags().Bool(flagSaveAllHeaders, false, "Save all request headers to the session")

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		return fmt.Errorf("could not bind flags: %w", err)
	}

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

func getMethod(method string, methodChanged bool, hasData bool) (string, error) {
	method = strings.ToUpper(method)

	if !methodChanged && hasData {
		method = http.MethodPost
	}

	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return method, nil
	default:
		return "", newUnknownMethodError(method)
	}
}

func loadAndValidateFlags() (*flags, error) {
	var f flags
	if err := viper.Unmarshal(&f); err != nil {
		return nil, fmt.Errorf("could not unmarshal flags: %w", err)
	}

	if f.UseHTTP && f.UseHTTPS {
		return nil, errors.New("cannot specify both --http and --https")
	}

	return &f, nil
}

func loadSession(f *flags, reqURL *url.URL) (*session.Session, error) {
	ssn := session.NewSession()
	if !f.NoSession {
		if f.SessionName == "" {
			f.SessionName = reqURL.Host
		}

		readSSN, err := session.ReadSession(f.SessionName)
		if err != nil && !errors.Is(err, session.ErrNoSession) {
			return nil, fmt.Errorf("could not read session: %w", err)
		}
		ssn = readSSN
	}

	return ssn, nil
}

func getBaseURL(input string) (*url.URL, error) {
	urlArg := input
	userProvidedScheme := strings.HasPrefix(urlArg, "https://") || strings.HasPrefix(urlArg, "http://")

	if !userProvidedScheme {
		// We'll set the real scheme later, but we need to set something here so
		// that we can parse out the hostname.
		urlArg = "https://" + urlArg
	}

	reqURL, err := url.Parse(urlArg)
	if err != nil {
		return nil, fmt.Errorf("could not parse URL: %w", err)
	}

	return reqURL, nil
}

func marshalFormBody(input any) (string, error) {
	form := url.Values{}
	m, ok := input.(map[string]any)
	if !ok {
		return "", errors.New("form body must be an object")
	}

	for k, v := range m {
		switch vs := v.(type) {
		case string:
			form.Add(k, vs)
		case []any:
			for _, v := range vs {
				vs, ok := v.(string)
				if !ok {
					return "", errors.New("form body values must be string or string arrays")
				}

				form.Add(k, vs)
			}
		default:
			return "", errors.New("form body values must be string or string arrays")
		}
	}

	return form.Encode(), nil
}
