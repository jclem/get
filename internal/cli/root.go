package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jclem/get/internal/parser"
	"github.com/jclem/get/internal/session"
	"github.com/jclem/get/internal/writer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type flags struct {
	NoBody         bool   `mapstructure:"no-body"`
	NoHeaders      bool   `mapstructure:"no-headers"`
	NoSession      bool   `mapstructure:"no-session"`
	Session        string `mapstructure:"session"`
	HTTPMethod     string `mapstructure:"method"`
	Verbose        bool   `mapstructure:"verbose"`
	Data           string `mapstructure:"data"`
	UseHTTP        bool   `mapstructure:"http"`
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
		var f flags
		if err := viper.Unmarshal(&f); err != nil {
			return fmt.Errorf("could not unmarshal flags: %w", err)
		}

		out := writer.NewWriter(cmd.OutOrStdout())

		reqURL := args[0]
		if !strings.HasPrefix(reqURL, "https://") && !strings.HasPrefix(reqURL, "http://") {
			if f.UseHTTP {
				reqURL = "http://" + reqURL
			} else {
				reqURL = "https://" + reqURL
			}
		}

		input, err := parser.ParseInput(args[1:])
		if err != nil {
			return fmt.Errorf("could not parse input: %w", err)
		}

		method, err := getMethod(f.HTTPMethod)
		if err != nil {
			return err
		}

		data := f.Data
		if data != "" && input.Body != nil {
			return errors.New("cannot specify both data and body")
		}

		if input.Body != nil {
			if f.FormBody {
				form := url.Values{}
				m, ok := input.Body.(map[string]any)
				if !ok {
					return errors.New("form body must be an object")
				}

				for k, v := range m {
					switch vs := v.(type) {
					case string:
						form.Add(k, vs)
					case []any:
						for _, v := range vs {
							vs, ok := v.(string)
							if !ok {
								return errors.New("form body values must be string or string arrays")
							}

							form.Add(k, vs)
						}
					default:
						return errors.New("form body values must be string or string arrays")
					}
				}

				data = form.Encode()
			} else {
				b, err := json.Marshal(input.Body)
				if err != nil {
					return fmt.Errorf("could not marshal body: %w", err)
				}

				data = string(b)
			}
		}

		req, err := http.NewRequestWithContext(cmd.Context(), method, reqURL, strings.NewReader(data))
		if err != nil {
			return fmt.Errorf("could not create request: %w", err)
		}

		if f.Session == "" {
			f.Session = req.URL.Host
		}

		if input.Body != nil {
			if !cmd.Flags().Changed(flagMethod) {
				req.Method = http.MethodPost
			}

			if req.Header.Get("content-type") == "" {
				if f.FormBody {
					req.Header.Set("content-type", "application/x-www-form-urlencoded")
				} else {
					req.Header.Set("content-type", "application/json")
				}
			}
		}

		for _, header := range input.Headers {
			req.Header.Add(header.Name, header.Value)
		}

		var shouldWriteSession bool
		for _, header := range input.Headers {
			if session.IsWritableHeader(header.Name) || f.SaveAllHeaders {
				shouldWriteSession = true
				break
			}
		}

		query := req.URL.Query()
		for _, qp := range input.QueryParams {
			query.Add(qp.Name, qp.Value)
		}
		req.URL.RawQuery = query.Encode()

		if !f.NoSession && shouldWriteSession {
			if err := session.WriteSession(f.Session, req, session.WriteSessionOpts{SaveAllHeaders: f.SaveAllHeaders}); err != nil {
				return fmt.Errorf("could not write session: %w", err)
			}
		}

		if !f.NoSession {
			ssn, err := session.ReadSession(f.Session)
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

		if f.Verbose {
			if err := out.PrintRequest(req, writer.WithHighlight(!f.NoHighlight)); err != nil {
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

		if err := out.PrintResponse(resp,
			writer.WithHeaders(!f.NoHeaders),
			writer.WithBody(!f.NoBody),
			writer.WithHighlight(!f.NoHighlight),
			writer.WithStream(f.StreamResponse),
		); err != nil {
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

func getMethod(method string) (string, error) {
	method = strings.ToUpper(method)

	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return method, nil
	default:
		return "", newUnknownMethodError(method)
	}
}
