// Package builder builds HTTP requests based on a URL and parsed input.
package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jclem/get/internal/parser"
	"github.com/jclem/get/internal/sessions"
)

type buildOpts struct {
	httpMethod  string
	useFormBody bool
	session     *sessions.Session
}

// WithHTTPMethod sets the HTTP method to use for the request.
func WithHTTPMethod(m string) func(*buildOpts) {
	return func(o *buildOpts) {
		o.httpMethod = m
	}
}

// WithFormBody sets whether to format the request body as a form.
func WithFormBody(b bool) func(*buildOpts) {
	return func(o *buildOpts) {
		o.useFormBody = b
	}
}

// WithSession sets the session to use for the request.
func WithSession(s *sessions.Session) func(*buildOpts) {
	return func(o *buildOpts) {
		o.session = s
	}
}

// Build builds an HTTP request based on a URL and parsed input.
func Build(ctx context.Context, url url.URL, input parser.ParsedInput, buildOpts ...func(*buildOpts)) (*http.Request, error) {
	opts := getBuildOpts(buildOpts...)
	session := opts.session

	var body io.Reader
	if input.Body != nil && opts.useFormBody {
		fBody, err := marshalForm(input.Body)
		if err != nil {
			return nil, err
		}
		body = fBody
	} else if input.Body != nil {
		b, err := json.Marshal(input.Body)
		if err != nil {
			return nil, fmt.Errorf("marshal json: %w", err)
		}
		body = bytes.NewBuffer(b)
	}

	req, err := http.NewRequestWithContext(ctx, opts.httpMethod, url.String(), body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	if session != nil {
		for key, values := range session.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// Input headers should replace session headers, but not themselves.
	setInputHeaders := make(map[string]bool)

	for _, header := range input.Headers {
		didSetHeader := setInputHeaders[header.Name]
		if didSetHeader {
			req.Header.Add(header.Name, header.Value)
			continue
		}

		setInputHeaders[header.Name] = true
		req.Header.Set(header.Name, header.Value)
	}

	if req.Header.Get("Content-Type") == "" && body != nil {
		if opts.useFormBody {
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Add("Content-Type", "application/json")
		}
	}

	if req.Header.Get("Host") == "" {
		req.Header.Add("Host", req.URL.Host)
	}

	query := req.URL.Query()
	for _, param := range input.QueryParams {
		query.Add(param.Name, param.Value)
	}
	req.URL.RawQuery = query.Encode()

	return req, nil
}

func getBuildOpts(opts ...func(*buildOpts)) buildOpts {
	buildOpts := buildOpts{
		httpMethod:  http.MethodGet,
		useFormBody: false,
		session:     nil,
	}

	for _, opt := range opts {
		opt(&buildOpts)
	}

	return buildOpts
}

// ErrFormBody is returned when the body's values are not valid for a form.
var ErrFormBody = errors.New("form body values must be strings or string arrays")

func marshalForm(body any) (io.Reader, error) {
	form := url.Values{}
	m, ok := body.(map[string]any)
	if !ok {
		return nil, errors.New("body is not a map[string]any")
	}

	for k, v := range m {
		switch v := v.(type) {
		case string:
			form.Add(k, v)
		case []any:
			for _, v := range v {
				v, ok := v.(string)
				if !ok {
					return nil, ErrFormBody
				}

				form.Add(k, v)
			}
		default:
			return nil, ErrFormBody
		}
	}

	return bytes.NewBufferString(form.Encode()), nil
}
