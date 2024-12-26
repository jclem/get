// Package writer provides convenience wrappers around common write/print
// operations for our HTTP primitives.
package writer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/fatih/color"
)

// A Writer wraps an io.Writer and provides convenience methods for writing
// data.
type Writer struct {
	w io.Writer
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	b, err := w.w.Write(p)
	if err != nil {
		return b, fmt.Errorf("could not write bytes: %w", err)
	}

	return b, nil
}

type printOpts struct {
	highlight bool
	headers   bool
	body      bool
	stream    bool
}

func newPrintOpts(opts []PrintOpt) printOpts {
	opt := printOpts{
		highlight: true,
		headers:   false,
		body:      false,
		stream:    false,
	}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// A PrintOpt is an option for printing an HTTP request or response.
type PrintOpt func(*printOpts)

// WithHighlight specifies that the request/response body should be highlighted.
func WithHighlight(b bool) PrintOpt {
	return func(o *printOpts) {
		o.highlight = b
	}
}

// WithStream specifies that the response body should be streamed.
func WithStream(b bool) PrintOpt {
	return func(o *printOpts) {
		o.stream = b
	}
}

// PrintRequest prints information about an HTTP request.
func (w *Writer) PrintRequest(req *http.Request, opts ...PrintOpt) error { //nolint:gocognit,funlen
	printOpts := newPrintOpts(opts)

	path := req.URL.Path

	if path == "" {
		path = "/"
	}

	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	if err := w.PrintfGreen("%s %s %s\n", req.Method, path, req.Proto); err != nil {
		return err
	}

	if err := w.printHeaders(req.Header); err != nil {
		return err
	}

	body, err := req.GetBody()
	if err != nil {
		return fmt.Errorf("could not get request body: %w", err)
	}

	b, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("could not read request body: %w", err)
	}

	if len(b) > 0 { //nolint:nestif
		bodyString := string(b)

		if printOpts.highlight {
			ct := req.Header.Get("Content-Type")
			parts := strings.Split(ct, ";")

			mimeType := "application/octet-stream"
			if len(parts) > 0 {
				mimeType = parts[0]
			}

			if mimeType == "application/json" {
				var j any
				if err := json.Unmarshal(b, &j); err != nil {
					return fmt.Errorf("could not unmarshal request body: %w", err)
				}

				js, err := json.MarshalIndent(j, "", "  ")
				if err != nil {
					return fmt.Errorf("could not marshal request body: %w", err)
				}

				bodyString = string(js)
			}

			lexer := lexers.MatchMimeType(mimeType)
			if lexer == nil {
				lexer = lexers.Fallback
			}

			style := styles.Get("monokai")
			if style == nil {
				return errors.New("could not get style")
			}

			formatter := formatters.Get("terminal")
			if formatter == nil {
				return errors.New("could not get formatter")
			}

			it, err := lexer.Tokenise(nil, bodyString)
			if err != nil {
				return fmt.Errorf("could not tokenise response body: %w", err)
			}

			bw := bytes.NewBuffer([]byte{})
			if err := formatter.Format(bw, style, it); err != nil {
				return fmt.Errorf("could not format response body: %w", err)
			}

			bodyString = bw.String()
		}

		if err := w.Printf("\n%s\n", bodyString); err != nil {
			return err
		}
	}

	return w.Printf("\n")
}

// WithHeaders specifies that the response headers should be printed.
func WithHeaders(b bool) PrintOpt {
	return func(o *printOpts) {
		o.headers = b
	}
}

// WithBody specifies that the response body should be printed.
func WithBody(b bool) PrintOpt {
	return func(o *printOpts) {
		o.body = b
	}
}

// PrintResponse prints information about an HTTP response.
func (w *Writer) PrintResponse(resp *http.Response, opts ...PrintOpt) error { //nolint:funlen,gocognit
	o := newPrintOpts(opts)

	if o.headers {
		if err := w.PrintfGreen("%s %s\n", resp.Proto, resp.Status); err != nil {
			return err
		}

		if err := w.printHeaders(resp.Header); err != nil {
			return err
		}

		if err := w.Printf("\n"); err != nil {
			return err
		}
	}

	if !o.body {
		return nil
	}

	if o.highlight && !o.stream { //nolint:nestif
		ct := resp.Header.Get("Content-Type")

		mimeType, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return fmt.Errorf("could not parse Content-Type: %w", err)
		}

		isJSON := mimeType == "application/json" || strings.HasSuffix(mimeType, "+json")

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read response body: %w", err)
		}

		lexer := lexers.MatchMimeType(mimeType)
		if lexer == nil {
			if isJSON {
				lexer = lexers.Get("json")
			} else {
				lexer = lexers.Analyse(string(b))
				if lexer == nil {
					lexer = lexers.Fallback
				}
			}
		}

		style := styles.Get("monokai")
		if style == nil {
			return errors.New("could not get style")
		}

		formatter := formatters.Get("terminal")
		if formatter == nil {
			return errors.New("could not get formatter")
		}

		if isJSON {
			var j any
			if err := json.Unmarshal(b, &j); err != nil {
				return fmt.Errorf("could not unmarshal response body: %w", err)
			}

			js, err := json.MarshalIndent(j, "", "  ")
			if err != nil {
				return fmt.Errorf("could not marshal response body: %w", err)
			}

			b = js
		}

		it, err := lexer.Tokenise(nil, string(b))
		if err != nil {
			return fmt.Errorf("could not tokenise response body: %w", err)
		}

		if err := formatter.Format(w.w, style, it); err != nil {
			return fmt.Errorf("could not format response body: %w", err)
		}

		return nil
	}

	if o.stream {
		if _, err := io.Copy(w, resp.Body); err != nil {
			return fmt.Errorf("could not write response body: %w", err)
		}
	} else {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read response body: %w", err)
		}

		if err := w.Printf("%s\n", string(b)); err != nil {
			return err
		}
	}

	return nil
}

// Printf writes a formatted string to the underlying io.Writer.
func (w *Writer) Printf(format string, a ...any) error {
	if _, err := fmt.Fprintf(w.w, format, a...); err != nil {
		return fmt.Errorf("could not write formatted string: %w", err)
	}

	return nil
}

// PrintfBlue writes a formatted string to the underlying io.Writer in blue.
func (w *Writer) PrintfBlue(format string, a ...any) error {
	return w.printfColor(color.New(color.FgBlue), format, a...)
}

// PrintfGreen writes a formatted string to the underlying io.Writer in green.
func (w *Writer) PrintfGreen(format string, a ...any) error {
	return w.printfColor(color.New(color.FgGreen), format, a...)
}

// PrintfCyan writes a formatted string to the underlying io.Writer in red.
func (w *Writer) PrintfCyan(format string, a ...any) error {
	return w.printfColor(color.New(color.FgCyan), format, a...)
}

func (w *Writer) printfColor(c *color.Color, format string, a ...any) error {
	if _, err := c.Fprintf(w.w, format, a...); err != nil {
		return fmt.Errorf("could not write formatted string: %w", err)
	}

	return nil
}

func (w *Writer) printHeaders(h http.Header) error {
	for k, v := range h {
		if err := w.PrintfCyan("%s: ", k); err != nil {
			return err
		}

		if err := w.Printf("%s\n", strings.Join(v, ", ")); err != nil {
			return err
		}
	}

	return nil
}

// NewWriter returns a new Writer that wraps w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}
