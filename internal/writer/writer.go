// Package writer provides convenience wrappers around common write/print
// operations for our HTTP primitives.
package writer

import (
	"fmt"
	"io"
	"net/http"
	"strings"

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

// PrintRequest prints information about an HTTP request.
func (w *Writer) PrintRequest(req *http.Request) error {
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

	if bs := string(b); bs != "" {
		if err := w.Printf("\n%s\n", bs); err != nil {
			return err
		}
	}

	return w.Printf("\n")
}

type printResponseOpts struct {
	noHeaders bool
	noBody    bool
}

// A PrintResponseOpt is an option for printing an HTTP response.
type PrintResponseOpt func(*printResponseOpts)

// WithHeaders specifies that the response headers should be printed.
func WithHeaders(b bool) PrintResponseOpt {
	return func(o *printResponseOpts) {
		o.noHeaders = !b
	}
}

// WithBody specifies that the response body should be printed.
func WithBody(b bool) PrintResponseOpt {
	return func(o *printResponseOpts) {
		o.noBody = !b
	}
}

// PrintResponse prints information about an HTTP response.
func (w *Writer) PrintResponse(resp *http.Response, opts ...PrintResponseOpt) error {
	o := &printResponseOpts{}
	for _, opt := range opts {
		opt(o)
	}

	if !o.noHeaders {
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

	if !o.noBody {
		if _, err := io.Copy(w, resp.Body); err != nil {
			return fmt.Errorf("could not write response body: %w", err)
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
