// Package writer provides utilities for writing requests and responses in a
// human-readable format.
package writer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/fatih/color"
)

// A Writer wraps an io.Writer and provides methods for writing requests and
// responses in a human-readable format.
type Writer struct {
	io.Writer

	color   bool
	info    func(f string, a ...any) error
	plain   func(f string, a ...any) error
	success func(f string, a ...any) error
}

// WithColor sets whether to use color in the output.
func WithColor(b bool) func(*Writer) {
	return func(w *Writer) {
		w.color = b
	}
}

// NewWriter creates a new Writer that wraps the given io.Writer.
func NewWriter(w io.Writer, optFns ...func(*Writer)) *Writer {
	bindPrintfFunc := func(w io.Writer, c *color.Color) func(f string, a ...any) error {
		return func(f string, a ...any) error {
			if _, err := c.Fprintf(w, f, a...); err != nil {
				return fmt.Errorf("printf: %w", err)
			}

			return nil
		}
	}

	info := color.New(color.FgCyan)
	plain := color.New(color.FgHiWhite)
	success := color.New(color.FgGreen)

	writer := Writer{
		Writer:  w,
		color:   true,
		info:    bindPrintfFunc(w, info),
		plain:   bindPrintfFunc(w, plain),
		success: bindPrintfFunc(w, success),
	}

	for _, optFn := range optFns {
		optFn(&writer)
	}

	// Override automatic reading of NO_COLOR, and use the option.
	if writer.color {
		info.EnableColor()
		plain.EnableColor()
		success.EnableColor()
	} else {
		info.DisableColor()
		plain.DisableColor()
		success.DisableColor()
	}

	return &writer
}

type writeOpts struct {
	headers   bool
	body      bool
	highlight bool
	format    bool
	stream    bool
}

// WithHeaders sets whether to write the headers.
func WithHeaders(b bool) func(*writeOpts) {
	return func(o *writeOpts) {
		o.headers = b
	}
}

// WithBody sets whether to write the body.
func WithBody(b bool) func(*writeOpts) {
	return func(o *writeOpts) {
		o.body = b
	}
}

// WithHighlight sets whether to highlight the response.
func WithHighlight(b bool) func(*writeOpts) {
	return func(o *writeOpts) {
		o.highlight = b
	}
}

// WithFormat sets whether to format the response.
func WithFormat(b bool) func(*writeOpts) {
	return func(o *writeOpts) {
		o.format = b
	}
}

// WithStream sets whether to write the response as a stream.
func WithStream(b bool) func(*writeOpts) {
	return func(o *writeOpts) {
		o.stream = b
	}
}

// WriteResponse writes out a human-readable representation of an HTTP response.
func (w *Writer) WriteResponse(r *http.Response, opts ...func(*writeOpts)) error {
	writeOpts := writeOpts{
		headers:   true,
		body:      true,
		highlight: true,
		format:    true,
		stream:    false,
	}

	for _, opt := range opts {
		opt(&writeOpts)
	}

	if err := w.success("%s %s\n", r.Proto, r.Status); err != nil {
		return err
	}

	if writeOpts.headers {
		for k, v := range r.Header {
			if err := w.info("%s: ", k); err != nil {
				return err
			}

			if err := w.plain(strings.Join(v, ", ") + "\n"); err != nil {
				return err
			}
		}
	}

	if !writeOpts.body {
		return nil
	}

	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	switch {
	case writeOpts.stream:
		return w.streamBody(r)
	case writeOpts.highlight && w.color:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		if len(b) == 0 {
			return w.plainBody(r, b, writeOpts)
		}

		return w.highlightBody(r, b, writeOpts)
	default:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		return w.plainBody(r, b, writeOpts)
	}
}

func (w *Writer) streamBody(r *http.Response) error {
	if _, err := io.Copy(w, r.Body); err != nil {
		return fmt.Errorf("stream body: %w", err)
	}

	return nil
}

func (w *Writer) highlightBody(r *http.Response, body []byte, writeOpts writeOpts) error {
	contentType := r.Header.Get("Content-Type")
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		slog.Debug("parse media type", "error", err)
		return w.plainBody(r, body, writeOpts)
	}

	lexer := lexers.MatchMimeType(mimeType)
	if lexer == nil {
		slog.Debug("lexer not found, analysing body")
		lexer = lexers.Analyse(string(body))
	}
	if lexer == nil {
		slog.Debug("lexer not found, using fallback")
		lexer = lexers.Fallback
	}

	if lexer == lexers.Get("json") && writeOpts.format {
		jsonBody, err := formatJSON(body)
		if err != nil {
			return fmt.Errorf("format json: %w", err)
		}

		body = jsonBody
	}

	style := styles.Get("monokai")
	formatter := formatters.Get("terminal")
	slog.Debug("highlighting", "lexer", lexer.Config().Name, "style", style.Name)

	tokenIter, err := lexer.Tokenise(nil, string(body))
	if err != nil {
		return fmt.Errorf("tokenise: %w", err)
	}

	if err := formatter.Format(w, style, tokenIter); err != nil {
		return fmt.Errorf("format: %w", err)
	}

	return nil
}

func (w *Writer) plainBody(r *http.Response, body []byte, writeOpts writeOpts) error {
	contentType := r.Header.Get("Content-Type")
	mimeType, _, _ := mime.ParseMediaType(contentType)

	if mimeType == "application/json" && writeOpts.format {
		jsonBody, err := formatJSON(body)
		if err != nil {
			return fmt.Errorf("format json: %w", err)
		}

		body = jsonBody
	}

	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

func formatJSON(body []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}

	var bytes bytes.Buffer
	enc := json.NewEncoder(&bytes)
	enc.SetIndent("", "\t")
	if err := enc.Encode(value); err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}

	return bytes.Bytes(), nil
}
