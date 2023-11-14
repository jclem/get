// Package parser provides a parser for data, header, and query parameter input
// strings.
package parser

import (
	"fmt"

	parsec "github.com/prataprc/goparsec"
)

// var dquote = parsec.AtomExact(`"`, "DQUOTE")
// var squote = parsec.AtomExact(`'`, "SQUOTE")
var eq = parsec.AtomExact(`=`, "EQ")

var headerChar = parsec.TokenExact("[a-z]", "HEADERCHAR")
var anyChar = parsec.TokenExact(".+", "ANYCHAR")
var whitespace = parsec.TokenExact(`\s+`, "WHITESPACE")
var headerJoin = eq

// A ParsedHeader represents a single parsed header. They may be repeated in one
// input.
type ParsedHeader struct {
	Name  string
	Value string
}

// A ParsedQueryParam represents a single parsed query parameter. They may be
// repeated in one input.
type ParsedQueryParam struct {
	Name  string
	Value string
}

// A ParsedInput represents data gathered from a user input string.
type ParsedInput struct {
	Headers     []ParsedHeader
	QueryParams []ParsedQueryParam
	Body        any
}

func newParsedInput() ParsedInput {
	return ParsedInput{
		Headers:     make([]ParsedHeader, 0),
		QueryParams: make([]ParsedQueryParam, 0),
	}
}

// ParseInput parses a string of headers.
func ParseInput(in []string) (*ParsedInput, error) {
	parsed := newParsedInput()

	for _, part := range in {
		scanner := parsec.NewScanner([]byte(part))
		node, scanner := inputParser(scanner)

		if !scanner.Endof() {
			cursor := scanner.GetCursor()
			remainder := part[cursor:]
			return nil, fmt.Errorf("unexpected input: %q", remainder)
		}

		nodes, ok := node.([]parsec.ParsecNode)
		if !ok {
			return nil, fmt.Errorf("unexpected type: %T", node)
		}

		for _, n := range nodes {
			switch n := n.(type) {
			case ParsedHeader:
				parsed.Headers = append(parsed.Headers, n)
			case ParsedQueryParam:
				parsed.QueryParams = append(parsed.QueryParams, n)
			}
		}
	}

	return &parsed, nil
}

var inputParser = parsec.OrdChoice(nil, queryParamParser, headerParser)

var headerParser = parsec.And(toHeader,
	parsec.Many(toString, headerChar),
	eq,
	parsec.Many(toString, anyChar),
)

func toHeader(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	name, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	hd := ParsedHeader{Name: name}

	val, ok := nodes[2].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
	}

	hd.Value = val

	return hd
}

var queryParamParser = parsec.And(toQueryParam,
	parsec.Many(toString, headerChar),
	eq,
	eq,
	parsec.Many(toString, anyChar),
)

func toQueryParam(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	name, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	hd := ParsedQueryParam{Name: name}

	val, ok := nodes[3].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
	}

	hd.Value = val

	return hd
}

func toString(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	var str string

	for _, node := range nodes {
		term, ok := node.(*parsec.Terminal)
		if !ok {
			panic(fmt.Sprintf("unexpected type: %T\n", node))
		}

		str += term.Value
	}

	return str
}
