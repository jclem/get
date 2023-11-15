// Package parser provides a parser for data, header, and query parameter input
// strings.
package parser

import (
	"encoding/json"
	"fmt"

	parsec "github.com/prataprc/goparsec"
)

var equalsSign = parsec.AtomExact(`=`, "EQ")
var colon = parsec.AtomExact(`:`, "COL")

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

type parsedKeyValue struct {
	Key   string
	Value json.RawMessage
}

// A ParsedInput represents data gathered from a user input string.
type ParsedInput struct {
	Headers     []ParsedHeader
	QueryParams []ParsedQueryParam
	Body        map[string]json.RawMessage
}

func newParsedInput() ParsedInput {
	return ParsedInput{
		Headers:     make([]ParsedHeader, 0),
		QueryParams: make([]ParsedQueryParam, 0),
		Body:        make(map[string]json.RawMessage),
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
			case parsedKeyValue:
				parsed.Body[n.Key] = n.Value
			}
		}
	}

	return &parsed, nil
}

var inputParser = parsec.OrdChoice(nil, queryParamParser, headerParser, keyValueParser)

// A header key can be alphanumeric with underscores and hyphens.
var headerKey = parsec.Many(toString, parsec.TokenExact("[A-Za-z0-9-_]", "HEADERKEYCHAR"))

// A header value can be any character.
var headerVal = parsec.Many(toString, parsec.TokenExact(".", "HEADERVALCHAR"))

var headerParser = parsec.And(toHeader, headerKey, colon, headerVal)

func toHeader(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	name, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	value, ok := nodes[2].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
	}

	return ParsedHeader{Name: name, Value: value}
}

var queryParamParser = parsec.And(toQueryParam,
	parsec.Many(toString, parsec.TokenExact("[^=]", "QUERYKEYCHAR")),
	equalsSign,
	equalsSign,
	parsec.Many(toString, parsec.TokenExact(".", "QUERYVALCHAR")),
)

func toQueryParam(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	name, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	value, ok := nodes[3].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
	}

	return ParsedQueryParam{Name: name, Value: value}
}

var keyValueParser = parsec.And(toKeyValue,
	parsec.Many(toString, parsec.TokenExact(".+", "KEYCHAR")),
	parsec.Maybe(nil, colon),
	equalsSign,
	parsec.Many(toString, parsec.TokenExact(".+", "VALCHAR")),
)

func toKeyValue(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	key, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	kv := parsedKeyValue{Key: key}

	isRawJSON := false
	_, ok = nodes[1].(parsec.MaybeNone)
	if !ok {
		isRawJSON = true
	}

	if isRawJSON {
		val, ok := nodes[3].(string)
		if !ok {
			panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
		}

		kv.Value = json.RawMessage(val)
	} else {
		val, ok := nodes[3].(string)
		if !ok {
			panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
		}

		kv.Value = json.RawMessage(`"` + val + `"`)
	}

	return kv
}

func toString(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	var str string

	for _, node := range nodes {
		switch node := node.(type) {
		case *parsec.Terminal:
			str += node.Value
		default:
			panic(fmt.Sprintf("unexpected type: %T\n", node))
		}
	}

	return str
}
