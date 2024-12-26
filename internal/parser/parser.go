// Package parser provides a parser for data, header, and query parameter input
// strings.
package parser

import (
	"encoding/json"
	"fmt"
	"strconv"

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

type accessPath any

type accessObjectKey struct {
	key string
}

type accessArrayIndex struct {
	index int
}

type accessArrayEnd struct{}

type bodyComponent struct {
	path  []accessPath
	value any
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
		Body:        nil,
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
			case bodyComponent:
				if err := parsed.buildBody(n); err != nil {
					return nil, err
				}
			}
		}
	}

	return &parsed, nil
}

func (p *ParsedInput) buildBody(comp bodyComponent) error { //nolint:funlen // Less readable when broken up
	currentTarget := p.Body
	setCurrentTarget := func(v any) { p.Body = v }

	for _, segment := range comp.path {
		switch segment := segment.(type) {
		case accessObjectKey:
			var m map[string]any

			switch target := currentTarget.(type) {
			case nil:
				m = map[string]any{segment.key: nil}
				setCurrentTarget(m)
			case map[string]any:
				m = target
			default:
				return fmt.Errorf("attempted to access key of non-object (%T): %+v", target, target)
			}

			currentTarget = m[segment.key]
			setCurrentTarget = func(v any) { m[segment.key] = v }
		case accessArrayIndex:
			var a []any

			switch t := (currentTarget).(type) {
			case nil:
				a = make([]any, segment.index+1)
				setCurrentTarget(a)
			case []any:
				a = t

				if segment.index >= len(a) {
					a = append(a, make([]any, segment.index-len(a)+1)...) //nolint:makezero
					setCurrentTarget(a)
				}
			default:
				return fmt.Errorf("attempted to access index of non-array (%T): %+v", t, t)
			}

			currentTarget = a[segment.index]
			setCurrentTarget = func(v any) { a[segment.index] = v }
		case accessArrayEnd:
			var a []any

			switch t := (currentTarget).(type) {
			case nil:
				a = make([]any, 1)
				setCurrentTarget(a)
			case []any:
				a = t
				a = append(a, nil) //nolint:makezero
				setCurrentTarget(a)
			default:
				return fmt.Errorf("attempted to access end of non-array (%T): %+v", t, t)
			}

			currentTarget = a[len(a)-1]
			setCurrentTarget = func(v any) { a[len(a)-1] = v }
		}
	}

	setCurrentTarget(comp.value)

	return nil
}

var inputParser = parsec.OrdChoice(nil,
	accessJSONParser, queryParamParser, headerParser, accessStringParser)

var headerParser = parsec.And(toHeader,
	parsec.Many(toString, parsec.TokenExact("[A-Za-z0-9-_]", "HEADERKEYCHAR")),
	colon,
	parsec.Many(toString, parsec.TokenExact(".", "HEADERVALCHAR")),
)

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

var queryParamParser = parsec.And(func(nodes []parsec.ParsecNode) parsec.ParsecNode {
	name, ok := nodes[0].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	value, ok := nodes[3].(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[2]))
	}

	return ParsedQueryParam{Name: name, Value: value}
},
	parsec.Many(toString, parsec.TokenExact("[^=]", "QUERYKEYCHAR")),
	equalsSign,
	equalsSign,
	parsec.Many(toString, parsec.TokenExact(".", "QUERYVALCHAR")),
)

var objectKeyParser = parsec.OrdChoice(nil,
	parsec.And(toObjectKeyAccessAtIndex(1),
		parsec.TokenExact(`\[`, "OPENBRACKET"),
		parsec.Many(toString, parsec.TokenExact(`[^\]]`, "KEYCHAR")),
		parsec.TokenExact(`\]`, "CLOSEBRACKET")),
	parsec.And(toObjectKeyAccessAtIndex(1),
		parsec.TokenExact(`\.`, "PERIOD"),
		parsec.Many(toString, parsec.TokenExact(`[^\.\[:=]`, "KEYCHAR"))),
	parsec.And(toObjectKeyAccessAtIndex(0),
		parsec.Many(toString, parsec.TokenExact(`[^\.\[:=]`, "KEYCHAR"))),
)

func toObjectKeyAccessAtIndex(index int) parsec.Nodify {
	return func(nodes []parsec.ParsecNode) parsec.ParsecNode {
		key, ok := nodes[index].(string)
		if !ok {
			panic(fmt.Sprintf("unexpected type: %T\n", nodes[index]))
		}

		return accessObjectKey{key: key}
	}
}

var arrayEndParser = parsec.And(toAccessArrayEnd, parsec.TokenExact(`\[\]`, "PUSHARRAY"))

func toAccessArrayEnd(_ []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	return accessArrayEnd{}
}

var arrayIndexParser = parsec.OrdChoice(nil,
	parsec.And(toAccessArrayIndexAtIndex(1),
		parsec.TokenExact(`\[`, "OPENBRACKET"),
		parsec.Many(toInt, parsec.TokenExact(`[0-9]`, "INDEXCHAR")),
		parsec.TokenExact(`\]`, "CLOSEBRACKET"),
	),
	parsec.And(toAccessArrayIndexAtIndex(1),
		parsec.TokenExact(`\.`, "PERIOD"),
		parsec.Many(toInt, parsec.TokenExact(`[0-9]`, "INDEXCHAR"))),
	parsec.And(toAccessArrayIndexAtIndex(0),
		parsec.Many(toInt, parsec.TokenExact(`[0-9]`, "INDEXCHAR"))),
)

func toAccessArrayIndexAtIndex(index int) parsec.Nodify {
	return func(nodes []parsec.ParsecNode) parsec.ParsecNode {
		index, ok := nodes[index].(int)
		if !ok {
			panic(fmt.Sprintf("unexpected type: %T\n", nodes[1]))
		}

		return accessArrayIndex{index: index}
	}
}

var accessKeyParser = parsec.And(func() func(nodes []parsec.ParsecNode) parsec.ParsecNode {
	var toAccessPath func([]parsec.ParsecNode) parsec.ParsecNode

	toAccessPath = func(nodes []parsec.ParsecNode) parsec.ParsecNode {
		path := make([]accessPath, 0, len(nodes))

		for _, node := range nodes {
			switch node := node.(type) {
			case accessObjectKey:
				path = append(path, node)
			case accessArrayIndex:
				path = append(path, node)
			case accessArrayEnd:
				path = append(path, node)
			case []parsec.ParsecNode:
				subPath, ok := toAccessPath(node).([]accessPath)
				if !ok {
					panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
				}

				path = append(path, subPath...)
			case parsec.MaybeNone:
			default:
				panic(fmt.Sprintf("unexpected type: %T\n", node))
			}
		}

		return path
	}

	return toAccessPath
}(),
	parsec.Many(nil, parsec.OrdChoice(nil, arrayIndexParser, objectKeyParser, arrayEndParser)),
)

var accessStringParser = parsec.And(toAccess,
	accessKeyParser,
	equalsSign,
	parsec.Many(toString, parsec.TokenExact(".", "ACCESSVALCHAR")),
)

var accessJSONParser = parsec.And(toAccess,
	accessKeyParser,
	colon,
	equalsSign,
	parsec.Many(parseJSON, parsec.TokenExact(".", "ACCESSVALCHAR")),
)

// JSONNull is a value representing a JSON null value.
//
// This is required because `parseJSON` will be passed over if it returns `nil`
// in an OrdChoice combinator.
type JSONNull struct{}

func (j JSONNull) MarshalJSON() ([]byte, error) {
	return []byte("null"), nil
}

func parseJSON(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	str, ok := toString(nodes).(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	var val any

	err := json.Unmarshal([]byte(str), &val)
	if err != nil {
		panic(err)
	}

	if val == nil {
		return JSONNull{}
	}

	return val
}

func toAccess(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	path, ok := nodes[0].([]accessPath)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	lastNode := nodes[len(nodes)-1]

	var value any
	switch t := lastNode.(type) {
	case string:
		value = t
	case *parsec.Terminal:
		value = t.Value
	default:
		value = t
	}

	return bodyComponent{
		path:  path,
		value: value,
	}
}

func toString(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	var str string

	for _, node := range nodes {
		switch node := node.(type) {
		case *parsec.Terminal:
			str += node.Value
		case string:
			str += node
		default:
			panic(fmt.Sprintf("unexpected type: %T\n", node))
		}
	}

	return str
}

func toInt(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	str, ok := toString(nodes).(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	i, err := strconv.Atoi(str)
	if err != nil {
		panic(err)
	}

	return i
}
