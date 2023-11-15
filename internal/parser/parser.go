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

type accessPath interface {
	Type() string
}

type accessObjectKey struct {
	key string
}

func (k accessObjectKey) Type() string {
	return "objectKey"
}

type accessArrayIndex struct {
	index int
}

func (i accessArrayIndex) Type() string {
	return "arrayIndex"
}

type accessArrayEnd struct{}

func (e accessArrayEnd) Type() string {
	return "arrayEnd"
}

type parsedAccess struct {
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
			case parsedAccess:
				handleParsedAccess(&parsed, n)
			}
		}
	}

	return &parsed, nil
}

func handleParsedAccess(p *ParsedInput, a parsedAccess) {
	currentTarget := p.Body
	setCurrentTarget := func(v any) {
		p.Body = v
	}

	for _, s := range a.path[:len(a.path)-1] {
		switch s := s.(type) {
		case accessObjectKey:
			switch t := (currentTarget).(type) {
			case nil:
				m := map[string]any{s.key: nil}
				currentTarget = m[s.key]
				setCurrentTarget(m)
				setCurrentTarget = func(v any) {
					m[s.key] = v
				}
			case map[string]any:
				currentTarget = t[s.key]
				setCurrentTarget = func(v any) {
					t[s.key] = v
				}
			default:
				panic(fmt.Sprintf("unexpected type in path (expected nil/map): %T", t))
			}
		case accessArrayIndex:
			switch t := (currentTarget).(type) {
			case nil:
				a := make([]any, s.index+1)
				currentTarget = a[s.index]
				setCurrentTarget(a)
				setCurrentTarget = func(v any) {
					a[s.index] = v
				}
			case []any:
				if s.index >= len(t) {
					a := make([]any, s.index+1)
					copy(a, t)
					currentTarget = a[s.index]
					setCurrentTarget(a)
					setCurrentTarget = func(v any) {
						a[s.index] = v
					}
				} else {
					currentTarget = t[s.index]
				}
			default:
				panic(fmt.Sprintf("unexpected type: %T", t))
			}
		case accessArrayEnd:
			switch t := (currentTarget).(type) {
			case nil:
				a := make([]any, 1)
				currentTarget = a[0]
				setCurrentTarget(a)
				setCurrentTarget = func(v any) {
					a[0] = v
				}
			case []any:
				t = append(t, nil)
				currentTarget = t[len(t)-1]
				setCurrentTarget(t)
				setCurrentTarget = func(v any) {
					t[len(t)-1] = v
				}
			default:
				panic(fmt.Sprintf("unexpected type: %T", t))
			}
		default:
			panic(fmt.Sprintf("unexpected type: %T", s))
		}
	}

	switch p := a.path[len(a.path)-1].(type) {
	case accessObjectKey:
		switch t := currentTarget.(type) {
		case map[string]any:
			t[p.key] = a.value
		case nil:
			setCurrentTarget(map[string]any{p.key: a.value})
		default:
			panic(fmt.Sprintf("unexpected type: %T", t))
		}
	case accessArrayIndex:
		switch t := currentTarget.(type) {
		case []any:
			if p.index >= len(t) {
				a := make([]any, p.index+1)
				copy(a, t)
				setCurrentTarget(a)
			} else {
				t[p.index] = a.value
			}
		case nil:
			val := make([]any, p.index+1)
			val[p.index] = a.value
			setCurrentTarget(val)
		default:
			panic(fmt.Sprintf("unexpected type: %T", t))
		}
	case accessArrayEnd:
		switch t := currentTarget.(type) {
		case []any:
			t[0] = a.value
		case nil:
			val := make([]any, 1)
			val[0] = a.value
			setCurrentTarget(val)
		default:
			panic(fmt.Sprintf("unexpected type: %T", t))
		}
	default:
		panic(fmt.Sprintf("unexpected type: %T", p))
	}
}

var inputParser = parsec.OrdChoice(nil, accessJSONParser, queryParamParser, headerParser, accessStringParser)

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

var firstKeyParser = parsec.Many(func(nodes []parsec.ParsecNode) parsec.ParsecNode {
	key, ok := toString(nodes).(string)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[0]))
	}

	return accessObjectKey{key: key}
}, parsec.TokenExact("[^:=\\[]", "FIRSTKEYCHAR"))

var objectKeyParser = parsec.And(toObjectKeyAccessAtIndex(1),
	parsec.TokenExact(`\[`, "OPENBRACKET"),
	parsec.Many(toString, parsec.TokenExact(`[^\]]`, "KEYCHAR")),
	parsec.TokenExact(`\]`, "CLOSEBRACKET"),
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

var arrayIndexParser = parsec.And(toAccessArrayIndex,
	parsec.TokenExact(`\[`, "OPENBRACKET"),
	parsec.Many(toInt, parsec.TokenExact(`[0-9]`, "INDEXCHAR")),
	parsec.TokenExact(`\]`, "CLOSEBRACKET"),
)

func toAccessArrayIndex(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
	index, ok := nodes[1].(int)
	if !ok {
		panic(fmt.Sprintf("unexpected type: %T\n", nodes[1]))
	}

	return accessArrayIndex{index: index}
}

var accessKeyParser = parsec.And(toAccessPath,
	parsec.Maybe(nil, firstKeyParser),
	parsec.Kleene(nil, parsec.OrdChoice(nil, arrayIndexParser, objectKeyParser, arrayEndParser)),
)

func toAccessPath(nodes []parsec.ParsecNode) parsec.ParsecNode { //nolint:ireturn
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

	return parsedAccess{
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
