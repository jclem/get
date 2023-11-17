package parser_test

import (
	"errors"
	"testing"

	"github.com/jclem/get/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testInput struct {
	input []string
}

type testOutput struct {
	result *resultBuilder
	error  error
}

type testCase struct {
	description string
	input       testInput
	output      testOutput
}

type resultBuilder struct {
	*parser.ParsedInput
}

func (b *resultBuilder) withHeader(name, value string) *resultBuilder {
	b.Headers = append(b.Headers, parser.ParsedHeader{Name: name, Value: value})
	return b
}

func (b *resultBuilder) withQueryParam(name, value string) *resultBuilder {
	b.QueryParams = append(b.QueryParams, parser.ParsedQueryParam{Name: name, Value: value})
	return b
}

func (b *resultBuilder) withBodyParam(body any) *resultBuilder {
	b.Body = body
	return b
}

func newResultBuilder() *resultBuilder {
	return &resultBuilder{&parser.ParsedInput{
		Headers:     make([]parser.ParsedHeader, 0),
		QueryParams: make([]parser.ParsedQueryParam, 0),
	}}
}

func TestParseInput(t *testing.T) {
	testCases := []testCase{{
		description: "ParsesSimpleHeader",
		input:       testInput{input: []string{"foo:bar"}},
		output: testOutput{
			result: newResultBuilder().withHeader("foo", "bar"),
			error:  nil,
		},
	}, {
		description: "ParsesQuotedHeader",
		input:       testInput{input: []string{`foo:bar baz`}},
		output: testOutput{
			result: newResultBuilder().withHeader("foo", "bar baz"),
			error:  nil,
		},
	}, {

		description: "ErrorsOnDisallowedHeaderChar",
		input:       testInput{input: []string{`foo bar:baz`}},
		output: testOutput{
			result: nil,
			error:  errors.New(`unexpected input: "foo bar:baz"`),
		},
	}, {
		description: "ParsesSimpleQueryParam",
		input:       testInput{input: []string{`foo==bar`}},
		output: testOutput{
			result: newResultBuilder().withQueryParam("foo", "bar"),
			error:  nil,
		},
	}, {
		description: "ParsesQuotedQueryParam",
		input:       testInput{input: []string{`foo bar==bar baz`}},
		output: testOutput{
			result: newResultBuilder().withQueryParam("foo bar", "bar baz"),
			error:  nil,
		},
	}, {
		description: "ParsesSimpleKVBodyParam",
		input:       testInput{input: []string{`foo=bar`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": "bar"}),
			error:  nil,
		},
	}, {
		description: "ParsesNestedKVBodyParam",
		input:       testInput{input: []string{`foo[bar]=baz`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": map[string]any{"bar": "baz"}}),
			error:  nil,
		},
	}, {
		description: "ParsesMultiNestedKVBodyParam",
		input:       testInput{input: []string{`foo[bar][baz][qux]=quux`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": map[string]any{"bar": map[string]any{"baz": map[string]any{"qux": "quux"}}}}),
			error:  nil,
		},
	}, {
		description: "ParsesArrayEndParam",
		input:       testInput{input: []string{`[]=foo`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam([]any{"foo"}),
			error:  nil,
		},
	}, {
		description: "ParsesNestedArrayEndParam",
		input:       testInput{input: []string{`foo[][]=bar`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": []any{[]any{"bar"}}}),
			error:  nil,
		},
	}, {
		description: "ParsesArrayIndexParam",
		input:       testInput{input: []string{`[1]=foo`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam([]any{nil, "foo"}),
			error:  nil,
		},
	}, {
		description: "ParsesNestedArrayIndexParam",
		input:       testInput{input: []string{`foo[0][0]=bar`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": []any{[]any{"bar"}}}),
			error:  nil,
		},
	}, {
		description: "ParsesComplexParam",
		input:       testInput{input: []string{`foo[][bar]=baz`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": []any{map[string]any{"bar": "baz"}}}),
			error:  nil,
		},
	}, {
		description: "ParsesMultipleComplexParams",
		input:       testInput{input: []string{`foo[][bar]=baz`, `foo[][qux]=quux`, `foo[3][][][a][][4][][b][c][][d]=x`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{
				"foo": []any{
					map[string]any{"bar": "baz"},
					map[string]any{"qux": "quux"},
					nil,
					[]any{
						[]any{
							map[string]any{
								"a": []any{
									[]any{nil, nil, nil, nil, []any{
										map[string]any{
											"b": map[string]any{
												"c": []any{
													map[string]any{"d": "x"},
												},
											},
										},
									},
									},
								},
							},
						},
					},
				},
			}),
			error: nil,
		},
	}, {
		description: "ParsesRawJSONValues",
		input:       testInput{input: []string{`foo:={"bar":"baz"}`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": map[string]any{"bar": "baz"}}),
		},
	}, {
		description: "SetsMultipleArrayEnd",
		input:       testInput{input: []string{`foo[]=bar`, `foo[]=baz`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": []any{"bar", "baz"}}),
			error:  nil,
		},
	}, {
		description: "SetsMultipleArrayIndex",
		input:       testInput{input: []string{`foo[]=bar`, `foo[]=baz`, `foo[2]=qux`}},
		output: testOutput{
			result: newResultBuilder().withBodyParam(map[string]any{"foo": []any{"bar", "baz", "qux"}}),
			error:  nil,
		},
	}}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			out, err := parser.ParseInput(testCase.input.input)

			if testCase.output.error == nil {
				require.NoErrorf(t, err, "expected no error, got %v", err)
			} else {
				require.EqualErrorf(t, err, testCase.output.error.Error(), "expected error %v, got %v", testCase.output.error, err)
			}

			if testCase.output.result == nil {
				assert.Nilf(t, out, "expected nil output, got %v", out)
			} else {
				assert.Equalf(t, testCase.output.result.ParsedInput, out, "expected output %v, got %v", testCase.output.result, out)
			}
		})
	}
}
