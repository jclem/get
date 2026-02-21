use serde_json::{Map, Value};
use std::error::Error;
use std::fmt;
use winnow::combinator::{alt, repeat};
use winnow::prelude::*;
use winnow::token::take_while;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ParsedInput {
    pub headers: Vec<ParsedHeader>,
    pub query_params: Vec<ParsedQueryParam>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseInputError {
    message: String,
}

impl ParseInputError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn unexpected(input: &str) -> Self {
        Self::new(format!("unexpected input: {input:?}"))
    }

    fn invalid_json(input: &str, error: serde_json::Error) -> Self {
        Self::new(format!("invalid JSON value in {input:?}: {error}"))
    }

    fn type_mismatch(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for ParseInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for ParseInputError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    ObjectKey(String),
    ArrayIndex(usize),
    ArrayEnd,
}

#[derive(Debug, Clone, PartialEq)]
struct BodyComponent {
    path: Vec<PathSegment>,
    value: Value,
}

#[derive(Debug, Clone, PartialEq)]
enum ParsedPart {
    Header(ParsedHeader),
    Query(ParsedQueryParam),
    Body(BodyComponent),
}

pub fn parse_input(parts: &[String]) -> Result<ParsedInput, ParseInputError> {
    let mut parsed = ParsedInput::default();

    for part in parts {
        match parse_part(part)? {
            ParsedPart::Header(header) => parsed.headers.push(header),
            ParsedPart::Query(query) => parsed.query_params.push(query),
            ParsedPart::Body(component) => apply_body_component(&mut parsed.body, component)?,
        }
    }

    Ok(parsed)
}

fn parse_part(part: &str) -> Result<ParsedPart, ParseInputError> {
    if let Some(component) = parse_json_assignment(part)? {
        return Ok(ParsedPart::Body(component));
    }

    if let Some(query) = parse_query_param(part)? {
        return Ok(ParsedPart::Query(query));
    }

    if let Some(header) = parse_header(part)? {
        return Ok(ParsedPart::Header(header));
    }

    if let Some(component) = parse_string_assignment(part)? {
        return Ok(ParsedPart::Body(component));
    }

    Err(ParseInputError::unexpected(part))
}

fn parse_json_assignment(part: &str) -> Result<Option<BodyComponent>, ParseInputError> {
    let Some((path_raw, value_raw)) = part.split_once(":=") else {
        return Ok(None);
    };

    let path = parse_access_path(path_raw).map_err(|_| ParseInputError::unexpected(part))?;
    let value = serde_json::from_str(value_raw)
        .map_err(|error| ParseInputError::invalid_json(part, error))?;

    Ok(Some(BodyComponent { path, value }))
}

fn parse_query_param(part: &str) -> Result<Option<ParsedQueryParam>, ParseInputError> {
    let Some((name, value)) = part.split_once("==") else {
        return Ok(None);
    };

    if !is_valid_query_name(name) {
        return Err(ParseInputError::unexpected(part));
    }

    Ok(Some(ParsedQueryParam {
        name: name.to_string(),
        value: value.to_string(),
    }))
}

fn parse_header(part: &str) -> Result<Option<ParsedHeader>, ParseInputError> {
    let Some((name, value)) = part.split_once(':') else {
        return Ok(None);
    };

    if !is_valid_header_name(name) {
        return Err(ParseInputError::unexpected(part));
    }

    Ok(Some(ParsedHeader {
        name: name.to_string(),
        value: value.to_string(),
    }))
}

fn parse_string_assignment(part: &str) -> Result<Option<BodyComponent>, ParseInputError> {
    let Some((path_raw, value_raw)) = part.split_once('=') else {
        return Ok(None);
    };

    let path = parse_access_path(path_raw).map_err(|_| ParseInputError::unexpected(part))?;
    let value = Value::String(value_raw.to_string());

    Ok(Some(BodyComponent { path, value }))
}

fn is_valid_header_name(name: &str) -> bool {
    let mut input = name;
    take_while::<_, _, ()>(1.., is_header_name_char)
        .parse_next(&mut input)
        .is_ok()
        && input.is_empty()
}

fn is_header_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn is_valid_query_name(name: &str) -> bool {
    let mut input = name;
    take_while::<_, _, ()>(1.., is_query_name_char)
        .parse_next(&mut input)
        .is_ok()
        && input.is_empty()
}

fn is_query_name_char(c: char) -> bool {
    c != '='
}

fn parse_access_path(path_raw: &str) -> Result<Vec<PathSegment>, ParseInputError> {
    let mut input = path_raw;
    let path = repeat(1.., access_path_segment)
        .parse_next(&mut input)
        .map_err(|_| ParseInputError::unexpected(path_raw))?;

    if !input.is_empty() {
        return Err(ParseInputError::unexpected(path_raw));
    }

    Ok(path)
}

fn access_path_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    alt((array_index_segment, object_key_segment, array_end_segment)).parse_next(input)
}

fn array_end_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    "[]".parse_next(input)?;
    Ok(PathSegment::ArrayEnd)
}

fn array_index_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    alt((
        bracket_array_index_segment,
        dotted_array_index_segment,
        bare_array_index_segment,
    ))
    .parse_next(input)
}

fn bracket_array_index_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    "[".parse_next(input)?;
    let index = parse_index_digits(input)?;
    "]".parse_next(input)?;
    Ok(PathSegment::ArrayIndex(index))
}

fn dotted_array_index_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    ".".parse_next(input)?;
    let index = parse_index_digits(input)?;
    Ok(PathSegment::ArrayIndex(index))
}

fn bare_array_index_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    let index = parse_index_digits(input)?;
    Ok(PathSegment::ArrayIndex(index))
}

fn parse_index_digits(input: &mut &str) -> winnow::Result<usize> {
    let digits: &str = take_while(1.., |c: char| c.is_ascii_digit()).parse_next(input)?;
    Ok(digits.parse().unwrap_or(usize::MAX))
}

fn object_key_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    alt((
        bracket_object_key_segment,
        dotted_object_key_segment,
        bare_object_key_segment,
    ))
    .parse_next(input)
}

fn bracket_object_key_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    "[".parse_next(input)?;
    let key: &str = take_while(1.., |c: char| c != ']').parse_next(input)?;
    "]".parse_next(input)?;
    Ok(PathSegment::ObjectKey(key.to_string()))
}

fn dotted_object_key_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    ".".parse_next(input)?;
    let key: &str = take_while(1.., is_plain_object_key_char).parse_next(input)?;
    Ok(PathSegment::ObjectKey(key.to_string()))
}

fn bare_object_key_segment(input: &mut &str) -> winnow::Result<PathSegment> {
    let key: &str = take_while(1.., is_plain_object_key_char).parse_next(input)?;
    Ok(PathSegment::ObjectKey(key.to_string()))
}

fn is_plain_object_key_char(c: char) -> bool {
    c != '.' && c != '[' && c != ':' && c != '='
}

fn apply_body_component(
    body: &mut Option<Value>,
    component: BodyComponent,
) -> Result<(), ParseInputError> {
    if body.is_none() {
        *body = Some(Value::Null);
    }

    let Some(target) = body.as_mut() else {
        return Err(ParseInputError::type_mismatch(
            "body was unexpectedly absent",
        ));
    };

    set_path_value(target, &component.path, component.value)
}

fn set_path_value(
    target: &mut Value,
    path: &[PathSegment],
    value: Value,
) -> Result<(), ParseInputError> {
    if path.is_empty() {
        *target = value;
        return Ok(());
    }

    match &path[0] {
        PathSegment::ObjectKey(key) => {
            if target.is_null() {
                *target = Value::Object(Map::new());
            }

            let Some(map) = target.as_object_mut() else {
                return Err(ParseInputError::type_mismatch(format!(
                    "attempted to access key of non-object ({}): {}",
                    value_type_name(target),
                    target
                )));
            };

            let entry = map.entry(key.clone()).or_insert(Value::Null);
            set_path_value(entry, &path[1..], value)
        }
        PathSegment::ArrayIndex(index) => {
            if target.is_null() {
                *target = Value::Array(Vec::new());
            }

            let Some(array) = target.as_array_mut() else {
                return Err(ParseInputError::type_mismatch(format!(
                    "attempted to access index of non-array ({}): {}",
                    value_type_name(target),
                    target
                )));
            };

            if *index >= array.len() {
                array.resize(*index + 1, Value::Null);
            }

            set_path_value(&mut array[*index], &path[1..], value)
        }
        PathSegment::ArrayEnd => {
            if target.is_null() {
                *target = Value::Array(Vec::new());
            }

            let Some(array) = target.as_array_mut() else {
                return Err(ParseInputError::type_mismatch(format!(
                    "attempted to access end of non-array ({}): {}",
                    value_type_name(target),
                    target
                )));
            };

            array.push(Value::Null);
            let idx = array.len() - 1;
            set_path_value(&mut array[idx], &path[1..], value)
        }
    }
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_input, ParseInputError, ParsedHeader, ParsedInput, ParsedQueryParam};
    use serde_json::{json, Value};

    fn parse(parts: &[&str]) -> Result<ParsedInput, ParseInputError> {
        parse_input(
            &parts
                .iter()
                .map(|part| (*part).to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn parses_headers_query_and_body_components() {
        let parsed = parse(&[
            "Authorization:Bearer token",
            "q==hello world",
            "foo[bar]=baz",
            "is_draft:=true",
        ])
        .expect("parse input");

        assert_eq!(
            parsed,
            ParsedInput {
                headers: vec![ParsedHeader {
                    name: "Authorization".to_string(),
                    value: "Bearer token".to_string(),
                }],
                query_params: vec![ParsedQueryParam {
                    name: "q".to_string(),
                    value: "hello world".to_string(),
                }],
                body: Some(json!({
                    "foo": {"bar": "baz"},
                    "is_draft": true,
                })),
            }
        );
    }

    #[test]
    fn parses_simple_header() {
        let parsed = parse(&["foo:bar"]).expect("parse input");
        assert_eq!(
            parsed,
            ParsedInput {
                headers: vec![ParsedHeader {
                    name: "foo".to_string(),
                    value: "bar".to_string(),
                }],
                query_params: vec![],
                body: None,
            }
        );
    }

    #[test]
    fn parses_quoted_header() {
        let parsed = parse(&["foo:bar baz"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "foo".to_string(),
                value: "bar baz".to_string(),
            }]
        );
    }

    #[test]
    fn errors_on_disallowed_header_char() {
        let err = parse(&["foo bar:baz"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"foo bar:baz\"");
    }

    #[test]
    fn parses_simple_query_param() {
        let parsed = parse(&["foo==bar"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "foo".to_string(),
                value: "bar".to_string(),
            }]
        );
    }

    #[test]
    fn parses_quoted_query_param() {
        let parsed = parse(&["foo bar==bar baz"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "foo bar".to_string(),
                value: "bar baz".to_string(),
            }]
        );
    }

    #[test]
    fn parses_simple_kv_body_param() {
        let parsed = parse(&["foo=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": "bar"})));
    }

    #[test]
    fn parses_nested_kv_body_param() {
        let parsed = parse(&["foo[bar]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": "baz"}})));
    }

    #[test]
    fn parses_multi_nested_kv_body_param() {
        let parsed = parse(&["foo[bar][baz][qux]=quux"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": {
                    "bar": {
                        "baz": {
                            "qux": "quux"
                        }
                    }
                }
            }))
        );
    }

    #[test]
    fn parses_array_end_param() {
        let parsed = parse(&["[]=foo"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!(["foo"])));
    }

    #[test]
    fn parses_nested_array_end_param() {
        let parsed = parse(&["foo[][]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [["bar"]]})));
    }

    #[test]
    fn parses_array_index_param() {
        let parsed = parse(&["[1]=foo"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([null, "foo"])));
    }

    #[test]
    fn parses_array_index_param_overwrite() {
        let parsed = parse(&["[1]=foo", "[1]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([null, "bar"])));
    }

    #[test]
    fn parses_nested_array_index_param() {
        let parsed = parse(&["foo[0][0]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [["bar"]]})));
    }

    #[test]
    fn parses_complex_param() {
        let parsed = parse(&["foo[][bar]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [{"bar": "baz"}]})));
    }

    #[test]
    fn parses_multiple_complex_params() {
        let parsed = parse(&[
            "foo[][bar]=baz",
            "foo[][qux]=quux",
            "foo[3][][][a][][4][][b][c][][d]=x",
        ])
        .expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": [
                    {"bar": "baz"},
                    {"qux": "quux"},
                    null,
                    [
                        [
                            {
                                "a": [
                                    [null, null, null, null, [
                                        {
                                            "b": {
                                                "c": [
                                                    {"d": "x"}
                                                ]
                                            }
                                        }
                                    ]]
                                ]
                            }
                        ]
                    ]
                ]
            }))
        );
    }

    #[test]
    fn parses_multiple_complex_params_flexible() {
        let parsed = parse(&[
            "foo[].bar=baz",
            "foo[]qux=quux",
            "foo.3[][]a[]4[].b[c][][d]=x",
        ])
        .expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": [
                    {"bar": "baz"},
                    {"qux": "quux"},
                    null,
                    [
                        [
                            {
                                "a": [
                                    [null, null, null, null, [
                                        {
                                            "b": {
                                                "c": [
                                                    {"d": "x"}
                                                ]
                                            }
                                        }
                                    ]]
                                ]
                            }
                        ]
                    ]
                ]
            }))
        );
    }

    #[test]
    fn parses_raw_json_maps() {
        let parsed = parse(&["foo:={\"bar\":\"baz\"}"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": "baz"}})));
    }

    #[test]
    fn parses_raw_json_strings() {
        let parsed = parse(&["foo:=\"bar\""]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": "bar"})));
    }

    #[test]
    fn parses_raw_json_ints() {
        let parsed = parse(&["foo:=1"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": 1})));
    }

    #[test]
    fn parses_raw_json_nulls() {
        let parsed = parse(&["foo:=null"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": null})));
    }

    #[test]
    fn sets_multiple_array_end() {
        let parsed = parse(&["foo[]=bar", "foo[]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": ["bar", "baz"]})));
    }

    #[test]
    fn sets_multiple_array_index() {
        let parsed = parse(&["foo[]=bar", "foo[]=baz", "foo[2]=qux"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": ["bar", "baz", "qux"]})));
    }

    #[test]
    fn gives_priority_to_json_then_query_then_header_then_kv() {
        let parsed = parse(&[
            "foo:=true",
            "bar==baz",
            "Authorization:Bearer token",
            "qux=value",
        ])
        .expect("parse input");

        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "bar".to_string(),
                value: "baz".to_string(),
            }]
        );
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "Authorization".to_string(),
                value: "Bearer token".to_string(),
            }]
        );
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": true,
                "qux": "value",
            }))
        );
    }

    #[test]
    fn errors_on_invalid_json_value() {
        let err = parse(&["foo:={bar"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("invalid JSON value in \"foo:={bar\""),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn errors_on_unexpected_remainder() {
        let err = parse(&["foo[bar=baz"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"foo[bar=baz\"");
    }

    #[test]
    fn preserves_sparse_array_slots_as_null() {
        let parsed = parse(&["foo[3]=bar"]).expect("parse input");
        let body = parsed.body.expect("body");
        assert_eq!(body, json!({"foo": [null, null, null, "bar"]}));
    }

    #[test]
    fn allows_repeated_query_params() {
        let parsed = parse(&["q==first", "q==second"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![
                ParsedQueryParam {
                    name: "q".to_string(),
                    value: "first".to_string()
                },
                ParsedQueryParam {
                    name: "q".to_string(),
                    value: "second".to_string()
                }
            ]
        );
    }

    #[test]
    fn overwrites_same_path_with_last_value() {
        let parsed = parse(&["foo=bar", "foo=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": "baz"})));
    }

    #[test]
    fn reports_type_mismatch_for_invalid_traversal() {
        let err = parse(&["foo=bar", "foo[0]=baz"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("attempted to access index of non-array"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn empty_body_when_only_headers_and_query() {
        let parsed = parse(&["Accept:application/json", "page==1"]).expect("parse input");
        assert_eq!(
            parsed,
            ParsedInput {
                headers: vec![ParsedHeader {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                }],
                query_params: vec![ParsedQueryParam {
                    name: "page".to_string(),
                    value: "1".to_string(),
                }],
                body: None,
            }
        );
    }

    #[test]
    fn parses_json_arrays_and_numbers_without_quotes() {
        let parsed = parse(&["items:=[1,2,3]", "rating:=4.2"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "items": [1, 2, 3],
                "rating": 4.2
            }))
        );
    }

    #[test]
    fn keeps_string_assignment_values_as_raw_strings() {
        let parsed = parse(&["foo=true", "bar=123"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": "true",
                "bar": "123"
            }))
        );
    }

    #[test]
    fn supports_root_value_overwrite() {
        let parsed = parse(&["[]=foo", "[]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!(["foo", "bar"])));
    }

    #[test]
    fn parses_nested_object_and_array_mix() {
        let parsed = parse(&["root[0].user[name]=alex"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "root": [
                    {
                        "user": {
                            "name": "alex"
                        }
                    }
                ]
            }))
        );
    }

    #[test]
    fn query_name_must_not_be_empty() {
        let err = parse(&["==value"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"==value\"");
    }

    #[test]
    fn header_name_must_match_allowed_characters() {
        let err = parse(&["hello/world:ok"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"hello/world:ok\"");
    }

    #[test]
    fn json_assignment_rejects_invalid_path() {
        let err = parse(&["foo[:=1"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"foo[:=1\"");
    }

    #[test]
    fn parse_returns_none_body_when_no_parts() {
        let parsed = parse(&[]).expect("parse input");
        assert_eq!(parsed.body, None);
        assert_eq!(parsed.headers, Vec::<ParsedHeader>::new());
        assert_eq!(parsed.query_params, Vec::<ParsedQueryParam>::new());
    }

    #[test]
    fn array_indices_use_numeric_segments() {
        let parsed = parse(&["foo.0=bar", "foo.1=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": ["bar", "baz"]})));
    }

    #[test]
    fn bracket_keys_allow_periods() {
        let parsed = parse(&["foo[bar.baz]=qux"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar.baz": "qux"}})));
    }

    #[test]
    fn supports_mixed_assignments_in_single_payload() {
        let parsed =
            parse(&["title=hello", "meta[count]:=2", "meta[tags][]=rust"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "title": "hello",
                "meta": {
                    "count": 2,
                    "tags": ["rust"]
                }
            }))
        );
    }

    #[test]
    fn json_null_can_be_replaced_by_nested_object_assignment() {
        let parsed = parse(&["foo:=null", "foo[bar]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": "baz"}})));
    }

    #[test]
    fn parses_full_old_matrix_mixed_case() {
        let parsed = parse(&[
            "foo[][bar]=baz",
            "foo[][qux]=quux",
            "foo[3][][][a][][4][][b][c][][d]=x",
            "auth-token:abc",
            "include==comments",
        ])
        .expect("parse input");

        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "auth-token".to_string(),
                value: "abc".to_string(),
            }]
        );
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "include".to_string(),
                value: "comments".to_string(),
            }]
        );

        let body = parsed.body.expect("body");
        let expected = json!({
            "foo": [
                {"bar": "baz"},
                {"qux": "quux"},
                null,
                [
                    [
                        {
                            "a": [
                                [null, null, null, null, [
                                    {
                                        "b": {
                                            "c": [
                                                {"d": "x"}
                                            ]
                                        }
                                    }
                                ]]
                            ]
                        }
                    ]
                ]
            ]
        });

        assert_eq!(body, expected);
    }

    #[test]
    fn keeps_query_value_with_additional_equals() {
        let parsed = parse(&["q==a=b=c"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "q".to_string(),
                value: "a=b=c".to_string(),
            }]
        );
    }

    #[test]
    fn allows_empty_header_value() {
        let parsed = parse(&["x-empty:"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "x-empty".to_string(),
                value: String::new(),
            }]
        );
    }

    #[test]
    fn allows_empty_query_value() {
        let parsed = parse(&["page=="]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "page".to_string(),
                value: String::new(),
            }]
        );
    }

    #[test]
    fn rejects_empty_path_assignments() {
        let err = parse(&["=value"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"=value\"");
    }

    #[test]
    fn rejects_header_with_missing_name() {
        let err = parse(&[":value"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \":value\"");
    }

    #[test]
    fn keeps_json_objects_and_subsequent_overrides() {
        let parsed = parse(&["foo:={\"bar\":1}", "foo[bar]=2"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": "2"}})));
    }

    #[test]
    fn handles_root_index_then_nested_object() {
        let parsed = parse(&["[0][name]=bob"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([{"name": "bob"}])));
    }

    #[test]
    fn parses_dot_notation_object_chain() {
        let parsed = parse(&["config.database.host=localhost"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "config": {
                    "database": {
                        "host": "localhost"
                    }
                }
            }))
        );
    }

    #[test]
    fn parses_json_array_root_element() {
        let parsed = parse(&["items[0]:={\"id\":1}"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"items": [{"id": 1}]})));
    }

    #[test]
    fn handles_path_with_adjacent_segments_without_separators() {
        let parsed = parse(&["foo[]bar[0]baz=qux"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({
                "foo": [
                    {
                        "bar": [
                            {"baz": "qux"}
                        ]
                    }
                ]
            }))
        );
    }

    #[test]
    fn query_and_header_do_not_create_body() {
        let parsed = parse(&["accept:application/json", "q==search"]).expect("parse input");
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn permissive_path_allows_closing_brackets_in_plain_keys() {
        let parsed = parse(&["foo[]]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [{"]": "bar"}]})));
    }

    #[test]
    fn parse_input_is_stable_for_large_nested_path() {
        let parsed = parse(&["a[0][0][0][0][0]=z"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"a": [[[[["z"]]]]]})));
    }

    #[test]
    fn parse_json_number_assignment() {
        let parsed = parse(&["count:=10"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"count": 10})));
    }

    #[test]
    fn parse_json_boolean_assignment() {
        let parsed = parse(&["enabled:=false"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"enabled": false})));
    }

    #[test]
    fn parse_string_assignment_with_spaces() {
        let parsed = parse(&["title=this is a title"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"title": "this is a title"})));
    }

    #[test]
    fn parse_mixed_header_query_body_in_order() {
        let parsed = parse(&["x-id:123", "page==2", "name=alice"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "x-id".to_string(),
                value: "123".to_string(),
            }]
        );
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "page".to_string(),
                value: "2".to_string(),
            }]
        );
        assert_eq!(parsed.body, Some(json!({"name": "alice"})));
    }

    #[test]
    fn parse_json_overwrites_existing_string_path() {
        let parsed = parse(&["foo=bar", "foo:=true"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": true})));
    }

    #[test]
    fn parse_assignment_with_bracket_index_and_append() {
        let parsed = parse(&["items[1]=b", "items[]=c"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"items": [null, "b", "c"]})));
    }

    #[test]
    fn parse_query_name_with_colon_is_allowed() {
        let parsed = parse(&["a:b==c"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "a:b".to_string(),
                value: "c".to_string(),
            }]
        );
    }

    #[test]
    fn parse_header_name_with_underscore_is_allowed() {
        let parsed = parse(&["x_token:abc"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "x_token".to_string(),
                value: "abc".to_string(),
            }]
        );
    }

    #[test]
    fn parse_access_path_can_start_with_array_end() {
        let parsed = parse(&["[][a]=b"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([{"a": "b"}])));
    }

    #[test]
    fn parse_access_path_can_start_with_bare_index() {
        let parsed = parse(&["0=foo"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!(["foo"])));
    }

    #[test]
    fn parse_access_path_can_mix_dot_and_bracket_indices() {
        let parsed = parse(&["foo.1[0]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [null, ["bar"]]})));
    }

    #[test]
    fn rejects_invalid_json_even_if_other_formats_might_match() {
        let err = parse(&["foo:={not-json}"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("invalid JSON value in \"foo:={not-json}\""),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_query_then_body_does_not_conflict() {
        let parsed = parse(&["foo==bar", "foo=baz"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "foo".to_string(),
                value: "bar".to_string(),
            }]
        );
        assert_eq!(parsed.body, Some(json!({"foo": "baz"})));
    }

    #[test]
    fn parse_preserves_header_case() {
        let parsed = parse(&["X-Custom:Value"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "X-Custom".to_string(),
                value: "Value".to_string(),
            }]
        );
    }

    #[test]
    fn parse_body_with_multiple_root_array_paths() {
        let parsed = parse(&["[2]=z", "[]=y"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([null, null, "z", "y"])));
    }

    #[test]
    fn permissive_path_allows_extra_brackets_in_plain_keys() {
        let parsed = parse(&["foo[bar]]]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": {"]]": "baz"}}})));
    }

    #[test]
    fn parse_body_handles_large_index_growth() {
        let parsed = parse(&["foo[5]=x"]).expect("parse input");
        assert_eq!(
            parsed.body,
            Some(json!({"foo": [null, null, null, null, null, "x"]}))
        );
    }

    #[test]
    fn parse_header_value_may_contain_colons() {
        let parsed = parse(&["Authorization:Bearer a:b:c"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "Authorization".to_string(),
                value: "Bearer a:b:c".to_string(),
            }]
        );
    }

    #[test]
    fn parse_query_value_may_contain_spaces_and_symbols() {
        let parsed = parse(&["q==foo bar:baz/qux"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "q".to_string(),
                value: "foo bar:baz/qux".to_string(),
            }]
        );
    }

    #[test]
    fn parse_body_string_value_may_contain_equals() {
        let parsed = parse(&["token=abc=def"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"token": "abc=def"})));
    }

    #[test]
    fn parse_body_string_value_may_be_empty() {
        let parsed = parse(&["token="]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"token": ""})));
    }

    #[test]
    fn parse_json_value_may_be_array() {
        let parsed = parse(&["tags:=[\"a\",\"b\"]"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"tags": ["a", "b"]})));
    }

    #[test]
    fn parse_json_value_may_be_object() {
        let parsed = parse(&["cfg:={\"a\":1}"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"cfg": {"a": 1}})));
    }

    #[test]
    fn parse_complex_mixed_case_with_all_component_types() {
        let parsed = parse(&[
            "X-Trace:abc",
            "q==search term",
            "user[name]=Jane",
            "user[active]:=true",
        ])
        .expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![ParsedHeader {
                name: "X-Trace".to_string(),
                value: "abc".to_string(),
            }]
        );
        assert_eq!(
            parsed.query_params,
            vec![ParsedQueryParam {
                name: "q".to_string(),
                value: "search term".to_string(),
            }]
        );
        assert_eq!(
            parsed.body,
            Some(json!({
                "user": {
                    "name": "Jane",
                    "active": true
                }
            }))
        );
    }

    #[test]
    fn parse_result_is_deterministic() {
        let first = parse(&["foo[1]=a", "foo[]=b"]).expect("parse input");
        let second = parse(&["foo[1]=a", "foo[]=b"]).expect("parse input");
        assert_eq!(first, second);
    }

    #[test]
    fn parse_body_appends_after_sparse_index() {
        let parsed = parse(&["items[2]=c", "items[]=d"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"items": [null, null, "c", "d"]})));
    }

    #[test]
    fn parse_handles_nested_empty_object_then_assignment() {
        let parsed = parse(&["foo:={}", "foo[bar]=baz"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": {"bar": "baz"}})));
    }

    #[test]
    fn parse_handles_nested_empty_array_then_append() {
        let parsed = parse(&["foo:=[]", "foo[]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": ["bar"]})));
    }

    #[test]
    fn parse_mixed_root_array_and_object_is_rejected() {
        let err = parse(&["[]=foo", "[0][bar]=baz"]).expect_err("expected type mismatch");
        assert!(
            err.to_string()
                .starts_with("attempted to access key of non-object"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_preserves_query_order() {
        let parsed = parse(&["a==1", "b==2", "a==3"]).expect("parse input");
        assert_eq!(
            parsed.query_params,
            vec![
                ParsedQueryParam {
                    name: "a".to_string(),
                    value: "1".to_string(),
                },
                ParsedQueryParam {
                    name: "b".to_string(),
                    value: "2".to_string(),
                },
                ParsedQueryParam {
                    name: "a".to_string(),
                    value: "3".to_string(),
                },
            ]
        );
    }

    #[test]
    fn parse_headers_allow_multiple_with_same_name() {
        let parsed = parse(&["X-Test:one", "X-Test:two"]).expect("parse input");
        assert_eq!(
            parsed.headers,
            vec![
                ParsedHeader {
                    name: "X-Test".to_string(),
                    value: "one".to_string(),
                },
                ParsedHeader {
                    name: "X-Test".to_string(),
                    value: "two".to_string(),
                },
            ]
        );
    }

    #[test]
    fn parse_empty_input_returns_empty_parsed_input() {
        let parsed = parse(&[]).expect("parse input");
        assert_eq!(parsed, ParsedInput::default());
    }

    #[test]
    fn parse_path_type_conflict_from_object_to_array() {
        let err = parse(&["foo[bar]=baz", "foo[bar][0]=qux"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("attempted to access index of non-array"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_path_type_conflict_from_array_to_object() {
        let err = parse(&["foo[0]=baz", "foo[0][bar]=qux"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("attempted to access key of non-object"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_body_order_and_overwrites_match_input_order() {
        let parsed = parse(&["foo=1", "foo=2", "foo[bar]=3"]).expect_err("expected type mismatch");
        assert!(
            parsed
                .to_string()
                .starts_with("attempted to access key of non-object"),
            "unexpected error: {parsed}"
        );
    }

    #[test]
    fn parse_json_parser_precedence_over_header() {
        let parsed = parse(&["foo:=\"bar\""]).expect("parse input");
        assert_eq!(parsed.headers.len(), 0);
        assert_eq!(parsed.body, Some(json!({"foo": "bar"})));
    }

    #[test]
    fn parse_query_parser_precedence_over_string_assignment() {
        let parsed = parse(&["foo==bar"]).expect("parse input");
        assert_eq!(parsed.query_params.len(), 1);
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn parse_header_parser_precedence_over_string_assignment() {
        let parsed = parse(&["foo:bar"]).expect("parse input");
        assert_eq!(parsed.headers.len(), 1);
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn parse_invalid_token_returns_unexpected_input_error() {
        let err = parse(&["foo[bar"]).expect_err("expected error");
        assert_eq!(err.to_string(), "unexpected input: \"foo[bar\"");
    }

    #[test]
    fn parse_json_error_includes_token() {
        let err = parse(&["foo:=not-json"]).expect_err("expected error");
        assert!(
            err.to_string()
                .starts_with("invalid JSON value in \"foo:=not-json\""),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_access_path_root_array_append_then_object() {
        let parsed = parse(&["[][x]=1"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([{"x": "1"}])));
    }

    #[test]
    fn parse_access_path_root_index_then_append() {
        let parsed = parse(&["[1]=a", "[]=b"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!([null, "a", "b"])));
    }

    #[test]
    fn parse_access_path_plain_digits_become_array_indices() {
        let parsed = parse(&["foo.1=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [null, "bar"]})));
    }

    #[test]
    fn parse_access_path_bracketed_digits_become_array_indices() {
        let parsed = parse(&["foo[1]=bar"]).expect("parse input");
        assert_eq!(parsed.body, Some(json!({"foo": [null, "bar"]})));
    }

    #[test]
    fn parse_access_path_dot_digits_become_array_indices() {
        let parsed = parse(&["foo.10=bar"]).expect("parse input");
        let mut expected = vec![Value::Null; 11];
        expected[10] = Value::String("bar".to_string());
        assert_eq!(parsed.body, Some(json!({"foo": expected})));
    }
}
