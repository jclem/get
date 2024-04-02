# Get

Get is a CLI for making HTTP requests.

## Installation

```shell
go install github.com/jclem/get@latest
```

## Usage

This CLI is still rudimentary compared to [httpie](https://httpie.io/cli),
especially in terms of parsing JSON body paths and supporting other request body
types (no file support, etc). Your mileage may vary.

It accepts a URL and a list of request options, and makes an HTTP request to the
specified URL. The request options can be used to specify headers, query
parameters, and a request body.

### Request Options

#### Headers

HTTP headers are specified using Key:Value syntax. For example, to specify a
header named "Accept" with a value of "application/json", you would use:

    get example.com accept:application/json
	
Note that HTTP header names are canonicalized automatically, so "Accept" would
be sent, in this case, not "accept".

#### Query Parameters

Query parameters are specified using Key==Value syntax. For example, to specify
a query parameter named "q" with a value of "foo", you would use:

    get example.com q==foo

#### Request Body

Request bodies can be specified using the format `<path>[:]=<value>`. For example,
to specify a request body of `{"foo":"bar"}`, you would use:

    get example.com foo=bar

The value is parsed as a string, unless a colon is present, in which case the
value is parsed as JSON. For example, to specify a request body of
`{"foo": true}`, you would use:

    get example.com foo:=true

Paths can be used to specify more complex request bodies, and they can be nested.

    foo[bar]=baz // {"foo":{"bar":"baz"}} Sets an object value.
    foo[]=bar    // {"foo":["bar"]} Pushes a value onto an array.
    foo[1]=bar   // {"foo":[null,"bar"]} Sets a value at a specific index in an array.

As a more complex example:

    get example.com foo[bar][baz]=qux foo[quux][]:='{"corge":"grault"}' foo[quux][0][graply]=waldo

Would result in the following request body:

```json
{
  "foo": {
    "bar": {
      "baz": "qux"
    },
    "quux": [
      {
        "corge": "grault",
        "graply": "waldo"
      }
    ]
  }
}
```

```text
Get is a command-line interface for making HTTP requests.

Usage:
  get <url> [request-options] [flags]
  get [command]

Available Commands:
  completion                        Generate the autocompletion script for the specified shell
  help                              Help about any command
  session                           Manage sessions

Flags:
      --config string      Path to the configuration file (defaults to $XDG_CONFIG_HOME/get/config.json)
  -d, --data string        Data to send in the request body
      --form               Send input as form data instead of JSON
  -h, --help               help for get
      --http               Use HTTP instead of HTTPS, regardless of session configuration
      --https              Use HTTPS instead of HTTP, regardless of session configuration
  -X, --method string      HTTP method to use (default "GET")
  -B, --no-body            Do not print the response body
  -H, --no-headers         Do not print the response headers
      --no-highlight       Do not format or highlight input or output
  -S, --no-session         Do not use a stored session if one exists for this host
      --save-all-headers   Save all request headers to the session
  -s, --session string     Session name to use (defaults to URL host)
  -t, --stream             Stream the response body (implies --no-highlight of output)
  -v, --verbose            Print verbose output

Use "get [command] --help" for more information about a command.
```

## Configuration

Get can be configured using the configuration file located by default at
$XDG_CONFIG_PATH/get/config.json.

- fallback_hostname: The hostname to use when no hostname is specified (for
	example, if the host is simply ":3000").
- http_hostnames: A list of hostnames that are considered HTTP hostnames. By
	default, these hosts will use HTTP unless otherwise noted by flag or session.
