use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[test]
fn get_prints_response_body_to_stdout() {
    let body = "hello from server";
    let (url, request_handle) =
        spawn_server("/simple", "200 OK", &[("content-type", "text/plain")], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .arg(url)
        .output()
        .expect("failed to run get");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    assert!(output.stderr.is_empty(), "expected empty stderr");

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("GET /simple HTTP/1.1\r\n"));
}

#[test]
fn completions_command_writes_bash_script() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["completions", "bash"])
        .output()
        .expect("failed to run get completions bash");

    assert!(output.status.success(), "expected success, got: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("COMPLETE=\"bash\""),
        "expected dynamic bash script"
    );
    assert!(
        stdout.contains("\"get\" --"),
        "completion script should call get"
    );
    assert!(output.stderr.is_empty(), "expected empty stderr");
}

#[test]
fn completions_command_uses_shell_env_when_not_provided() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .arg("completions")
        .env("SHELL", "/bin/zsh")
        .output()
        .expect("failed to run get completions");

    assert!(output.status.success(), "expected success, got: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("#compdef get"),
        "expected zsh completion output"
    );
    assert!(
        stdout.contains("COMPLETE=\"zsh\""),
        "expected dynamic zsh script"
    );
    assert!(output.stderr.is_empty(), "expected empty stderr");
}

#[test]
fn dynamic_completion_env_request_returns_candidates() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["--", "get", "--he"])
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "1")
        .env("_CLAP_COMPLETE_COMP_TYPE", "9")
        .env("_CLAP_COMPLETE_SPACE", "true")
        .output()
        .expect("failed to run dynamic completion request");

    assert!(output.status.success(), "expected success, got: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--help"),
        "expected --help completion candidate"
    );
    assert!(output.stderr.is_empty(), "expected empty stderr");
}

#[test]
fn stream_prints_response_body_to_stdout() {
    let body = "hello streamed response";
    let (url, request_handle) =
        spawn_server("/stream", "200 OK", &[("content-type", "text/plain")], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-s", &url])
        .output()
        .expect("failed to run get -s");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    assert!(output.stderr.is_empty(), "expected empty stderr");

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("GET /stream HTTP/1.1\r\n"));
}

#[test]
fn stream_writes_body_incrementally() {
    let chunks = vec!["chunk one", "chunk two", "chunk three"];
    let body_chunks = chunks;
    let (url, request_handle) = spawn_server_stream_chunks(
        "/streamed-chunks",
        "200 OK",
        &[],
        body_chunks.as_slice(),
        450,
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-s", &url])
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run get -s");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_for_reader = Arc::clone(&output);

    let output_handle = thread::spawn(move || {
        let mut buffer = [0_u8; 128];
        loop {
            let n = stdout.read(&mut buffer).expect("read stdout");
            if n == 0 {
                break;
            }
            output_for_reader
                .lock()
                .unwrap()
                .extend_from_slice(&buffer[..n]);
        }
    });

    let wait = |predicate: &dyn Fn(&Vec<u8>) -> bool| -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if predicate(&output.lock().unwrap()) {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        predicate(&output.lock().unwrap())
    };

    assert!(
        wait(&|received| {
            let response = String::from_utf8_lossy(received).to_string();
            response.starts_with("chunk one")
        }),
        "expected first chunk before timeout"
    );

    let mid = output.lock().unwrap().len();
    thread::sleep(Duration::from_millis(250));
    assert!(
        output.lock().unwrap().len() < "chunk onechunk twochunk three".len(),
        "expected streaming to be incremental"
    );
    assert_eq!(mid, "chunk one".len());

    let mut final_output = String::new();
    let status = child.wait().expect("wait for child");
    output_handle.join().expect("stdout reader thread panicked");

    let output = output.lock().unwrap();
    final_output.push_str(&String::from_utf8_lossy(&output));
    assert_eq!(final_output, "chunk onechunk twochunk three");
    assert!(status.success());

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("GET /streamed-chunks HTTP/1.1\r\n"));
}

#[test]
fn method_flag_sets_http_method() {
    let body = "method is set";
    let (url, request_handle) = spawn_server_with_method("POST", "/method", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-X", "POST", &url])
        .output()
        .expect("failed to run get -X POST");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    assert!(output.stderr.is_empty(), "expected empty stderr");

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("POST /method HTTP/1.1\r\n"));
}

#[test]
fn header_argument_sends_custom_header() {
    let body = "header set";
    let (url, request_handle) = spawn_server("/headers", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([&url, "Authorization:Bearer test-token"])
        .output()
        .expect("failed to run get with custom header");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    assert!(output.stderr.is_empty(), "expected empty stderr");

    let request = request_handle.join().expect("server thread panicked");
    let request_lc = request.to_ascii_lowercase();
    assert!(request_lc.contains("\r\nauthorization: bearer test-token\r\n"));
}

#[test]
fn dry_run_does_not_send_request() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["--dry-run", "http://127.0.0.1:1/dry-run"])
        .output()
        .expect("failed to run get --dry-run");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert!(output.stdout.is_empty(), "expected no stdout output");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> GET /dry-run HTTP/1.1"));
    assert!(stderr.contains("> host: 127.0.0.1:1"));
    assert!(stderr.contains("> accept: */*"));
    assert!(stderr.contains("> user-agent: get/"));
}

#[test]
fn dry_run_prints_request_body_to_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([
            "--dry-run",
            "http://127.0.0.1:1/dry-run",
            "title=this is the title",
        ])
        .output()
        .expect("failed to run get --dry-run with body");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert!(output.stdout.is_empty(), "expected no stdout output");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> POST /dry-run HTTP/1.1"));
    assert!(stderr.contains("> {\"title\":\"this is the title\"}"));
}

#[test]
fn dry_run_with_form_prints_form_body_to_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([
            "--dry-run",
            "--form",
            "http://127.0.0.1:1/dry-run",
            "title=this is the title",
        ])
        .output()
        .expect("failed to run get --dry-run --form with body");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert!(output.stdout.is_empty(), "expected no stdout output");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> POST /dry-run HTTP/1.1"));
    assert!(stderr.contains("> content-type: application/x-www-form-urlencoded"));
    assert!(stderr.contains("> title=this+is+the+title"));
}

#[test]
fn verbose_prints_request_and_response_headers_to_stderr() {
    let body = "verbose response";
    let (url, request_handle) = spawn_server(
        "/verbose?x=1",
        "200 OK",
        &[("x-test", "yes"), ("server", "test")],
        body,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-v", &url])
        .output()
        .expect("failed to run get -v");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let host = url
        .strip_prefix("http://")
        .expect("http URL")
        .split('/')
        .next()
        .expect("host segment");
    assert!(stderr.contains("> GET /verbose?x=1 HTTP/1.1"));
    assert!(stderr.contains("> accept: */*"));
    assert!(stderr.contains("> user-agent: get/"));
    assert!(stderr.contains(&format!("> host: {host}")));
    assert!(stderr.contains("< HTTP/1.1 200 OK"));
    assert!(stderr.contains("< x-test: yes"));

    let request = request_handle.join().expect("server thread panicked");
    let request_lc = request.to_ascii_lowercase();
    assert!(request_lc.contains("\r\naccept: */*\r\n"));
    assert!(request_lc.contains("\r\nuser-agent: get/"));
}

#[test]
fn verbose_prints_request_body_to_stderr() {
    let body = "verbose request body";
    let (url, request_handle) =
        spawn_server_with_method("POST", "/verbose-body", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-v", &url, "title=this is the title"])
        .output()
        .expect("failed to run get -v with body");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> POST /verbose-body HTTP/1.1"));
    assert!(stderr.contains("> content-type: application/json"));
    assert!(stderr.contains("> {\"title\":\"this is the title\"}"));

    let request = request_handle.join().expect("server thread panicked");
    assert_json_body(&request, json!({"title": "this is the title"}));
}

#[test]
fn no_body_does_not_print_response_body() {
    let body = "hidden body";
    let (url, request_handle) = spawn_server(
        "/no-body",
        "200 OK",
        &[("content-type", "text/plain")],
        body,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-B", &url])
        .output()
        .expect("failed to run get -B");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert!(output.stdout.is_empty(), "expected no stdout output");
    assert!(output.stderr.is_empty(), "expected no stderr output");

    request_handle.join().expect("server thread panicked");
}

#[test]
fn body_input_defaults_to_post_method() {
    let body = "created";
    let (url, request_handle) = spawn_server_with_method("POST", "/auto-post", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([&url, "title=this is the title"])
        .output()
        .expect("failed to run get with body input");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("POST /auto-post HTTP/1.1\r\n"));
    assert_json_body(&request, json!({"title": "this is the title"}));
}

#[test]
fn explicit_method_overrides_auto_post() {
    let body = "ok";
    let (url, request_handle) =
        spawn_server_with_method("GET", "/method-override", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["-X", "GET", &url, "title=this is the title"])
        .output()
        .expect("failed to run get with explicit method and body");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("GET /method-override HTTP/1.1\r\n"));
    assert_json_body(&request, json!({"title": "this is the title"}));
}

#[test]
fn mixed_inputs_set_header_and_json_body() {
    let body = "created";
    let (url, request_handle) = spawn_server_with_method("POST", "/issues", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([
            "-X",
            "POST",
            &url,
            "Authorization:Bearer foo",
            "title=this is the title",
            "foo[bar]:=true",
        ])
        .output()
        .expect("failed to run get with mixed parser inputs");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let request = request_handle.join().expect("server thread panicked");
    let request_lc = request.to_ascii_lowercase();
    assert!(request.starts_with("POST /issues HTTP/1.1\r\n"));
    assert!(request_lc.contains("\r\nauthorization: bearer foo\r\n"));
    assert!(request_lc.contains("\r\ncontent-type: application/json\r\n"));
    assert_json_body(
        &request,
        json!({
            "title": "this is the title",
            "foo": {"bar": true}
        }),
    );
}

#[test]
fn form_flag_sets_content_type_and_urlencodes_body() {
    let body = "created";
    let (url, request_handle) = spawn_server_with_method("POST", "/form", "200 OK", &[], body);

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args(["--form", &url, "title=this is the title", "foo[bar]:=true"])
        .output()
        .expect("failed to run get --form");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let request = request_handle.join().expect("server thread panicked");
    let request_lc = request.to_ascii_lowercase();
    assert!(request.starts_with("POST /form HTTP/1.1\r\n"));
    assert!(request_lc.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"));
    assert_form_body(
        &request,
        &[("title", "this is the title"), ("foo[bar]", "true")],
    );
}

#[test]
fn query_inputs_append_query_params_and_repeat_keys() {
    let body = "query response";
    let (url, request_handle) = spawn_server_with_method_and_url(
        "GET",
        "/query",
        "/query?q=one&q=two",
        "200 OK",
        &[],
        body,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .args([&url, "q==one", "q==two"])
        .output()
        .expect("failed to run get with query inputs");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);

    let request = request_handle.join().expect("server thread panicked");
    assert!(request.starts_with("GET /query?q=one&q=two HTTP/1.1\r\n"));
}

#[cfg(unix)]
#[test]
fn unix_socket_get_prints_response_body() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let sock_path = dir.path().join("test.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

    let response = build_response("200 OK", &[("content-type", "text/plain")], "hello unix");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept unix client");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");
        let request = read_unix_request(&mut stream);
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush response");
        request
    });

    let url = format!("unix:{}:/simple", sock_path.display());
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .arg(&url)
        .output()
        .expect("failed to run get with unix socket");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello unix");

    let request = handle.join().expect("server thread panicked");
    assert!(
        request.starts_with("GET /simple HTTP/1.1\r\n"),
        "unexpected request: {request}"
    );
}

#[cfg(unix)]
#[test]
fn unix_socket_slash_prefix_works() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let sock_path = dir.path().join("slash.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

    let response = build_response("200 OK", &[("content-type", "text/plain")], "slash prefix");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept unix client");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");
        let request = read_unix_request(&mut stream);
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush response");
        request
    });

    let url = format!("{}:/path", sock_path.display());
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .arg(&url)
        .output()
        .expect("failed to run get with slash-prefix unix socket");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "slash prefix");

    let request = handle.join().expect("server thread panicked");
    assert!(
        request.starts_with("GET /path HTTP/1.1\r\n"),
        "unexpected request: {request}"
    );
}

#[cfg(unix)]
#[test]
fn unix_socket_defaults_path_to_root() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let sock_path = dir.path().join("root.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

    let response = build_response("200 OK", &[("content-type", "text/plain")], "root path");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept unix client");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");
        let request = read_unix_request(&mut stream);
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush response");
        request
    });

    let url = format!("unix:{}:", sock_path.display());
    let output = Command::new(env!("CARGO_BIN_EXE_get"))
        .arg(&url)
        .output()
        .expect("failed to run get with unix socket default path");

    assert!(output.status.success(), "expected success, got: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "root path");

    let request = handle.join().expect("server thread panicked");
    assert!(
        request.starts_with("GET / HTTP/1.1\r\n"),
        "unexpected request: {request}"
    );
}

#[cfg(unix)]
fn read_unix_request(stream: &mut std::os::unix::net::UnixStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut content_length = None;
    let mut header_end = None;

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                if header_end.is_none() {
                    if let Some(end) = find_header_end(&bytes) {
                        header_end = Some(end);
                        content_length = parse_content_length(&bytes[..end]);
                        if content_length == Some(0) {
                            break;
                        }
                    }
                }

                if let (Some(end), Some(length)) = (header_end, content_length) {
                    if bytes.len() >= end + length {
                        break;
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => panic!("failed reading unix request: {error}"),
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn spawn_server(
    expected_path_and_query: &str,
    status: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, JoinHandle<String>) {
    spawn_server_with_method_and_url(
        "GET",
        expected_path_and_query,
        expected_path_and_query,
        status,
        headers,
        body,
    )
}

fn spawn_server_with_method(
    expected_method: &str,
    expected_path_and_query: &str,
    status: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, JoinHandle<String>) {
    spawn_server_with_method_and_url(
        expected_method,
        expected_path_and_query,
        expected_path_and_query,
        status,
        headers,
        body,
    )
}

fn spawn_server_with_method_and_url(
    expected_method: &str,
    url_path_and_query: &str,
    expected_path_and_query: &str,
    status: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let response = build_response(status, headers, body);
    let expected_request_line = format!("{expected_method} {expected_path_and_query} HTTP/1.1\r\n");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");

        let request = read_http_request(&mut stream);
        assert!(
            request.starts_with(&expected_request_line),
            "unexpected request line: {request:?}"
        );

        stream
            .write_all(response.as_bytes())
            .expect("write HTTP response");
        stream.flush().expect("flush response");
        request
    });

    (format!("http://{addr}{url_path_and_query}"), handle)
}

fn spawn_server_stream_chunks(
    expected_path_and_query: &str,
    status: &str,
    headers: &[(&str, &str)],
    chunks: &[&str],
    delay_ms: u64,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let expected_path = expected_path_and_query.to_string();
    let expected_request_line = format!("GET {expected_path} HTTP/1.1\r\n");
    let chunks = chunks
        .iter()
        .map(|chunk| chunk.to_string())
        .collect::<Vec<_>>();
    let delay = Duration::from_millis(delay_ms);
    let response = {
        let mut response = format!("HTTP/1.1 {status}\r\nconnection: close\r\n");
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response
    };

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");

        let request = read_http_request(&mut stream);
        assert!(
            request.starts_with(&expected_request_line),
            "unexpected request line: {request:?}"
        );

        stream
            .write_all(response.as_bytes())
            .expect("write response headers");
        stream.flush().expect("flush response headers");

        for (index, chunk) in chunks.iter().enumerate() {
            stream.write_all(chunk.as_bytes()).expect("write chunk");
            stream.flush().expect("flush chunk");
            if index + 1 < chunks.len() {
                thread::sleep(delay);
            }
        }
        stream.flush().expect("flush response");
        request
    });

    (format!("http://{addr}{expected_path}"), handle)
}

fn build_response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    response
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut content_length = None;
    let mut header_end = None;

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                if header_end.is_none() {
                    if let Some(end) = find_header_end(&bytes) {
                        header_end = Some(end);
                        content_length = parse_content_length(&bytes[..end]);
                        if content_length == Some(0) {
                            break;
                        }
                    }
                }

                if let (Some(end), Some(length)) = (header_end, content_length) {
                    if bytes.len() >= end + length {
                        break;
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => panic!("failed reading request: {error}"),
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|chunk| chunk == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_content_length(header_bytes: &[u8]) -> Option<usize> {
    let header_str = String::from_utf8_lossy(header_bytes);
    header_str
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.eq_ignore_ascii_case("content-length") {
                return None;
            }
            value.trim().parse::<usize>().ok()
        })
        .or(Some(0))
}

fn assert_json_body(request: &str, expected: Value) {
    let body = request_body(request);
    let parsed: Value = serde_json::from_str(body).expect("request body should be JSON");
    assert_eq!(parsed, expected);
}

fn assert_form_body(request: &str, expected: &[(&str, &str)]) {
    let body = request_body(request);
    let parsed = parse_form_body(body);

    assert_eq!(
        parsed.len(),
        expected.len(),
        "unexpected encoded form body: {body}"
    );

    for (expected_key, expected_value) in expected {
        assert!(
            parsed.contains(&(expected_key.to_string(), expected_value.to_string())),
            "missing {expected_key}={expected_value} in form body: {body}"
        );
    }
}

fn parse_form_body(body: &str) -> Vec<(String, String)> {
    if body.is_empty() {
        return vec![];
    }

    body.split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_component(key), decode_form_component(value))
        })
        .collect()
}

fn decode_form_component(component: &str) -> String {
    let mut output = Vec::with_capacity(component.len());
    let bytes = component.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                output.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (decode_hex(bytes[i + 1]), decode_hex(bytes[i + 2]))
                {
                    output.push((high << 4) | low);
                    i += 3;
                } else {
                    output.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                output.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(output).expect("form value should be valid UTF-8")
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default()
}
