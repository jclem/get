use std::io::{Read, Write};
use std::net::TcpListener;
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
            let response = String::from_utf8_lossy(&received).to_string();
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

fn spawn_server(
    expected_path_and_query: &str,
    status: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let response = build_response(status, headers, body);
    let expected_request_line = format!("GET {expected_path_and_query} HTTP/1.1\r\n");

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

    (format!("http://{addr}{expected_path_and_query}"), handle)
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

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                if bytes.windows(4).any(|chunk| chunk == b"\r\n\r\n") {
                    break;
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
