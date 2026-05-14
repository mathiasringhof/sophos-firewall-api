#![cfg(feature = "blocking-http")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sophos_firewall::{Error, HttpTransport, SophosConnection, SophosTransport};

fn connection(verify_tls: bool) -> SophosConnection {
    SophosConnection {
        host: "firewall.example".to_string(),
        username: "api-user".to_string(),
        password: "super-secret".to_string(),
        port: 4444,
        verify_tls,
    }
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout can be set");

    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let read = stream.read(&mut buffer).expect("request bytes read");
        assert_ne!(read, 0, "client closed before sending a full request");
        bytes.extend_from_slice(&buffer[..read]);

        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("valid content-length"))
            })
            .unwrap_or(0);

        if bytes.len() >= body_start + content_length {
            return String::from_utf8(bytes).expect("HTTP request is UTF-8 for this test");
        }
    }
}

fn fake_api_url(listener: &TcpListener) -> String {
    format!(
        "http://{}/webconsole/APIController",
        listener.local_addr().expect("local address")
    )
}

fn serve_once(status_line: &'static str, body: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fake server binds");
    let url = fake_api_url(&listener);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("client connects");
        let request = read_http_request(&mut stream);
        tx.send(request).expect("request is captured");

        write!(
            stream,
            "{status_line}\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("response is written");
    });

    (url, rx)
}

fn serve_once_closing_without_response() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fake server binds");
    let url = fake_api_url(&listener);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("client connects");
        let request = read_http_request(&mut stream);
        tx.send(request).expect("request is captured");
    });

    (url, rx)
}

#[test]
fn blocking_http_transport_posts_reqxml_form_and_returns_response_body() {
    let response_xml = "<Response><Status code=\"200\">ok</Status></Response>";
    let (api_url, captured_request) = serve_once("HTTP/1.1 200 OK", response_xml);
    let transport = HttpTransport::from_connection(&connection(true)).expect("transport builds");
    let request_xml = "<Request><Login><Username>api-user</Username><Password>super-secret</Password></Login></Request>";

    let response = transport
        .send_xml(&api_url, request_xml)
        .expect("HTTP response body is returned");

    assert_eq!(response, response_xml);

    let request = captured_request
        .recv_timeout(Duration::from_secs(5))
        .expect("server captured request");
    assert!(request.starts_with("POST /webconsole/APIController HTTP/1.1"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("accept: application/xml"),
        "request should include Accept: application/xml:\n{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"),
        "request should be form encoded:\n{request}"
    );
    assert!(
        request.contains("reqxml=%3CRequest%3E"),
        "request body should include form field reqxml=<request_xml>:\n{request}"
    );
    assert!(
        request.contains("%3CPassword%3Esuper-secret%3C%2FPassword%3E"),
        "form body should contain the XML payload under reqxml:\n{request}"
    );
}

#[test]
fn blocking_http_transport_maps_transport_failure_without_leaking_xml_or_password() {
    let (api_url, captured_request) = serve_once_closing_without_response();
    let transport = HttpTransport::from_connection(&connection(true)).expect("transport builds");
    let request_xml = "<Request><Login><Username>api-user</Username><Password>super-secret</Password></Login></Request>";

    let error = transport
        .send_xml(&api_url, request_xml)
        .expect_err("connection failure should become a transport error");

    assert!(matches!(error, Error::Transport(_)));
    let message = error.to_string();
    assert!(
        !message.contains("super-secret"),
        "password leaked: {message}"
    );
    assert!(
        !message.contains("<Request"),
        "request XML leaked: {message}"
    );
    assert!(
        !message.contains("%3CRequest"),
        "encoded request XML leaked: {message}"
    );

    captured_request
        .recv_timeout(Duration::from_secs(5))
        .expect("server still receives the attempted request");
}

#[test]
fn blocking_http_transport_maps_non_success_status_without_leaking_xml_or_password() {
    let echoed_sensitive_body =
        "<error><Password>super-secret</Password><Request>do not log me</Request></error>";
    let (api_url, captured_request) =
        serve_once("HTTP/1.1 503 Service Unavailable", echoed_sensitive_body);
    let transport = HttpTransport::from_connection(&connection(false)).expect("transport builds");
    let request_xml = "<Request><Login><Username>api-user</Username><Password>super-secret</Password></Login></Request>";

    let error = transport
        .send_xml(&api_url, request_xml)
        .expect_err("non-success HTTP status should fail");

    assert!(matches!(error, Error::Transport(_)));
    let message = error.to_string();
    assert!(
        message.contains("503"),
        "status should be visible: {message}"
    );
    assert!(
        !message.contains("super-secret"),
        "password leaked: {message}"
    );
    assert!(
        !message.contains("<Request"),
        "request XML leaked: {message}"
    );
    assert!(
        !message.contains("%3CRequest"),
        "encoded request XML leaked: {message}"
    );

    captured_request
        .recv_timeout(Duration::from_secs(5))
        .expect("server still receives the attempted request");
}
