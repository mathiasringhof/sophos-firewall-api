use std::cell::RefCell;
use std::rc::Rc;

use sophos_firewall::{
    AuthorizationPolicy, Error, SophosClient, SophosConnection, SophosRequest, SophosTransport,
    parse_response_xml,
};

#[derive(Clone)]
struct FakeTransport {
    requests: Rc<RefCell<Vec<String>>>,
    response_xml: String,
}

impl FakeTransport {
    fn new(response_xml: impl Into<String>) -> Self {
        Self {
            requests: Rc::new(RefCell::new(Vec::new())),
            response_xml: response_xml.into(),
        }
    }

    fn captured_requests(&self) -> Vec<String> {
        self.requests.borrow().clone()
    }
}

impl SophosTransport for FakeTransport {
    fn send_xml(&self, _api_url: &str, request_xml: &str) -> sophos_firewall::Result<String> {
        self.requests.borrow_mut().push(request_xml.to_string());
        Ok(self.response_xml.clone())
    }
}

fn connection() -> SophosConnection {
    SophosConnection::new("firewall.example", "api-user", "secret")
}

#[test]
fn client_authorizes_before_sending_xml() {
    let transport = FakeTransport::new("<Response/>");
    let client = SophosClient::new(connection(), transport.clone())
        .with_authorization("agent:webfilter-bot", AuthorizationPolicy::default());
    let request = SophosRequest::update("WebFilterPolicy", "Default Policy");

    let error = client
        .execute(&request)
        .expect_err("empty policy denies request");

    assert!(matches!(error, Error::AuthorizationDenied(_)));
    assert!(
        transport.captured_requests().is_empty(),
        "denied request must not reach transport"
    );
}

#[test]
fn client_sends_safe_xml_to_transport_and_returns_response() {
    let success_xml = concat!(
        "<Response>",
        "<WebFilterPolicy>",
        "<Status code=\"200\">Configuration applied successfully.</Status>",
        "<Name>Default Policy</Name>",
        "</WebFilterPolicy>",
        "</Response>"
    );
    let transport = FakeTransport::new(success_xml);
    let client = SophosClient::new(connection(), transport.clone());
    let request = SophosRequest::update("WebFilterPolicy", "Default Policy");

    let response = client.execute(&request).expect("success response parses");

    let captured = transport.captured_requests();
    assert_eq!(captured.len(), 1);
    let xml = &captured[0];
    assert!(xml.contains("<Request>"));
    assert!(
        xml.contains("<Login><Username>api-user</Username><Password>secret</Password></Login>")
    );
    assert!(xml.contains("<Set operation=\"update\"><WebFilterPolicy>"));
    assert!(xml.contains("<Name>Default Policy</Name>"));

    let resource = response
        .resource("WebFilterPolicy")
        .expect("resource response is exposed");
    assert_eq!(resource.status.code.as_deref(), Some("200"));
    assert_eq!(resource.status.text, "Configuration applied successfully.");
    assert!(resource.body_xml.contains("<Name>Default Policy</Name>"));
}

#[test]
fn response_parser_maps_zero_records_to_zero_records_error() {
    let xml = concat!(
        "<Response>",
        "<DNSHostEntry>",
        "<Status>Number of records Zero.</Status>",
        "</DNSHostEntry>",
        "</Response>"
    );

    let error = parse_response_xml(xml).expect_err("zero records should be structured");

    assert_eq!(
        error,
        Error::ZeroRecords {
            resource: "DNSHostEntry".to_string()
        }
    );
}

#[test]
fn response_parser_maps_non_2xx_resource_status_to_api_error() {
    let xml = concat!(
        "<Response>",
        "<DNSHostEntry>",
        "<Status code=\"500\">Missing or invalid host parameters.</Status>",
        "</DNSHostEntry>",
        "</Response>"
    );

    let error = parse_response_xml(xml).expect_err("non-2xx status should be structured");

    assert_eq!(
        error,
        Error::ApiError {
            resource: "DNSHostEntry".to_string(),
            code: Some("500".to_string()),
            message: "Missing or invalid host parameters.".to_string()
        }
    );
}
