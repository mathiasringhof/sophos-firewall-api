use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall::{
    DnsBulkMutationResult, DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate,
    DnsMutationAction, EntryType, Error, IpFamily, PublishOnWan, SophosClient, SophosConnection,
    SophosTransport,
};

#[derive(Clone)]
struct QueueTransport {
    requests: Rc<RefCell<Vec<String>>>,
    responses: Rc<RefCell<VecDeque<String>>>,
}

impl QueueTransport {
    fn new(responses: impl IntoIterator<Item = String>) -> Self {
        Self {
            requests: Rc::new(RefCell::new(Vec::new())),
            responses: Rc::new(RefCell::new(responses.into_iter().collect())),
        }
    }

    fn captured_requests(&self) -> Vec<String> {
        self.requests.borrow().clone()
    }
}

impl SophosTransport for QueueTransport {
    fn send_xml(&self, _api_url: &str, request_xml: &str) -> sophos_firewall::Result<String> {
        self.requests.borrow_mut().push(request_xml.to_string());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| Error::Transport("no queued fake response".to_string()))
    }
}

fn connection() -> SophosConnection {
    SophosConnection::new("firewall.example", "api-user", "secret")
}

fn client_with(
    responses: impl IntoIterator<Item = String>,
) -> (SophosClient<QueueTransport>, QueueTransport) {
    let transport = QueueTransport::new(responses);
    (
        SophosClient::new(connection(), transport.clone()),
        transport,
    )
}

fn address(ip: &str) -> DnsHostAddress {
    DnsHostAddress::new(EntryType::Manual, IpFamily::IPv4, ip).expect("valid address")
}

fn entry(host: &str, ip: &str) -> DnsHostEntryCreate {
    DnsHostEntryCreate::new(host, vec![address(ip)]).expect("valid DNS entry")
}

fn update_with_address(host: &str, ip: &str) -> DnsHostEntryUpdate {
    DnsHostEntryUpdate::new(host)
        .expect("valid host")
        .with_addresses(vec![address(ip)])
        .expect("valid update")
}

fn dns_record_xml(
    host: &str,
    ip: &str,
    ttl: u32,
    weight: u8,
    publish: PublishOnWan,
    reverse: bool,
) -> String {
    format!(
        concat!(
            "<DNSHostEntry>",
            "<HostName>{host}</HostName>",
            "<AddressList><Address>",
            "<EntryType>Manual</EntryType>",
            "<IPFamily>IPv4</IPFamily>",
            "<IPAddress>{ip}</IPAddress>",
            "<TTL>{ttl}</TTL>",
            "<Weight>{weight}</Weight>",
            "<PublishOnWAN>{publish}</PublishOnWAN>",
            "</Address></AddressList>",
            "<AddReverseDNSLookUp>{reverse}</AddReverseDNSLookUp>",
            "</DNSHostEntry>"
        ),
        host = host,
        ip = ip,
        ttl = ttl,
        weight = weight,
        publish = publish.as_str(),
        reverse = if reverse { "Enable" } else { "Disable" },
    )
}

fn response(body: impl AsRef<str>) -> String {
    format!("<Response>{}</Response>", body.as_ref())
}

fn existing_response(host: &str, ip: &str) -> String {
    response(dns_record_xml(
        host,
        ip,
        3600,
        0,
        PublishOnWan::Disable,
        false,
    ))
}

fn zero_records_response() -> String {
    response("<DNSHostEntry><Status>Number of records Zero.</Status></DNSHostEntry>")
}

fn success_response(text: &str) -> String {
    response(format!(
        "<DNSHostEntry><Status code=\"200\">{text}</Status></DNSHostEntry>"
    ))
}

#[test]
fn dns_host_name_is_trimmed_and_trailing_dot_removed() {
    let entry = DnsHostEntryCreate::new("  web-1.example.com.  ", vec![address("10.0.0.10")])
        .expect("host is normalized");

    assert_eq!(entry.host_name(), "web-1.example.com");

    let error = DnsHostEntryCreate::new("bad..host", vec![address("10.0.0.10")])
        .expect_err("empty labels are invalid");
    assert!(error.to_string().contains("hostname"));
}

#[test]
fn dns_rejects_ipv4_family_with_ipv6_address() {
    let error = DnsHostAddress::new(EntryType::Manual, IpFamily::IPv4, "2001:4860:4860::8888")
        .expect_err("IPv4 family rejects IPv6 address");

    assert!(error.to_string().contains("IPv4"));
}

#[test]
fn dns_rejects_invalid_addresses() {
    for invalid in [
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "169.254.10.20",
        "255.255.255.255",
        "ff02::1",
        "::",
        "fe80::1",
    ] {
        let family = if invalid.contains(':') {
            IpFamily::IPv6
        } else {
            IpFamily::IPv4
        };
        assert!(
            DnsHostAddress::new(EntryType::Manual, family, invalid).is_err(),
            "{invalid} should be rejected"
        );
    }
}

#[test]
fn dns_list_entries_normalizes_single_and_multiple_records() {
    let (single_client, _) = client_with([response(dns_record_xml(
        "web-1.example.com",
        "10.0.0.10",
        120,
        7,
        PublishOnWan::Enable,
        true,
    ))]);

    let single = single_client
        .dns()
        .list_entries()
        .expect("single record parses");

    assert_eq!(single.len(), 1);
    assert_eq!(single[0].host_name(), "web-1.example.com");
    assert_eq!(single[0].addresses()[0].ttl(), 120);
    assert_eq!(single[0].addresses()[0].weight(), 7);
    assert_eq!(
        single[0].addresses()[0].publish_on_wan(),
        PublishOnWan::Enable
    );
    assert!(single[0].add_reverse_dns_lookup());

    let multiple_body = format!(
        "{}{}",
        dns_record_xml(
            "web-1.example.com",
            "10.0.0.10",
            3600,
            0,
            PublishOnWan::Disable,
            false
        ),
        dns_record_xml(
            "api-1.example.com",
            "10.0.0.20",
            3600,
            0,
            PublishOnWan::Disable,
            false
        )
    );
    let (multiple_client, _) = client_with([response(multiple_body)]);

    let multiple = multiple_client
        .dns()
        .list_entries()
        .expect("multiple records parse");

    assert_eq!(
        multiple
            .iter()
            .map(|entry| entry.host_name())
            .collect::<Vec<_>>(),
        vec!["web-1.example.com", "api-1.example.com"]
    );
}

#[test]
fn dns_get_entry_returns_none_on_zero_records() {
    let (client, transport) = client_with([zero_records_response()]);

    let entry = client
        .dns()
        .get_entry("missing.example.com")
        .expect("zero records is not an error for get");

    assert!(entry.is_none());
    let request = &transport.captured_requests()[0];
    assert!(request.contains("<key name=\"HostName\" criteria=\"=\">missing.example.com</key>"));
}

#[test]
fn dns_add_entry_fails_when_existing_without_force() {
    let (client, transport) = client_with([existing_response("web-1.example.com", "10.0.0.10")]);

    let error = client
        .dns()
        .add_entry(entry("web-1.example.com", "10.0.0.20"), false)
        .expect_err("existing entry without force fails");

    assert!(error.to_string().contains("already exists"));
    assert_eq!(
        transport.captured_requests().len(),
        1,
        "no Set request is sent"
    );
}

#[test]
fn dns_add_entry_with_force_updates_existing() {
    let (client, transport) = client_with([
        existing_response("web-1.example.com", "10.0.0.10"),
        success_response("Updated"),
    ]);

    let outcome = client
        .dns()
        .add_entry(entry("web-1.example.com", "10.0.0.20"), true)
        .expect("force updates existing");

    assert_eq!(outcome.action, DnsMutationAction::Updated);
    let requests = transport.captured_requests();
    assert!(requests[1].contains("<Set operation=\"update\"><DNSHostEntry>"));
    assert!(requests[1].contains("<HostName>web-1.example.com</HostName>"));
    assert!(requests[1].contains("<IPAddress>10.0.0.20</IPAddress>"));
    assert!(!requests[1].contains("<Name>web-1.example.com</Name>"));
}

#[test]
fn dns_update_entry_merges_with_existing_record() {
    let (client, transport) = client_with([
        response(dns_record_xml(
            "web-1.example.com",
            "10.0.0.10",
            180,
            3,
            PublishOnWan::Enable,
            true,
        )),
        success_response("Updated"),
    ]);

    client
        .dns()
        .update_entry(update_with_address("web-1.example.com", "10.0.0.30"))
        .expect("existing record updates");

    let requests = transport.captured_requests();
    assert!(requests[1].contains("<IPAddress>10.0.0.30</IPAddress>"));
    assert!(requests[1].contains("<AddReverseDNSLookUp>Enable</AddReverseDNSLookUp>"));
}

#[test]
fn dns_update_entry_preserves_existing_addresses_when_only_reverse_lookup_changes() {
    let (client, transport) = client_with([
        response(dns_record_xml(
            "web-1.example.com",
            "10.0.0.10",
            180,
            3,
            PublishOnWan::Enable,
            true,
        )),
        success_response("Updated"),
    ]);

    let update = DnsHostEntryUpdate::new("web-1.example.com")
        .expect("valid host")
        .with_add_reverse_dns_lookup(false);

    client
        .dns()
        .update_entry(update)
        .expect("existing record updates");

    let requests = transport.captured_requests();
    assert!(requests[1].contains("<IPAddress>10.0.0.10</IPAddress>"));
    assert!(requests[1].contains("<TTL>180</TTL>"));
    assert!(requests[1].contains("<Weight>3</Weight>"));
    assert!(requests[1].contains("<PublishOnWAN>Enable</PublishOnWAN>"));
    assert!(requests[1].contains("<AddReverseDNSLookUp>Disable</AddReverseDNSLookUp>"));
}

#[test]
fn dns_delete_entry_uses_host_name_key_and_fails_when_missing() {
    let (delete_client, delete_transport) = client_with([
        existing_response("web-1.example.com", "10.0.0.10"),
        success_response("Deleted"),
    ]);

    delete_client
        .dns()
        .delete_entry("web-1.example.com")
        .expect("existing entry deletes");

    let delete_requests = delete_transport.captured_requests();
    assert!(delete_requests[1].contains(
        "<Remove><DNSHostEntry><HostName>web-1.example.com</HostName></DNSHostEntry></Remove>"
    ));
    assert!(!delete_requests[1].contains("<Name>web-1.example.com</Name>"));

    let (missing_client, missing_transport) = client_with([zero_records_response()]);

    let error = missing_client
        .dns()
        .delete_entry("missing.example.com")
        .expect_err("missing entry fails before remove");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}

#[test]
fn dns_add_many_stops_on_first_error_without_continue_on_error() {
    let (client, transport) = client_with([existing_response("web-1.example.com", "10.0.0.10")]);

    let result = client.dns().add_many(
        vec![
            entry("web-1.example.com", "10.0.0.20"),
            entry("api-1.example.com", "10.0.0.30"),
        ],
        false,
        false,
    );

    assert_eq!(
        result,
        DnsBulkMutationResult {
            total: 2,
            created: 0,
            updated: 0,
            failed: 1,
            errors: vec![
                "web-1.example.com: invalid request: DNS entry 'web-1.example.com' already exists"
                    .to_string()
            ],
        }
    );
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn dns_add_many_continues_and_reports_errors_with_continue_on_error() {
    let (client, transport) = client_with([
        existing_response("web-1.example.com", "10.0.0.10"),
        zero_records_response(),
        success_response("Created"),
    ]);

    let result = client.dns().add_many(
        vec![
            entry("web-1.example.com", "10.0.0.20"),
            entry("api-1.example.com", "10.0.0.30"),
        ],
        false,
        true,
    );

    assert_eq!(result.total, 2);
    assert_eq!(result.created, 1);
    assert_eq!(result.updated, 0);
    assert_eq!(result.failed, 1);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("web-1.example.com"));
    assert_eq!(transport.captured_requests().len(), 3);
}
