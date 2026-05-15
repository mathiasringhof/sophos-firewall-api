use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall_api::{Error, SophosClient, SophosConnection, SophosTransport, UrlGroupCreate};

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
    fn send_xml(&self, _api_url: &str, request_xml: &str) -> sophos_firewall_api::Result<String> {
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

fn response(body: impl AsRef<str>) -> String {
    format!("<Response>{}</Response>", body.as_ref())
}

fn url_group_xml(name: &str, domains: &[&str]) -> String {
    let urls = domains
        .iter()
        .map(|domain| format!("<URL>{domain}</URL>"))
        .collect::<String>();
    format!("<WebFilterURLGroup><Name>{name}</Name><URLlist>{urls}</URLlist></WebFilterURLGroup>")
}

fn zero_records_response() -> String {
    response("<WebFilterURLGroup><Status>Number of records Zero.</Status></WebFilterURLGroup>")
}

fn success_response(text: &str) -> String {
    response(format!(
        "<WebFilterURLGroup><Status code=\"200\">{text}</Status></WebFilterURLGroup>"
    ))
}

fn assert_urls_in_order(xml: &str, domains: &[&str]) {
    let mut cursor = 0;
    for domain in domains {
        let needle = format!("<URL>{domain}</URL>");
        let offset = xml[cursor..]
            .find(&needle)
            .unwrap_or_else(|| panic!("missing {needle} in {xml}"));
        cursor += offset + needle.len();
    }
}

#[test]
fn url_group_create_uses_resource_specific_set_operation() {
    let (client, transport) =
        client_with([success_response("Configuration applied successfully.")]);
    let group = UrlGroupCreate::new("allowed-domains", vec!["example.com", "example.org"])
        .expect("valid URL group");

    client
        .url_groups()
        .create_group(group)
        .expect("group is created");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    let xml = &requests[0];
    assert!(xml.contains("<Set operation=\"set\"><WebFilterURLGroup>"));
    assert!(xml.contains("<Name>allowed-domains</Name>"));
    assert_urls_in_order(xml, &["example.com", "example.org"]);
}

#[test]
fn url_group_rejects_empty_domain_values_in_user_input() {
    let error = UrlGroupCreate::new("allowed-domains", vec!["example.com", "   "])
        .expect_err("blank domain values should not be silently ignored");

    assert!(error.to_string().contains("domain must not be empty"));
}

#[test]
fn url_group_get_uses_webfilter_url_group_response_tag() {
    let (client, transport) =
        client_with([response(url_group_xml("codex-urlgrp", &["example.com"]))]);

    let group = client
        .url_groups()
        .get_group("codex-urlgrp")
        .expect("lookup succeeds")
        .expect("group exists");

    assert_eq!(group.name(), "codex-urlgrp");
    assert_eq!(group.domains(), &["example.com"]);
    let request = &transport.captured_requests()[0];
    assert!(request.contains("<Get><WebFilterURLGroup>"));
    assert!(request.contains("<key name=\"Name\" criteria=\"=\">codex-urlgrp</key>"));
}

#[test]
fn url_group_list_normalizes_single_and_multiple_records() {
    let (single_client, _) = client_with([response(url_group_xml("single", &["example.com"]))]);

    let single = single_client
        .url_groups()
        .list_groups()
        .expect("single record parses");

    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "single");
    assert_eq!(single[0].domains(), &["example.com"]);

    let multiple_body = format!(
        "{}{}",
        url_group_xml("first", &["a.example", "b.example"]),
        url_group_xml("second", &["c.example"])
    );
    let (multiple_client, _) = client_with([response(multiple_body)]);

    let multiple = multiple_client
        .url_groups()
        .list_groups()
        .expect("multiple records parse");

    assert_eq!(
        multiple
            .iter()
            .map(|group| (group.name(), group.domains()))
            .collect::<Vec<_>>(),
        vec![
            (
                "first",
                &["a.example".to_string(), "b.example".to_string()][..]
            ),
            ("second", &["c.example".to_string()][..]),
        ]
    );
}

#[test]
fn url_group_add_domains_fetches_existing_and_deduplicates_preserving_order() {
    let (client, transport) = client_with([
        response(url_group_xml("allowed", &["a.example", "b.example"])),
        success_response("Configuration applied successfully."),
    ]);

    client
        .url_groups()
        .add_domains("allowed", vec!["b.example", "c.example"])
        .expect("domains are added");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<Get><WebFilterURLGroup>"));
    assert!(requests[1].contains("<Set operation=\"update\"><WebFilterURLGroup>"));
    assert_urls_in_order(&requests[1], &["a.example", "b.example", "c.example"]);
    assert_eq!(requests[1].matches("<URL>b.example</URL>").count(), 1);
}

#[test]
fn url_group_remove_domains_preserves_unmentioned_domains() {
    let (client, transport) = client_with([
        response(url_group_xml(
            "allowed",
            &["a.example", "b.example", "c.example"],
        )),
        success_response("Configuration applied successfully."),
    ]);

    client
        .url_groups()
        .remove_domains("allowed", vec!["b.example"])
        .expect("domain is removed");

    let update = &transport.captured_requests()[1];
    assert_urls_in_order(update, &["a.example", "c.example"]);
    assert!(!update.contains("<URL>b.example</URL>"));
}

#[test]
fn url_group_replace_domains_replaces_full_list() {
    let (client, transport) = client_with([
        response(url_group_xml("allowed", &["a.example", "b.example"])),
        success_response("Configuration applied successfully."),
    ]);

    client
        .url_groups()
        .replace_domains("allowed", vec!["c.example", "c.example", "d.example"])
        .expect("domains are replaced");

    let update = &transport.captured_requests()[1];
    assert_urls_in_order(update, &["c.example", "d.example"]);
    assert!(!update.contains("<URL>a.example</URL>"));
    assert!(!update.contains("<URL>b.example</URL>"));
    assert_eq!(update.matches("<URL>c.example</URL>").count(), 1);
}

#[test]
fn url_group_update_missing_group_returns_not_found_without_sending_update() {
    let (client, transport) = client_with([zero_records_response()]);

    let error = client
        .url_groups()
        .add_domains("missing", vec!["example.com"])
        .expect_err("missing group is an invalid update");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(
        transport.captured_requests().len(),
        1,
        "zero-record lookup must not be followed by Set"
    );
}

#[test]
fn url_group_delete_uses_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(url_group_xml("allowed", &["example.com"])),
        success_response("Configuration applied successfully."),
    ]);

    client
        .url_groups()
        .delete_group("allowed")
        .expect("group is deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].contains(
            "<Remove><WebFilterURLGroup><Name>allowed</Name></WebFilterURLGroup></Remove>"
        )
    );

    let (missing_client, missing_transport) = client_with([zero_records_response()]);
    let error = missing_client
        .url_groups()
        .delete_group("missing")
        .expect_err("missing group is not deleted");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}
