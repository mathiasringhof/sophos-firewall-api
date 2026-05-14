use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use serde_json::json;
use sophos_firewall::{
    Error, FirewallRuleCreate, FirewallRuleGroupCreate, FirewallRuleUpdate, LocalServiceAclCreate,
    SophosClient, SophosConnection, SophosTransport,
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

fn response(body: impl AsRef<str>) -> String {
    format!("<Response>{}</Response>", body.as_ref())
}

fn success_response(resource: &str) -> String {
    response(format!(
        "<{resource}><Status code=\"200\">Configuration applied successfully.</Status></{resource}>"
    ))
}

fn zero_records_response(resource: &str) -> String {
    response(format!(
        "<{resource}><Status>Number of records Zero.</Status></{resource}>"
    ))
}

fn firewall_rule_xml(name: &str, status: &str, action: &str) -> String {
    format!(
        "<FirewallRule><Name>{name}</Name><Description>existing</Description><Status>{status}</Status><NetworkPolicy><Action>{action}</Action></NetworkPolicy></FirewallRule>"
    )
}

fn firewall_group_xml(name: &str, policies: &[&str]) -> String {
    let policies = policies
        .iter()
        .map(|policy| format!("<SecurityPolicy>{policy}</SecurityPolicy>"))
        .collect::<String>();
    format!(
        "<FirewallRuleGroup><Name>{name}</Name><SecurityPolicyList>{policies}</SecurityPolicyList></FirewallRuleGroup>"
    )
}

fn acl_xml(name: &str, action: &str) -> String {
    format!(
        "<LocalServiceACL><RuleName>{name}</RuleName><Action>{action}</Action></LocalServiceACL>"
    )
}

#[test]
fn firewall_rule_list_normalizes_single_and_multiple_records() {
    let (single_client, _) =
        client_with([response(firewall_rule_xml("allow-web", "Enable", "Accept"))]);

    let single = single_client
        .firewall()
        .list_rules()
        .expect("single firewall rule parses");

    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "allow-web");
    assert_eq!(single[0].status(), Some("Enable"));
    assert_eq!(single[0].field("NetworkPolicy.Action"), Some("Accept"));

    let (multiple_client, _) = client_with([response(format!(
        "{}{}",
        firewall_rule_xml("allow-web", "Enable", "Accept"),
        firewall_rule_xml("drop-telnet", "Disable", "Drop"),
    ))]);

    let multiple = multiple_client
        .firewall()
        .list_rules()
        .expect("multiple firewall rules parse");

    assert_eq!(
        multiple
            .iter()
            .map(|rule| (
                rule.name(),
                rule.status(),
                rule.field("NetworkPolicy.Action")
            ))
            .collect::<Vec<_>>(),
        vec![
            ("allow-web", Some("Enable"), Some("Accept")),
            ("drop-telnet", Some("Disable"), Some("Drop")),
        ]
    );
}

#[test]
fn firewall_rule_get_returns_none_on_zero_records() {
    let (client, transport) = client_with([zero_records_response("FirewallRule")]);

    let rule = client
        .firewall()
        .get_rule("missing")
        .expect("zero records maps to None");

    assert_eq!(rule, None);
    let request = &transport.captured_requests()[0];
    assert!(request.contains("<Get><FirewallRule>"));
    assert!(request.contains("<key name=\"Name\" criteria=\"=\">missing</key>"));
}

#[test]
fn firewall_rule_create_uses_add_resource_tag_and_escapes_user_strings() {
    let (client, transport) = client_with([success_response("FirewallRule")]);
    let rule = FirewallRuleCreate::new("allow-web")
        .expect("valid name")
        .with_field("Status", "Enable")
        .expect("valid field")
        .with_field("Description", "Allow A&B <web>")
        .expect("valid field")
        .with_field("NetworkPolicy", json!({ "Action": "Accept" }))
        .expect("valid nested field");

    client
        .firewall()
        .create_rule(rule)
        .expect("rule is created");

    let request = &transport.captured_requests()[0];
    assert!(request.contains("<Set operation=\"add\"><FirewallRule>"));
    assert!(request.contains("<Name>allow-web</Name>"));
    assert!(request.contains("<Status>Enable</Status>"));
    assert!(request.contains("<Action>Accept</Action>"));
    assert!(request.contains("<Description>Allow A&amp;B &lt;web&gt;</Description>"));
}

#[test]
fn firewall_rule_update_fetches_existing_and_preserves_status_when_omitted() {
    let (client, transport) = client_with([
        response(firewall_rule_xml("allow-web", "Disable", "Drop")),
        success_response("FirewallRule"),
    ]);
    let update = FirewallRuleUpdate::new("allow-web")
        .expect("valid name")
        .with_field("NetworkPolicy", json!({ "Action": "Accept" }))
        .expect("valid field");

    client
        .firewall()
        .update_rule(update)
        .expect("rule is updated");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<Get><FirewallRule>"));
    assert!(requests[1].contains("<Set operation=\"update\"><FirewallRule>"));
    assert!(requests[1].contains("<Name>allow-web</Name>"));
    assert!(requests[1].contains("<Status>Disable</Status>"));
    assert!(requests[1].contains("<Action>Accept</Action>"));
}

#[test]
fn firewall_rule_update_preserves_existing_nested_fields_when_patching_action() {
    let existing = "<FirewallRule><Name>allow-web</Name><Description>existing</Description><Status>Enable</Status><NetworkPolicy><Action>Drop</Action><LogTraffic>Enable</LogTraffic><WebFilter>kids</WebFilter></NetworkPolicy></FirewallRule>";
    let (client, transport) = client_with([response(existing), success_response("FirewallRule")]);
    let update = FirewallRuleUpdate::new("allow-web")
        .expect("valid name")
        .with_field("NetworkPolicy", json!({ "Action": "Accept" }))
        .expect("valid field");

    client
        .firewall()
        .update_rule(update)
        .expect("rule is updated");

    let request = &transport.captured_requests()[1];
    assert!(request.contains("<Action>Accept</Action>"));
    assert!(request.contains("<LogTraffic>Enable</LogTraffic>"));
    assert!(request.contains("<WebFilter>kids</WebFilter>"));
}

#[test]
fn missing_firewall_rule_update_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("FirewallRule")]);
    let update = FirewallRuleUpdate::new("missing")
        .expect("valid name")
        .with_field("Status", "Enable")
        .expect("valid field");

    let error = client
        .firewall()
        .update_rule(update)
        .expect_err("missing update is rejected");

    assert!(
        error
            .to_string()
            .contains("firewall rule 'missing' does not exist")
    );
    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("<Set operation=\"update\">"));
}

#[test]
fn firewall_payloads_reject_invalid_field_tags() {
    let top_level = FirewallRuleCreate::new("bad-rule")
        .expect("valid rule name")
        .with_field("1Bad", "value")
        .expect_err("invalid top-level XML tag is rejected");
    assert!(top_level.to_string().contains("invalid XML tag"));

    let nested = FirewallRuleCreate::new("bad-rule")
        .expect("valid rule name")
        .with_field("NetworkPolicy", json!({ "Bad<Tag": "value" }))
        .expect_err("invalid nested XML tag is rejected");
    assert!(nested.to_string().contains("invalid XML tag"));
}

#[test]
fn missing_firewall_rule_delete_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("FirewallRule")]);

    let error = client
        .firewall()
        .delete_rule("missing")
        .expect_err("missing delete is rejected");

    assert!(
        error
            .to_string()
            .contains("firewall rule 'missing' does not exist")
    );
    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("<Remove>"));
}

#[test]
fn firewall_rule_group_get_create_update_and_delete_use_name_key() {
    let (client, transport) = client_with([
        response(firewall_group_xml("group-a", &["allow-web"])),
        success_response("FirewallRuleGroup"),
        response(firewall_group_xml("group-a", &["allow-web"])),
        success_response("FirewallRuleGroup"),
        response(firewall_group_xml("group-a", &["allow-web"])),
        success_response("FirewallRuleGroup"),
    ]);

    assert_eq!(
        client
            .firewall()
            .get_rule_group("group-a")
            .expect("group get works")
            .expect("group exists")
            .name(),
        "group-a"
    );

    client
        .firewall()
        .create_rule_group(
            FirewallRuleGroupCreate::new("group-a")
                .expect("valid group")
                .with_field(
                    "SecurityPolicyList",
                    json!({ "SecurityPolicy": ["allow-web"] }),
                )
                .expect("valid field"),
        )
        .expect("group created");

    client
        .firewall()
        .update_rule_group(
            FirewallRuleGroupCreate::new("group-a")
                .expect("valid group")
                .with_field("Description", "updated")
                .expect("valid field")
                .into_update(),
        )
        .expect("group updated");

    client
        .firewall()
        .delete_rule_group("group-a")
        .expect("group deleted");

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<key name=\"Name\" criteria=\"=\">group-a</key>"));
    assert!(requests[1].contains("<Set operation=\"add\"><FirewallRuleGroup>"));
    assert!(requests[3].contains("<Set operation=\"update\"><FirewallRuleGroup>"));
    assert!(requests[5].contains("<Remove><FirewallRuleGroup><Name>group-a</Name>"));
}

#[test]
fn local_service_acl_uses_rule_name_key_for_get_update_and_delete() {
    let (client, transport) = client_with([
        response(acl_xml("admin-https", "accept")),
        success_response("LocalServiceACL"),
        response(acl_xml("admin-https", "accept")),
        success_response("LocalServiceACL"),
        response(acl_xml("admin-https", "accept")),
        success_response("LocalServiceACL"),
    ]);

    let acl = client
        .firewall()
        .get_acl_rule("admin-https")
        .expect("acl get works")
        .expect("acl exists");
    assert_eq!(acl.rule_name(), "admin-https");

    client
        .firewall()
        .create_acl_rule(
            LocalServiceAclCreate::new("admin-https")
                .expect("valid acl")
                .with_field("Action", "accept")
                .expect("valid field"),
        )
        .expect("acl created");

    client
        .firewall()
        .update_acl_rule(
            LocalServiceAclCreate::new("admin-https")
                .expect("valid acl")
                .with_field("Action", "drop")
                .expect("valid field")
                .into_update(),
        )
        .expect("acl updated");

    client
        .firewall()
        .delete_acl_rule("admin-https")
        .expect("acl deleted");

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<key name=\"RuleName\" criteria=\"=\">admin-https</key>"));
    assert!(requests[1].contains("<Set operation=\"add\"><LocalServiceACL>"));
    assert!(requests[1].contains("<RuleName>admin-https</RuleName>"));
    assert!(requests[3].contains("<Set operation=\"update\"><LocalServiceACL>"));
    assert!(requests[5].contains("<Remove><LocalServiceACL><RuleName>admin-https</RuleName>"));
}
