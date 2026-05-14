use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use serde_json::json;
use sophos_firewall::{
    Error, SophosClient, SophosConnection, SophosTransport, UserActivityCreate,
    WebFilterPolicyCreate,
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

fn policy_xml(name: &str, default_action: &str) -> String {
    format!(
        "<WebFilterPolicy><Name>{name}</Name><DefaultAction>{default_action}</DefaultAction><RuleList><Rule><HTTPAction>Deny</HTTPAction></Rule></RuleList></WebFilterPolicy>"
    )
}

fn user_activity_xml(name: &str, category: &str) -> String {
    format!(
        "<UserActivity><Name>{name}</Name><CategoryList><Category><type>WebCategory</type><ID>{category}</ID></Category></CategoryList></UserActivity>"
    )
}

#[test]
fn webfilter_policy_list_get_and_zero_records_normalize() {
    let (client, _) = client_with([response(format!(
        "{}{}",
        policy_xml("strict", "Deny"),
        policy_xml("monitor", "Allow"),
    ))]);

    let policies = client.webfilter().list_policies().expect("policies parse");

    assert_eq!(
        policies
            .iter()
            .map(|policy| (policy.name(), policy.field("DefaultAction")))
            .collect::<Vec<_>>(),
        vec![("strict", Some("Deny")), ("monitor", Some("Allow"))]
    );

    let (missing_client, transport) = client_with([zero_records_response("WebFilterPolicy")]);
    let missing = missing_client
        .webfilter()
        .get_policy("missing")
        .expect("zero records maps to None");
    assert_eq!(missing, None);
    assert!(
        transport.captured_requests()[0]
            .contains("<key name=\"Name\" criteria=\"=\">missing</key>")
    );
}

#[test]
fn webfilter_policy_create_update_delete_use_policy_resource_without_live_calls() {
    let (client, transport) = client_with([
        success_response("WebFilterPolicy"),
        response(policy_xml("strict", "Deny")),
        success_response("WebFilterPolicy"),
        response(policy_xml("strict", "Allow")),
        success_response("WebFilterPolicy"),
    ]);

    client
        .webfilter()
        .create_policy(
            WebFilterPolicyCreate::new("strict")
                .expect("valid policy")
                .with_field("DefaultAction", "Deny")
                .expect("valid field")
                .with_field("RuleList", json!({ "Rule": [{ "HTTPAction": "Deny" }] }))
                .expect("valid field"),
        )
        .expect("policy created");

    client
        .webfilter()
        .update_policy(
            WebFilterPolicyCreate::new("strict")
                .expect("valid policy")
                .with_field("DefaultAction", "Allow")
                .expect("valid field")
                .into_update(),
        )
        .expect("policy updated");

    client
        .webfilter()
        .delete_policy("strict")
        .expect("policy deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].contains("<Set operation=\"add\"><WebFilterPolicy>"));
    assert!(requests[0].contains("<Name>strict</Name>"));
    assert!(requests[0].contains("<DefaultAction>Deny</DefaultAction>"));
    assert!(requests[2].contains("<Set operation=\"update\"><WebFilterPolicy>"));
    assert!(requests[4].contains("<Remove><WebFilterPolicy><Name>strict</Name>"));
}

#[test]
fn webfilter_policy_update_preserves_existing_rule_list_when_default_changes() {
    let (client, transport) = client_with([
        response(policy_xml("strict", "Deny")),
        success_response("WebFilterPolicy"),
    ]);

    client
        .webfilter()
        .update_policy(
            WebFilterPolicyCreate::new("strict")
                .expect("valid policy")
                .with_field("DefaultAction", "Allow")
                .expect("valid field")
                .into_update(),
        )
        .expect("policy updated");

    let request = &transport.captured_requests()[1];
    assert!(request.contains("<DefaultAction>Allow</DefaultAction>"));
    assert!(request.contains("<RuleList>"));
    assert!(request.contains("<HTTPAction>Deny</HTTPAction>"));
}

#[test]
fn missing_webfilter_policy_delete_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("WebFilterPolicy")]);

    let error = client
        .webfilter()
        .delete_policy("missing")
        .expect_err("missing delete is rejected");

    assert!(
        error
            .to_string()
            .contains("web filter policy 'missing' does not exist")
    );
    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("<Remove>"));
}

#[test]
fn user_activity_create_get_delete_use_user_activity_resource() {
    let (client, transport) = client_with([
        success_response("UserActivity"),
        response(user_activity_xml("social", "Social Networking")),
        response(user_activity_xml("social", "Social Networking")),
        success_response("UserActivity"),
    ]);

    client
        .webfilter()
        .create_user_activity(
            UserActivityCreate::new("social")
                .expect("valid user activity")
                .with_field(
                    "CategoryList",
                    json!({ "Category": [{ "type": "WebCategory", "ID": "Social Networking" }] }),
                )
                .expect("valid field"),
        )
        .expect("activity created");

    let activity = client
        .webfilter()
        .get_user_activity("social")
        .expect("activity get works")
        .expect("activity exists");
    assert_eq!(activity.name(), "social");
    assert_eq!(
        activity.field("CategoryList.Category.ID"),
        Some("Social Networking")
    );

    client
        .webfilter()
        .delete_user_activity("social")
        .expect("activity deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].contains("<Set operation=\"add\"><UserActivity>"));
    assert!(requests[1].contains("<Get><UserActivity>"));
    assert!(requests[3].contains("<Remove><UserActivity><Name>social</Name>"));
}

#[test]
fn missing_user_activity_delete_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("UserActivity")]);

    let error = client
        .webfilter()
        .delete_user_activity("missing")
        .expect_err("missing delete is rejected");

    assert!(
        error
            .to_string()
            .contains("user activity 'missing' does not exist")
    );
    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("<Remove>"));
}
