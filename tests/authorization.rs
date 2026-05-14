use sophos_firewall::{
    Action, AuthorizationPolicy, AuthorizationRule, Decision, ObjectScope, SophosRequest,
};

fn webfilter_one_object_policy() -> AuthorizationPolicy {
    AuthorizationPolicy::new(vec![AuthorizationRule::allow(
        "agent:webfilter-bot",
        "WebFilterPolicy",
        ObjectScope::named(["Allowed Policy"]),
        [Action::Read, Action::Update],
    )])
}

#[test]
fn allows_agent_to_update_one_named_policy_object() {
    let request = SophosRequest::update("WebFilterPolicy", "Allowed Policy")
        .with_payload(serde_json::json!({"Description": "managed by agent"}));

    assert_eq!(
        webfilter_one_object_policy().decide("agent:webfilter-bot", &request),
        Decision::Allow
    );
}

#[test]
fn denies_agent_update_to_any_other_policy_object() {
    let request = SophosRequest::update("WebFilterPolicy", "Default Policy")
        .with_payload(serde_json::json!({"Description": "should not happen"}));

    assert!(matches!(
        webfilter_one_object_policy().decide("agent:webfilter-bot", &request),
        Decision::Deny(reason) if reason.contains("Default Policy")
    ));
}

#[test]
fn denies_unscoped_update_when_rule_requires_named_object() {
    let request = SophosRequest::new(Action::Update, "WebFilterPolicy");

    assert!(matches!(
        webfilter_one_object_policy().decide("agent:webfilter-bot", &request),
        Decision::Deny(reason) if reason.contains("object")
    ));
}

#[test]
fn denies_raw_xml_even_if_claimed_object_is_allowed() {
    let request = SophosRequest::raw_xml("WebFilterPolicy", Some("Allowed Policy"), "<Set />");

    assert!(matches!(
        webfilter_one_object_policy().decide("agent:webfilter-bot", &request),
        Decision::Deny(reason) if reason.contains("raw XML")
    ));
}
