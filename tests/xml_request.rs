use pretty_assertions::assert_eq;
use sophos_firewall_api::{Action, SophosConnection, SophosRequest, build_request_xml};

#[test]
fn builds_escaped_update_request_for_named_object() {
    let connection = SophosConnection::new("firewall.example", "api-user", "p<&>");
    let request = SophosRequest::update("WebFilterPolicy", "Allowed Policy")
        .with_payload(serde_json::json!({"Description": "only <this> one"}));

    let xml = build_request_xml(&connection, &request).expect("valid request XML");

    assert!(xml.contains("<Username>api-user</Username>"));
    assert!(xml.contains("<Password>p&lt;&amp;&gt;</Password>"));
    assert!(xml.contains("<Set operation=\"update\"><WebFilterPolicy>"));
    assert!(xml.contains("<Name>Allowed Policy</Name>"));
    assert!(xml.contains("<Description>only &lt;this&gt; one</Description>"));
}

#[test]
fn builds_get_request_with_name_filter() {
    let connection = SophosConnection::new("firewall.example", "api-user", "secret");
    let request = SophosRequest::read("WebFilterPolicy").for_object("Allowed Policy");

    let xml = build_request_xml(&connection, &request).expect("valid request XML");

    assert_eq!(
        xml,
        concat!(
            "<Request>",
            "<Login><Username>api-user</Username><Password>secret</Password></Login>",
            "<Get><WebFilterPolicy><Filter><key name=\"Name\" criteria=\"=\">Allowed Policy</key></Filter></WebFilterPolicy></Get>",
            "</Request>"
        )
    );
}

#[test]
fn rejects_invalid_xml_tag_names() {
    let connection = SophosConnection::new("firewall.example", "api-user", "secret");
    let request = SophosRequest::new(Action::Read, "Bad><Tag");

    let error = build_request_xml(&connection, &request).expect_err("invalid resource tag");

    assert!(error.to_string().contains("invalid XML tag"));
}
