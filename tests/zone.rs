use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use serde_json::json;
use sophos_firewall_api::{
    Error, SophosClient, SophosConnection, SophosTransport, ZoneCreate, ZoneUpdate,
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

fn zone_xml(name: &str, zone_type: &str, https: &str, ssh: &str) -> String {
    format!(
        "<Zone><Name>{name}</Name><Type>{zone_type}</Type><ApplianceAccess><AdminServices><HTTPS>{https}</HTTPS><SSH>{ssh}</SSH></AdminServices><NetworkServices><DNS>Enable</DNS></NetworkServices></ApplianceAccess></Zone>"
    )
}

fn interface_xml(name: &str, zone: &str) -> String {
    format!("<Interface><Name>{name}</Name><Zone>{zone}</Zone></Interface>")
}

fn vlan_xml(name: &str, vlan_id: &str) -> String {
    format!("<VLAN><Name>{name}</Name><VLANID>{vlan_id}</VLANID></VLAN>")
}

#[test]
fn zone_list_get_and_zero_records_normalize() {
    let (single_client, _) = client_with([response(zone_xml("LAN", "LAN", "Enable", "Disable"))]);
    let single = single_client.zones().list_zones().expect("single parses");
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "LAN");
    assert_eq!(
        single[0].field("ApplianceAccess.AdminServices.HTTPS"),
        Some("Enable")
    );

    let (multiple_client, _) = client_with([response(format!(
        "{}{}",
        zone_xml("LAN", "LAN", "Enable", "Disable"),
        zone_xml("DMZ", "DMZ", "Disable", "Disable")
    ))]);
    let multiple = multiple_client
        .zones()
        .list_zones()
        .expect("multiple parses");
    assert_eq!(
        multiple.iter().map(|zone| zone.name()).collect::<Vec<_>>(),
        vec!["LAN", "DMZ"]
    );

    let (missing_client, transport) = client_with([zero_records_response("Zone")]);
    let missing = missing_client
        .zones()
        .get_zone("missing")
        .expect("zero maps to None");
    assert_eq!(missing, None);
    assert!(
        transport.captured_requests()[0]
            .contains("<key name=\"Name\" criteria=\"=\">missing</key>")
    );
}

#[test]
fn zone_create_update_delete_use_zone_resource_and_preserve_nested_access() {
    let (client, transport) = client_with([
        success_response("Zone"),
        response(zone_xml("LAN", "LAN", "Enable", "Disable")),
        success_response("Zone"),
        response(zone_xml("LAN", "LAN", "Disable", "Disable")),
        success_response("Zone"),
    ]);

    client
        .zones()
        .create_zone(
            ZoneCreate::new("LAN", "LAN")
                .expect("valid zone")
                .with_field("Description", "trusted & wired")
                .expect("valid field")
                .with_field(
                    "ApplianceAccess",
                    json!({ "AdminServices": { "HTTPS": "Enable" } }),
                )
                .expect("valid nested field"),
        )
        .expect("zone created");

    client
        .zones()
        .update_zone(
            ZoneUpdate::new("LAN")
                .expect("valid zone")
                .with_field(
                    "ApplianceAccess",
                    json!({ "AdminServices": { "HTTPS": "Disable" } }),
                )
                .expect("valid nested field"),
        )
        .expect("zone updated");

    client.zones().delete_zone("LAN").expect("zone deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].contains("<Set operation=\"add\"><Zone>"));
    assert!(requests[0].contains("<Name>LAN</Name>"));
    assert!(requests[0].contains("<Type>LAN</Type>"));
    assert!(requests[0].contains("<Description>trusted &amp; wired</Description>"));
    assert!(requests[2].contains("<Set operation=\"update\"><Zone>"));
    assert!(requests[2].contains("<HTTPS>Disable</HTTPS>"));
    assert!(requests[2].contains("<SSH>Disable</SSH>"));
    assert!(requests[2].contains("<DNS>Enable</DNS>"));
    assert!(requests[4].contains("<Remove><Zone><Name>LAN</Name>"));
}

#[test]
fn missing_zone_delete_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("Zone")]);

    let error = client
        .zones()
        .delete_zone("missing")
        .expect_err("missing rejected");

    assert!(error.to_string().contains("zone 'missing' does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
    assert!(!transport.captured_requests()[0].contains("<Remove>"));
}

#[test]
fn interface_vlan_and_dns_forwarders_are_read_only_gets() {
    let (client, transport) = client_with([
        response(format!(
            "{}{}",
            interface_xml("Port1", "LAN"),
            interface_xml("Port2", "WAN")
        )),
        response(vlan_xml("lab.42", "42")),
        response(
            "<DNS><DNSQueryConfiguration>ChooseServerBasedOnIncomingRequestsRecordType</DNSQueryConfiguration></DNS>",
        ),
    ]);

    let interfaces = client.zones().list_interfaces().expect("interfaces parse");
    assert_eq!(interfaces.len(), 2);
    assert_eq!(interfaces[0].name(), "Port1");
    assert_eq!(interfaces[1].field("Zone"), Some("WAN"));

    let vlan = client
        .zones()
        .get_vlan("lab.42")
        .expect("VLAN get works")
        .expect("VLAN exists");
    assert_eq!(vlan.name(), "lab.42");
    assert_eq!(vlan.field("VLANID"), Some("42"));

    let dns = client
        .zones()
        .get_dns_forwarders()
        .expect("DNS forwarders parse");
    assert_eq!(
        dns.field("DNSQueryConfiguration"),
        Some("ChooseServerBasedOnIncomingRequestsRecordType")
    );

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<Get><Interface/>"));
    assert!(requests[1].contains("<Get><VLAN>"));
    assert!(requests[2].contains("<Get><DNS/>"));
    assert!(
        !requests
            .iter()
            .any(|request| request.contains("<Set") || request.contains("<Remove>"))
    );
}

#[test]
fn zone_payload_rejects_invalid_nested_field_tags() {
    let error = ZoneCreate::new("bad-zone", "LAN")
        .expect("valid zone")
        .with_field("ApplianceAccess", json!({ "Bad<Tag": "Enable" }))
        .expect_err("invalid nested tag rejected");

    assert!(error.to_string().contains("invalid XML tag"));
}
