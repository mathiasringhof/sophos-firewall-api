use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall_api::{
    Error, ServiceCreate, ServiceEntry, ServiceGroupCreate, ServiceGroupUpdate,
    ServiceGroupUpdateAction, ServiceType, SophosClient, SophosConnection, SophosTransport,
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

fn service_xml(name: &str, service_type: &str, details: &str) -> String {
    format!(
        "<Services><Name>{name}</Name><Type>{service_type}</Type><ServiceDetails>{details}</ServiceDetails></Services>"
    )
}

fn tcp_detail(protocol: &str, src_port: &str, dst_port: &str) -> String {
    format!(
        "<ServiceDetail><SourcePort>{src_port}</SourcePort><DestinationPort>{dst_port}</DestinationPort><Protocol>{protocol}</Protocol></ServiceDetail>"
    )
}

fn ip_detail(protocol: &str) -> String {
    format!("<ServiceDetail><ProtocolName>{protocol}</ProtocolName></ServiceDetail>")
}

fn icmp_detail(kind: &str, code: &str) -> String {
    format!("<ServiceDetail><ICMPType>{kind}</ICMPType><ICMPCode>{code}</ICMPCode></ServiceDetail>")
}

fn service_group_xml(name: &str, description: &str, services: &[&str]) -> String {
    let service_list = services
        .iter()
        .map(|service| format!("<Service>{service}</Service>"))
        .collect::<String>();
    format!(
        "<ServiceGroup><Name>{name}</Name><Description>{description}</Description><ServiceList>{service_list}</ServiceList></ServiceGroup>"
    )
}

fn zero_records_response(resource: &str) -> String {
    response(format!(
        "<{resource}><Status>Number of records Zero.</Status></{resource}>"
    ))
}

fn success_response(resource: &str, text: &str) -> String {
    response(format!(
        "<{resource}><Status code=\"200\">{text}</Status></{resource}>"
    ))
}

fn assert_tokens_in_order(xml: &str, tokens: &[&str]) {
    let mut cursor = 0;
    for token in tokens {
        let offset = xml[cursor..]
            .find(token)
            .unwrap_or_else(|| panic!("missing {token} in {xml}"));
        cursor += offset + token.len();
    }
}

#[test]
fn service_create_tcp_udp_defaults_source_port_and_uses_valid_xml() {
    let (client, transport) = client_with([success_response(
        "Services",
        "Configuration applied successfully.",
    )]);
    let service = ServiceCreate::new(
        "web",
        ServiceType::TcpOrUdp,
        vec![ServiceEntry::tcp_udp("TCP", "443")],
    )
    .expect("valid TCP service");

    client
        .services()
        .create_service(service)
        .expect("service is created");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    let xml = &requests[0];
    assert!(xml.contains("<Set operation=\"add\"><Services>"));
    assert!(xml.contains("<Name>web</Name>"));
    assert!(xml.contains("<Type>TCPorUDP</Type>"));
    assert!(xml.contains("<SourcePort>1:65535</SourcePort>"));
    assert!(xml.contains("<DestinationPort>443</DestinationPort>"));
    assert!(xml.contains("<Protocol>TCP</Protocol>"));
}

#[test]
fn service_create_rejects_tcp_udp_without_protocol_or_destination_port() {
    let missing_protocol = ServiceCreate::new(
        "bad",
        ServiceType::TcpOrUdp,
        vec![ServiceEntry::new().with_destination_port("443")],
    )
    .expect_err("TCPorUDP requires protocol");
    assert!(
        missing_protocol
            .to_string()
            .contains("TCPorUDP entries require protocol and dst_port")
    );

    let missing_destination = ServiceCreate::new(
        "bad",
        ServiceType::TcpOrUdp,
        vec![ServiceEntry::new().with_protocol("TCP")],
    )
    .expect_err("TCPorUDP requires destination port");
    assert!(
        missing_destination
            .to_string()
            .contains("TCPorUDP entries require protocol and dst_port")
    );
}

#[test]
fn service_create_ip_maps_protocol_to_protocol_name() {
    let (client, transport) = client_with([success_response(
        "Services",
        "Configuration applied successfully.",
    )]);
    let service = ServiceCreate::new("gre", ServiceType::Ip, vec![ServiceEntry::ip("GRE")])
        .expect("valid IP service");

    client
        .services()
        .create_service(service)
        .expect("service is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Type>IP</Type>"));
    assert!(xml.contains("<ProtocolName>GRE</ProtocolName>"));
    assert!(!xml.contains("<Protocol>GRE</Protocol>"));
}

#[test]
fn service_create_icmpv6_uses_matching_icmpv6_tags() {
    let (client, transport) = client_with([success_response(
        "Services",
        "Configuration applied successfully.",
    )]);
    let service = ServiceCreate::new(
        "icmpv6-echo",
        ServiceType::IcmpV6,
        vec![ServiceEntry::icmp_v6("128", "0")],
    )
    .expect("valid ICMPv6 service");

    client
        .services()
        .create_service(service)
        .expect("service is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<ICMPv6Type>128</ICMPv6Type>"));
    assert!(xml.contains("<ICMPv6Code>0</ICMPv6Code>"));
    assert!(!xml.contains("</ICMPType>"));
    assert!(!xml.contains("</ICMPCode>"));
}

#[test]
fn service_list_normalizes_single_and_multiple_records() {
    let (single_client, _) = client_with([response(service_xml(
        "web",
        "TCPorUDP",
        &tcp_detail("TCP", "1:65535", "443"),
    ))]);

    let single = single_client
        .services()
        .list_services()
        .expect("single record parses");

    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "web");
    assert_eq!(single[0].service_type(), ServiceType::TcpOrUdp);
    assert_eq!(single[0].entries(), &[ServiceEntry::tcp_udp("TCP", "443")]);

    let multiple_body = format!(
        "{}{}",
        service_xml("gre", "IP", &ip_detail("GRE")),
        service_xml("ping", "ICMP", &icmp_detail("8", "0")),
    );
    let (multiple_client, _) = client_with([response(multiple_body)]);

    let multiple = multiple_client
        .services()
        .list_services()
        .expect("multiple records parse");

    assert_eq!(
        multiple
            .iter()
            .map(|service| (service.name(), service.service_type(), service.entries()))
            .collect::<Vec<_>>(),
        vec![
            ("gre", ServiceType::Ip, &[ServiceEntry::ip("GRE")][..]),
            (
                "ping",
                ServiceType::Icmp,
                &[ServiceEntry::icmp("8", "0")][..]
            ),
        ]
    );
}

#[test]
fn service_get_returns_none_on_zero_records() {
    let (client, transport) = client_with([zero_records_response("Services")]);

    let service = client
        .services()
        .get_service("missing")
        .expect("zero records is mapped to None");

    assert_eq!(service, None);
    let request = &transport.captured_requests()[0];
    assert!(request.contains("<Get><Services>"));
    assert!(request.contains("<key name=\"Name\" criteria=\"=\">missing</key>"));
}

#[test]
fn service_update_add_fetches_existing_and_deduplicates_preserving_order() {
    let (client, transport) = client_with([
        response(service_xml(
            "web",
            "TCPorUDP",
            &(tcp_detail("TCP", "1:65535", "80") + &tcp_detail("TCP", "1:65535", "443")),
        )),
        success_response("Services", "Configuration applied successfully."),
    ]);

    client
        .services()
        .add_entries(
            "web",
            ServiceType::TcpOrUdp,
            vec![
                ServiceEntry::tcp_udp("TCP", "443"),
                ServiceEntry::tcp_udp("UDP", "53"),
            ],
        )
        .expect("entries are added");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<Get><Services>"));
    assert!(requests[1].contains("<Set operation=\"update\"><Services>"));
    assert_tokens_in_order(
        &requests[1],
        &[
            "<DestinationPort>80</DestinationPort>",
            "<DestinationPort>443</DestinationPort>",
            "<DestinationPort>53</DestinationPort>",
        ],
    );
    assert_eq!(
        requests[1]
            .matches("<DestinationPort>443</DestinationPort>")
            .count(),
        1
    );
}

#[test]
fn service_update_remove_preserves_unmentioned_entries() {
    let (client, transport) = client_with([
        response(service_xml(
            "web",
            "TCPorUDP",
            &(tcp_detail("TCP", "1:65535", "80")
                + &tcp_detail("TCP", "1:65535", "443")
                + &tcp_detail("UDP", "1:65535", "53")),
        )),
        success_response("Services", "Configuration applied successfully."),
    ]);

    client
        .services()
        .remove_entries(
            "web",
            ServiceType::TcpOrUdp,
            vec![ServiceEntry::tcp_udp("TCP", "443")],
        )
        .expect("entry is removed");

    let update = &transport.captured_requests()[1];
    assert_tokens_in_order(
        update,
        &[
            "<DestinationPort>80</DestinationPort>",
            "<DestinationPort>53</DestinationPort>",
        ],
    );
    assert!(!update.contains("<DestinationPort>443</DestinationPort>"));
}

#[test]
fn service_update_replace_replaces_full_entry_list() {
    let (client, transport) = client_with([
        response(service_xml(
            "web",
            "TCPorUDP",
            &(tcp_detail("TCP", "1:65535", "80") + &tcp_detail("TCP", "1:65535", "443")),
        )),
        success_response("Services", "Configuration applied successfully."),
    ]);

    client
        .services()
        .replace_entries(
            "web",
            ServiceType::TcpOrUdp,
            vec![
                ServiceEntry::tcp_udp("UDP", "53"),
                ServiceEntry::tcp_udp("UDP", "53"),
            ],
        )
        .expect("entries are replaced");

    let update = &transport.captured_requests()[1];
    assert!(update.contains("<DestinationPort>53</DestinationPort>"));
    assert!(!update.contains("<DestinationPort>80</DestinationPort>"));
    assert!(!update.contains("<DestinationPort>443</DestinationPort>"));
    assert_eq!(
        update
            .matches("<DestinationPort>53</DestinationPort>")
            .count(),
        1
    );
}

#[test]
fn service_update_missing_service_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("Services")]);

    let error = client
        .services()
        .add_entries(
            "missing",
            ServiceType::TcpOrUdp,
            vec![ServiceEntry::tcp_udp("TCP", "443")],
        )
        .expect_err("missing service is an invalid update");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn service_update_type_mismatch_does_not_send_update() {
    let (client, transport) = client_with([response(service_xml("gre", "IP", &ip_detail("GRE")))]);

    let error = client
        .services()
        .add_entries(
            "gre",
            ServiceType::TcpOrUdp,
            vec![ServiceEntry::tcp_udp("TCP", "443")],
        )
        .expect_err("wrong service type is rejected before update");

    assert!(error.to_string().contains("has type IP, not TCPorUDP"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn service_delete_uses_services_resource_and_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(service_xml(
            "web",
            "TCPorUDP",
            &tcp_detail("TCP", "1:65535", "443"),
        )),
        success_response("Services", "Configuration applied successfully."),
    ]);

    client.services().delete_service("web").expect("deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("<Remove><Services><Name>web</Name></Services></Remove>"));

    let (missing_client, missing_transport) = client_with([zero_records_response("Services")]);
    let error = missing_client
        .services()
        .delete_service("missing")
        .expect_err("missing service is not deleted");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}

#[test]
fn service_group_create_uses_set_operation_and_service_list() {
    let (client, transport) = client_with([success_response(
        "ServiceGroup",
        "Configuration applied successfully.",
    )]);
    let group = ServiceGroupCreate::new("Web Services", vec!["HTTP", "HTTPS"])
        .expect("valid group")
        .with_description("Browser traffic");

    client
        .service_groups()
        .create_group(group)
        .expect("group is created");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    let xml = &requests[0];
    assert!(xml.contains("<Set operation=\"set\"><ServiceGroup>"));
    assert!(xml.contains("<Name>Web Services</Name>"));
    assert!(xml.contains("<Description>Browser traffic</Description>"));
    assert_tokens_in_order(
        xml,
        &["<Service>HTTP</Service>", "<Service>HTTPS</Service>"],
    );
}

#[test]
fn service_group_list_normalizes_single_and_multiple_records() {
    let (single_client, _) = client_with([response(service_group_xml(
        "Web Services",
        "Browser traffic",
        &["HTTP", "HTTPS"],
    ))]);

    let single = single_client
        .service_groups()
        .list_groups()
        .expect("single record parses");

    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "Web Services");
    assert_eq!(single[0].description(), Some("Browser traffic"));
    assert_eq!(single[0].services(), &["HTTP", "HTTPS"]);

    let multiple_body = format!(
        "{}{}",
        service_group_xml("Web", "", &["HTTP"]),
        service_group_xml("Mail", "SMTP stuff", &["SMTP", "IMAP"]),
    );
    let (multiple_client, _) = client_with([response(multiple_body)]);

    let multiple = multiple_client
        .service_groups()
        .list_groups()
        .expect("multiple records parse");

    assert_eq!(multiple.len(), 2);
    assert_eq!(multiple[0].name(), "Web");
    assert_eq!(multiple[0].description(), None);
    assert_eq!(multiple[0].services(), &["HTTP"]);
    assert_eq!(multiple[1].name(), "Mail");
    assert_eq!(multiple[1].description(), Some("SMTP stuff"));
    assert_eq!(multiple[1].services(), &["SMTP", "IMAP"]);
}

#[test]
fn service_group_update_preserves_description_when_not_provided() {
    let (client, transport) = client_with([
        response(service_group_xml(
            "Web Services",
            "Browser traffic",
            &["HTTP"],
        )),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);

    client
        .service_groups()
        .add_services("Web Services", vec!["HTTPS"])
        .expect("member is added");

    let update = &transport.captured_requests()[1];
    assert!(update.contains("<Description>Browser traffic</Description>"));
    assert_tokens_in_order(
        update,
        &["<Service>HTTP</Service>", "<Service>HTTPS</Service>"],
    );
}

#[test]
fn service_group_update_can_override_description() {
    let (client, transport) = client_with([
        response(service_group_xml(
            "Web Services",
            "Browser traffic",
            &["HTTP"],
        )),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);
    let update = ServiceGroupUpdate::new(
        "Web Services",
        vec!["HTTP", "HTTPS"],
        ServiceGroupUpdateAction::Replace,
    )
    .expect("valid group update")
    .with_description("Curated browser services");

    client
        .service_groups()
        .update_group(update)
        .expect("group is updated");

    let update_xml = &transport.captured_requests()[1];
    assert!(update_xml.contains("<Description>Curated browser services</Description>"));
    assert!(!update_xml.contains("<Description>Browser traffic</Description>"));
}

#[test]
fn service_group_rejects_blank_service_names() {
    let error = ServiceGroupCreate::new("Web Services", vec!["HTTP", "  "])
        .expect_err("blank service names are invalid");

    assert!(error.to_string().contains("service must not be empty"));
}

#[test]
fn service_group_update_add_remove_replace_members_dedupe_preserving_order() {
    let (add_client, add_transport) = client_with([
        response(service_group_xml("Web", "", &["HTTP", "HTTPS"])),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);
    add_client
        .service_groups()
        .add_services("Web", vec!["HTTPS", "SSH"])
        .expect("member is added");
    let add_update = &add_transport.captured_requests()[1];
    assert_tokens_in_order(
        add_update,
        &[
            "<Service>HTTP</Service>",
            "<Service>HTTPS</Service>",
            "<Service>SSH</Service>",
        ],
    );
    assert_eq!(add_update.matches("<Service>HTTPS</Service>").count(), 1);

    let (remove_client, remove_transport) = client_with([
        response(service_group_xml("Web", "", &["HTTP", "HTTPS", "SSH"])),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);
    remove_client
        .service_groups()
        .remove_services("Web", vec!["HTTPS"])
        .expect("member is removed");
    let remove_update = &remove_transport.captured_requests()[1];
    assert_tokens_in_order(
        remove_update,
        &["<Service>HTTP</Service>", "<Service>SSH</Service>"],
    );
    assert!(!remove_update.contains("<Service>HTTPS</Service>"));

    let (replace_client, replace_transport) = client_with([
        response(service_group_xml("Web", "", &["HTTP", "HTTPS"])),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);
    replace_client
        .service_groups()
        .replace_services("Web", vec!["DNS", "DNS"])
        .expect("members are replaced");
    let replace_update = &replace_transport.captured_requests()[1];
    assert!(replace_update.contains("<Service>DNS</Service>"));
    assert!(!replace_update.contains("<Service>HTTP</Service>"));
    assert!(!replace_update.contains("<Service>HTTPS</Service>"));
    assert_eq!(replace_update.matches("<Service>DNS</Service>").count(), 1);
}

#[test]
fn service_group_update_missing_group_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("ServiceGroup")]);

    let error = client
        .service_groups()
        .add_services("missing", vec!["HTTP"])
        .expect_err("missing group is an invalid update");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn service_group_delete_uses_service_group_resource_and_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(service_group_xml("Web", "", &["HTTP"])),
        success_response("ServiceGroup", "Configuration applied successfully."),
    ]);

    client
        .service_groups()
        .delete_group("Web")
        .expect("group is deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("<Remove><ServiceGroup><Name>Web</Name></ServiceGroup></Remove>"));

    let (missing_client, missing_transport) = client_with([zero_records_response("ServiceGroup")]);
    let error = missing_client
        .service_groups()
        .delete_group("missing")
        .expect_err("missing group is not deleted");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}
