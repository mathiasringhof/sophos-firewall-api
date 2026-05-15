use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall_api::{
    Error, FqdnHostCreate, FqdnHostGroupCreate, FqdnHostGroupUpdate, FqdnHostUpdate, IpHostCreate,
    IpHostGroupCreate, IpHostGroupUpdate, IpNetworkCreate, IpRangeCreate, NetworkGroupUpdateAction,
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

fn ip_host_xml(name: &str, ip: &str) -> String {
    format!(
        "<IPHost><Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ip}</IPAddress></IPHost>"
    )
}

fn ip_network_xml(name: &str, ip: &str, subnet: &str) -> String {
    format!(
        "<IPHost><Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>{ip}</IPAddress><Subnet>{subnet}</Subnet></IPHost>"
    )
}

fn ip_range_xml(name: &str, start: &str, end: &str) -> String {
    format!(
        "<IPHost><Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>IPRange</HostType><StartIPAddress>{start}</StartIPAddress><EndIPAddress>{end}</EndIPAddress></IPHost>"
    )
}

fn ip_host_group_xml(name: &str, description: &str, hosts: &[&str]) -> String {
    let hosts = hosts
        .iter()
        .map(|host| format!("<Host>{host}</Host>"))
        .collect::<String>();
    format!(
        "<IPHostGroup><Name>{name}</Name><IPFamily>IPv4</IPFamily><Description>{description}</Description><HostList>{hosts}</HostList></IPHostGroup>"
    )
}

fn fqdn_host_xml(name: &str, description: &str, fqdn: &str, groups: &[&str]) -> String {
    let groups = groups
        .iter()
        .map(|group| format!("<FQDNHostGroup>{group}</FQDNHostGroup>"))
        .collect::<String>();
    format!(
        "<FQDNHost><Name>{name}</Name><Description>{description}</Description><FQDN>{fqdn}</FQDN><FQDNHostGroupList>{groups}</FQDNHostGroupList></FQDNHost>"
    )
}

fn fqdn_host_group_xml(name: &str, description: &str, hosts: &[&str]) -> String {
    let hosts = hosts
        .iter()
        .map(|host| format!("<FQDNHost>{host}</FQDNHost>"))
        .collect::<String>();
    format!(
        "<FQDNHostGroup><Name>{name}</Name><Description>{description}</Description><FQDNHostList>{hosts}</FQDNHostList></FQDNHostGroup>"
    )
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
fn ip_host_create_uses_iphost_payload_and_rejects_ipv6() {
    let (client, transport) = client_with([success_response("IPHost")]);
    let host = IpHostCreate::new("workstation", "192.0.2.10").expect("valid host");

    client
        .network()
        .create_ip_host(host)
        .expect("host is created");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 1);
    let xml = &requests[0];
    assert!(xml.contains("<Set operation=\"add\"><IPHost>"));
    assert!(xml.contains("<Name>workstation</Name>"));
    assert!(xml.contains("<HostType>IP</HostType>"));
    assert!(xml.contains("<IPFamily>IPv4</IPFamily>"));
    assert!(xml.contains("<IPAddress>192.0.2.10</IPAddress>"));

    let error = IpHostCreate::new("bad", "2001:db8::1").expect_err("IPv6 is rejected");
    assert!(error.to_string().contains("must be an IPv4 address"));
}

#[test]
fn ip_network_create_uses_network_payload_and_validates_mask() {
    let (client, transport) = client_with([success_response("IPHost")]);
    let network =
        IpNetworkCreate::new("lab-net", "192.0.2.0", "255.255.255.0").expect("valid network");

    client
        .network()
        .create_ip_network(network)
        .expect("network is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Set operation=\"add\"><IPHost>"));
    assert!(xml.contains("<HostType>Network</HostType>"));
    assert!(xml.contains("<IPAddress>192.0.2.0</IPAddress>"));
    assert!(xml.contains("<Subnet>255.255.255.0</Subnet>"));

    let error = IpNetworkCreate::new("bad", "192.0.2.0", "24")
        .expect_err("CIDR prefixes are not dotted decimal masks");
    assert!(error.to_string().contains("subnet must be an IPv4 address"));
}

#[test]
fn ip_range_create_uses_range_payload_and_rejects_reversed_range() {
    let (client, transport) = client_with([success_response("IPHost")]);
    let range = IpRangeCreate::new("pool", "192.0.2.20", "192.0.2.30").expect("valid range");

    client
        .network()
        .create_ip_range(range)
        .expect("range is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<HostType>IPRange</HostType>"));
    assert!(xml.contains("<StartIPAddress>192.0.2.20</StartIPAddress>"));
    assert!(xml.contains("<EndIPAddress>192.0.2.30</EndIPAddress>"));

    let error = IpRangeCreate::new("bad", "192.0.2.30", "192.0.2.20")
        .expect_err("reversed ranges are rejected");
    assert!(
        error
            .to_string()
            .contains("start_ip must be less than or equal to end_ip")
    );
}

#[test]
fn ip_host_list_normalizes_single_and_multiple_records() {
    let (single_client, _) = client_with([response(ip_host_xml("one", "192.0.2.10"))]);
    let single = single_client
        .network()
        .list_ip_hosts()
        .expect("single parses");
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].name(), "one");
    assert_eq!(single[0].ip_address(), "192.0.2.10");

    let body = format!(
        "{}{}{}",
        ip_host_xml("one", "192.0.2.10"),
        ip_network_xml("net", "192.0.2.0", "255.255.255.0"),
        ip_host_xml("two", "192.0.2.11")
    );
    let (multiple_client, _) = client_with([response(body)]);
    let multiple = multiple_client
        .network()
        .list_ip_hosts()
        .expect("multiple parses");
    assert_eq!(
        multiple
            .iter()
            .map(|host| (host.name(), host.ip_address()))
            .collect::<Vec<_>>(),
        vec![("one", "192.0.2.10"), ("two", "192.0.2.11")]
    );
}

#[test]
fn ip_network_and_range_lists_filter_iphost_records_by_host_type() {
    let body = format!(
        "{}{}{}",
        ip_host_xml("one", "192.0.2.10"),
        ip_network_xml("net", "192.0.2.0", "255.255.255.0"),
        ip_range_xml("pool", "192.0.2.20", "192.0.2.30")
    );
    let (network_client, _) = client_with([response(body.clone())]);
    let networks = network_client
        .network()
        .list_ip_networks()
        .expect("networks parse");
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name(), "net");
    assert_eq!(networks[0].subnet(), "255.255.255.0");

    let (range_client, _) = client_with([response(body)]);
    let ranges = range_client
        .network()
        .list_ip_ranges()
        .expect("ranges parse");
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].name(), "pool");
    assert_eq!(ranges[0].start_ip(), "192.0.2.20");
}

#[test]
fn ip_host_get_returns_none_when_zero_records_or_wrong_type() {
    let (zero_client, _) = client_with([zero_records_response("IPHost")]);
    assert_eq!(
        zero_client
            .network()
            .get_ip_host("missing")
            .expect("lookup"),
        None
    );

    let (wrong_client, _) = client_with([response(ip_network_xml(
        "net",
        "192.0.2.0",
        "255.255.255.0",
    ))]);
    assert_eq!(
        wrong_client.network().get_ip_host("net").expect("lookup"),
        None
    );
}

#[test]
fn ip_host_update_uses_update_operation_and_name_key() {
    let (client, transport) = client_with([success_response("IPHost")]);
    let host = IpHostCreate::new("workstation", "192.0.2.99").expect("valid host");

    client
        .network()
        .update_ip_host(host)
        .expect("host is updated");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Set operation=\"update\"><IPHost>"));
    assert!(xml.contains("<Name>workstation</Name>"));
    assert!(xml.contains("<HostType>IP</HostType>"));
    assert!(xml.contains("<IPAddress>192.0.2.99</IPAddress>"));
}

#[test]
fn ip_host_delete_uses_iphost_resource_and_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(ip_host_xml("workstation", "192.0.2.10")),
        success_response("IPHost"),
    ]);

    client
        .network()
        .delete_ip_host("workstation")
        .expect("host is deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<key name=\"Name\" criteria=\"=\">workstation</key>"));
    assert!(requests[1].contains("<Remove><IPHost><Name>workstation</Name></IPHost></Remove>"));

    let (missing_client, missing_transport) = client_with([zero_records_response("IPHost")]);
    let error = missing_client
        .network()
        .delete_ip_host("missing")
        .expect_err("missing host is not deleted");
    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}

#[test]
fn ip_network_delete_wrong_type_does_not_send_remove() {
    let (client, transport) = client_with([response(ip_host_xml("workstation", "192.0.2.10"))]);

    let error = client
        .network()
        .delete_ip_network("workstation")
        .expect_err("IP host is not deleted as a network");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn ip_host_group_create_uses_host_list_and_ipv4_family() {
    let (client, transport) = client_with([success_response("IPHostGroup")]);
    let group = IpHostGroupCreate::new("workstations", vec!["host-a", "host-b"])
        .expect("valid group")
        .with_description("lab clients");

    client
        .network()
        .create_ip_host_group(group)
        .expect("group is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Set operation=\"add\"><IPHostGroup>"));
    assert!(xml.contains("<IPFamily>IPv4</IPFamily>"));
    assert!(xml.contains("<Description>lab clients</Description>"));
    assert_tokens_in_order(xml, &["<Host>host-a</Host>", "<Host>host-b</Host>"]);
}

#[test]
fn ip_host_group_update_add_remove_replace_members_dedupe_preserving_order() {
    let (add_client, add_transport) = client_with([
        response(ip_host_group_xml("workstations", "kept", &["a", "b"])),
        success_response("IPHostGroup"),
    ]);
    let add = IpHostGroupUpdate::new(
        "workstations",
        vec!["b", "c", "c"],
        NetworkGroupUpdateAction::Add,
    )
    .expect("valid update");
    add_client
        .network()
        .update_ip_host_group(add)
        .expect("members are added");
    let update = &add_transport.captured_requests()[1];
    assert_tokens_in_order(
        update,
        &["<Host>a</Host>", "<Host>b</Host>", "<Host>c</Host>"],
    );
    assert_eq!(update.matches("<Host>c</Host>").count(), 1);

    let (remove_client, remove_transport) = client_with([
        response(ip_host_group_xml("workstations", "kept", &["a", "b", "c"])),
        success_response("IPHostGroup"),
    ]);
    let remove =
        IpHostGroupUpdate::new("workstations", vec!["b"], NetworkGroupUpdateAction::Remove)
            .expect("valid update");
    remove_client
        .network()
        .update_ip_host_group(remove)
        .expect("members are removed");
    let update = &remove_transport.captured_requests()[1];
    assert_tokens_in_order(update, &["<Host>a</Host>", "<Host>c</Host>"]);
    assert!(!update.contains("<Host>b</Host>"));

    let (replace_client, replace_transport) = client_with([
        response(ip_host_group_xml("workstations", "kept", &["a", "b"])),
        success_response("IPHostGroup"),
    ]);
    let replace = IpHostGroupUpdate::new(
        "workstations",
        vec!["d", "d", "e"],
        NetworkGroupUpdateAction::Replace,
    )
    .expect("valid update");
    replace_client
        .network()
        .update_ip_host_group(replace)
        .expect("members are replaced");
    let update = &replace_transport.captured_requests()[1];
    assert_tokens_in_order(update, &["<Host>d</Host>", "<Host>e</Host>"]);
    assert!(!update.contains("<Host>a</Host>"));
    assert_eq!(update.matches("<Host>d</Host>").count(), 1);
}

#[test]
fn ip_host_group_update_preserves_or_overrides_description() {
    let (preserve_client, preserve_transport) = client_with([
        response(ip_host_group_xml("workstations", "keep me", &["a"])),
        success_response("IPHostGroup"),
    ]);
    let update = IpHostGroupUpdate::new("workstations", vec!["b"], NetworkGroupUpdateAction::Add)
        .expect("valid update");
    preserve_client
        .network()
        .update_ip_host_group(update)
        .expect("description is preserved");
    assert!(
        preserve_transport.captured_requests()[1].contains("<Description>keep me</Description>")
    );

    let (override_client, override_transport) = client_with([
        response(ip_host_group_xml("workstations", "old", &["a"])),
        success_response("IPHostGroup"),
    ]);
    let update = IpHostGroupUpdate::new("workstations", vec!["b"], NetworkGroupUpdateAction::Add)
        .expect("valid update")
        .with_description("new");
    override_client
        .network()
        .update_ip_host_group(update)
        .expect("description is overridden");
    assert!(override_transport.captured_requests()[1].contains("<Description>new</Description>"));
}

#[test]
fn ip_host_group_update_missing_group_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("IPHostGroup")]);
    let update = IpHostGroupUpdate::new("missing", vec!["a"], NetworkGroupUpdateAction::Add)
        .expect("valid update");

    let error = client
        .network()
        .update_ip_host_group(update)
        .expect_err("missing group is not updated");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn ip_host_group_delete_uses_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(ip_host_group_xml("workstations", "", &["a"])),
        success_response("IPHostGroup"),
    ]);

    client
        .network()
        .delete_ip_host_group("workstations")
        .expect("group is deleted");

    assert!(
        transport.captured_requests()[1]
            .contains("<Remove><IPHostGroup><Name>workstations</Name></IPHostGroup></Remove>")
    );

    let (missing_client, missing_transport) = client_with([zero_records_response("IPHostGroup")]);
    let error = missing_client
        .network()
        .delete_ip_host_group("missing")
        .expect_err("missing group is not deleted");
    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}

#[test]
fn fqdn_host_create_uses_fqdn_and_optional_group_list() {
    let (client, transport) = client_with([success_response("FQDNHost")]);
    let host = FqdnHostCreate::new("app", "app.example")
        .expect("valid FQDN host")
        .with_description("frontend")
        .with_groups(vec!["web", "web", "prod"])
        .expect("valid group list");

    client
        .network()
        .create_fqdn_host(host)
        .expect("FQDN host is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Set operation=\"add\"><FQDNHost>"));
    assert!(xml.contains("<FQDN>app.example</FQDN>"));
    assert!(xml.contains("<Description>frontend</Description>"));
    assert_tokens_in_order(
        xml,
        &[
            "<FQDNHostGroup>web</FQDNHostGroup>",
            "<FQDNHostGroup>prod</FQDNHostGroup>",
        ],
    );
    assert_eq!(xml.matches("<FQDNHostGroup>web</FQDNHostGroup>").count(), 1);
}

#[test]
fn fqdn_host_list_get_update_delete_roundtrip_payloads() {
    let (list_client, _) = client_with([response(format!(
        "{}{}",
        fqdn_host_xml("app", "frontend", "app.example", &["web"]),
        fqdn_host_xml("db", "database", "db.example", &[])
    ))]);
    let hosts = list_client
        .network()
        .list_fqdn_hosts()
        .expect("hosts parse");
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].name(), "app");
    assert_eq!(hosts[0].fqdn(), "app.example");
    assert_eq!(hosts[0].groups(), &["web".to_string()]);

    let (get_client, get_transport) = client_with([response(fqdn_host_xml(
        "app",
        "frontend",
        "app.example",
        &["web"],
    ))]);
    assert_eq!(
        get_client
            .network()
            .get_fqdn_host("app")
            .expect("lookup")
            .expect("exists")
            .description(),
        Some("frontend")
    );
    assert!(
        get_transport.captured_requests()[0]
            .contains("<key name=\"Name\" criteria=\"=\">app</key>")
    );

    let (update_client, update_transport) = client_with([
        response(fqdn_host_xml("app", "frontend", "old.example", &["web"])),
        success_response("FQDNHost"),
    ]);
    let update = FqdnHostUpdate::new("app")
        .expect("valid update")
        .with_fqdn("new.example")
        .expect("valid FQDN");
    update_client
        .network()
        .update_fqdn_host(update)
        .expect("host is updated");
    let xml = &update_transport.captured_requests()[1];
    assert!(xml.contains("<Set operation=\"update\"><FQDNHost>"));
    assert!(xml.contains("<FQDN>new.example</FQDN>"));

    let (delete_client, delete_transport) = client_with([
        response(fqdn_host_xml("app", "frontend", "app.example", &["web"])),
        success_response("FQDNHost"),
    ]);
    delete_client
        .network()
        .delete_fqdn_host("app")
        .expect("host is deleted");
    assert!(
        delete_transport.captured_requests()[1]
            .contains("<Remove><FQDNHost><Name>app</Name></FQDNHost></Remove>")
    );
}

#[test]
fn fqdn_host_update_preserves_description_and_groups_when_not_provided() {
    let (client, transport) = client_with([
        response(fqdn_host_xml(
            "app",
            "frontend",
            "old.example",
            &["web", "prod"],
        )),
        success_response("FQDNHost"),
    ]);
    let update = FqdnHostUpdate::new("app")
        .expect("valid update")
        .with_fqdn("new.example")
        .expect("valid FQDN");

    client
        .network()
        .update_fqdn_host(update)
        .expect("host is updated");

    let xml = &transport.captured_requests()[1];
    assert!(xml.contains("<Description>frontend</Description>"));
    assert_tokens_in_order(
        xml,
        &[
            "<FQDNHostGroup>web</FQDNHostGroup>",
            "<FQDNHostGroup>prod</FQDNHostGroup>",
        ],
    );
}

#[test]
fn fqdn_host_update_overrides_description_and_replaces_group_list() {
    let (client, transport) = client_with([
        response(fqdn_host_xml(
            "app",
            "frontend",
            "app.example",
            &["web", "prod"],
        )),
        success_response("FQDNHost"),
    ]);
    let update = FqdnHostUpdate::new("app")
        .expect("valid update")
        .with_description("customer portal")
        .with_groups(vec!["blue", "blue", "prod"])
        .expect("valid group list");

    client
        .network()
        .update_fqdn_host(update)
        .expect("host is updated");

    let xml = &transport.captured_requests()[1];
    assert!(xml.contains("<Description>customer portal</Description>"));
    assert!(!xml.contains("<Description>frontend</Description>"));
    assert!(xml.contains("<FQDN>app.example</FQDN>"));
    assert_tokens_in_order(
        xml,
        &[
            "<FQDNHostGroup>blue</FQDNHostGroup>",
            "<FQDNHostGroup>prod</FQDNHostGroup>",
        ],
    );
    assert!(!xml.contains("<FQDNHostGroup>web</FQDNHostGroup>"));
    assert_eq!(
        xml.matches("<FQDNHostGroup>blue</FQDNHostGroup>").count(),
        1
    );
}

#[test]
fn fqdn_host_update_missing_host_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("FQDNHost")]);
    let update = FqdnHostUpdate::new("missing")
        .expect("valid update")
        .with_fqdn("missing.example")
        .expect("valid FQDN");

    let error = client
        .network()
        .update_fqdn_host(update)
        .expect_err("missing host is not updated");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn fqdn_host_delete_missing_host_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("FQDNHost")]);

    let error = client
        .network()
        .delete_fqdn_host("missing")
        .expect_err("missing host is not deleted");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn fqdn_group_inputs_reject_blank_host_names() {
    let error = FqdnHostGroupCreate::new("web-fqdns", vec!["app", "  "])
        .expect_err("blank FQDN host members are invalid");

    assert!(error.to_string().contains("FQDN host must not be empty"));
}

#[test]
fn fqdn_host_group_create_uses_fqdn_host_list() {
    let (client, transport) = client_with([success_response("FQDNHostGroup")]);
    let group = FqdnHostGroupCreate::new("web-fqdns", vec!["app", "api"])
        .expect("valid group")
        .with_description("web hosts");

    client
        .network()
        .create_fqdn_host_group(group)
        .expect("group is created");

    let xml = &transport.captured_requests()[0];
    assert!(xml.contains("<Set operation=\"add\"><FQDNHostGroup>"));
    assert!(xml.contains("<Description>web hosts</Description>"));
    assert_tokens_in_order(
        xml,
        &["<FQDNHost>app</FQDNHost>", "<FQDNHost>api</FQDNHost>"],
    );
}

#[test]
fn fqdn_host_group_update_add_remove_replace_members_dedupe_preserving_order() {
    let (client, transport) = client_with([
        response(fqdn_host_group_xml("web-fqdns", "kept", &["app", "api"])),
        success_response("FQDNHostGroup"),
    ]);
    let update = FqdnHostGroupUpdate::new(
        "web-fqdns",
        vec!["api", "cdn", "cdn"],
        NetworkGroupUpdateAction::Add,
    )
    .expect("valid update");
    client
        .network()
        .update_fqdn_host_group(update)
        .expect("members are added");
    let xml = &transport.captured_requests()[1];
    assert_tokens_in_order(
        xml,
        &[
            "<FQDNHost>app</FQDNHost>",
            "<FQDNHost>api</FQDNHost>",
            "<FQDNHost>cdn</FQDNHost>",
        ],
    );
    assert_eq!(xml.matches("<FQDNHost>cdn</FQDNHost>").count(), 1);

    let (remove_client, remove_transport) = client_with([
        response(fqdn_host_group_xml(
            "web-fqdns",
            "kept",
            &["app", "api", "cdn"],
        )),
        success_response("FQDNHostGroup"),
    ]);
    let update =
        FqdnHostGroupUpdate::new("web-fqdns", vec!["api"], NetworkGroupUpdateAction::Remove)
            .expect("valid update");
    remove_client
        .network()
        .update_fqdn_host_group(update)
        .expect("members are removed");
    let xml = &remove_transport.captured_requests()[1];
    assert_tokens_in_order(
        xml,
        &["<FQDNHost>app</FQDNHost>", "<FQDNHost>cdn</FQDNHost>"],
    );
    assert!(!xml.contains("<FQDNHost>api</FQDNHost>"));

    let (replace_client, replace_transport) = client_with([
        response(fqdn_host_group_xml("web-fqdns", "kept", &["app", "api"])),
        success_response("FQDNHostGroup"),
    ]);
    let update = FqdnHostGroupUpdate::new(
        "web-fqdns",
        vec!["new", "new", "other"],
        NetworkGroupUpdateAction::Replace,
    )
    .expect("valid update");
    replace_client
        .network()
        .update_fqdn_host_group(update)
        .expect("members are replaced");
    let xml = &replace_transport.captured_requests()[1];
    assert_tokens_in_order(
        xml,
        &["<FQDNHost>new</FQDNHost>", "<FQDNHost>other</FQDNHost>"],
    );
    assert!(!xml.contains("<FQDNHost>app</FQDNHost>"));
    assert_eq!(xml.matches("<FQDNHost>new</FQDNHost>").count(), 1);
}

#[test]
fn fqdn_host_group_update_missing_group_does_not_send_update() {
    let (client, transport) = client_with([zero_records_response("FQDNHostGroup")]);
    let update = FqdnHostGroupUpdate::new("missing", vec!["app"], NetworkGroupUpdateAction::Add)
        .expect("valid update");

    let error = client
        .network()
        .update_fqdn_host_group(update)
        .expect_err("missing group is not updated");

    assert!(error.to_string().contains("does not exist"));
    assert_eq!(transport.captured_requests().len(), 1);
}

#[test]
fn fqdn_host_group_delete_uses_name_key_and_fails_when_missing() {
    let (client, transport) = client_with([
        response(fqdn_host_group_xml("web-fqdns", "", &["app"])),
        success_response("FQDNHostGroup"),
    ]);

    client
        .network()
        .delete_fqdn_host_group("web-fqdns")
        .expect("group is deleted");

    assert!(
        transport.captured_requests()[1]
            .contains("<Remove><FQDNHostGroup><Name>web-fqdns</Name></FQDNHostGroup></Remove>")
    );

    let (missing_client, missing_transport) = client_with([zero_records_response("FQDNHostGroup")]);
    let error = missing_client
        .network()
        .delete_fqdn_host_group("missing")
        .expect_err("missing group is not deleted");
    assert!(error.to_string().contains("does not exist"));
    assert_eq!(missing_transport.captured_requests().len(), 1);
}
