use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

const RESOURCE: &str = "DNSHostEntry";
const HOST_KEY: &str = "HostName";
const DEFAULT_TTL: u32 = 3600;
const DEFAULT_WEIGHT: u8 = 0;
const MAX_ADDRESSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    Manual,
    #[serde(rename = "InterfaceIP")]
    InterfaceIp,
}

impl EntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::InterfaceIp => "InterfaceIP",
        }
    }

    fn from_sophos(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("InterfaceIP") => Self::InterfaceIp,
            _ => Self::Manual,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

impl IpFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
        }
    }

    fn from_sophos(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("IPv6") => Self::IPv6,
            _ => Self::IPv4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishOnWan {
    Enable,
    Disable,
}

impl PublishOnWan {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "Enable",
            Self::Disable => "Disable",
        }
    }

    fn from_sophos(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("enable") => Self::Enable,
            _ => Self::Disable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHostAddress {
    entry_type: EntryType,
    ip_family: IpFamily,
    ip_address: String,
    ttl: u32,
    weight: u8,
    publish_on_wan: PublishOnWan,
}

impl DnsHostAddress {
    pub fn new(
        entry_type: EntryType,
        ip_family: IpFamily,
        ip_address: impl Into<String>,
    ) -> Result<Self> {
        Self::with_options(
            entry_type,
            ip_family,
            ip_address,
            DEFAULT_TTL,
            DEFAULT_WEIGHT,
            PublishOnWan::Disable,
        )
    }

    pub fn with_options(
        entry_type: EntryType,
        ip_family: IpFamily,
        ip_address: impl Into<String>,
        ttl: u32,
        weight: u8,
        publish_on_wan: PublishOnWan,
    ) -> Result<Self> {
        let ip_address = ip_address.into();
        if ip_address.trim().is_empty() {
            return Err(Error::InvalidRequest(
                "ip_address must not be empty".to_string(),
            ));
        }
        if !(1..=604_800).contains(&ttl) {
            return Err(Error::InvalidRequest(
                "ttl must be between 1 and 604800".to_string(),
            ));
        }

        if entry_type == EntryType::Manual {
            validate_ip_address(ip_family, &ip_address)?;
        }

        Ok(Self {
            entry_type,
            ip_family,
            ip_address,
            ttl,
            weight,
            publish_on_wan,
        })
    }

    pub fn entry_type(&self) -> EntryType {
        self.entry_type
    }

    pub fn ip_family(&self) -> IpFamily {
        self.ip_family
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn weight(&self) -> u8 {
        self.weight
    }

    pub fn publish_on_wan(&self) -> PublishOnWan {
        self.publish_on_wan
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHostEntryCreate {
    host_name: String,
    addresses: Vec<DnsHostAddress>,
    add_reverse_dns_lookup: bool,
}

impl DnsHostEntryCreate {
    pub fn new(host_name: impl AsRef<str>, addresses: Vec<DnsHostAddress>) -> Result<Self> {
        validate_addresses(&addresses)?;
        Ok(Self {
            host_name: normalize_host_name(host_name.as_ref())?,
            addresses,
            add_reverse_dns_lookup: false,
        })
    }

    pub fn with_add_reverse_dns_lookup(mut self, add_reverse_dns_lookup: bool) -> Self {
        self.add_reverse_dns_lookup = add_reverse_dns_lookup;
        self
    }

    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    pub fn addresses(&self) -> &[DnsHostAddress] {
        &self.addresses
    }

    pub fn add_reverse_dns_lookup(&self) -> bool {
        self.add_reverse_dns_lookup
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHostEntryUpdate {
    host_name: String,
    addresses: Option<Vec<DnsHostAddress>>,
    add_reverse_dns_lookup: Option<bool>,
}

impl DnsHostEntryUpdate {
    pub fn new(host_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            host_name: normalize_host_name(host_name.as_ref())?,
            addresses: None,
            add_reverse_dns_lookup: None,
        })
    }

    pub fn with_addresses(mut self, addresses: Vec<DnsHostAddress>) -> Result<Self> {
        validate_addresses(&addresses)?;
        self.addresses = Some(addresses);
        Ok(self)
    }

    pub fn with_add_reverse_dns_lookup(mut self, add_reverse_dns_lookup: bool) -> Self {
        self.add_reverse_dns_lookup = Some(add_reverse_dns_lookup);
        self
    }

    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    pub fn addresses(&self) -> Option<&[DnsHostAddress]> {
        self.addresses.as_deref()
    }

    pub fn add_reverse_dns_lookup(&self) -> Option<bool> {
        self.add_reverse_dns_lookup
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMutationAction {
    Created,
    Updated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMutationOutcome {
    pub action: DnsMutationAction,
    pub response: ResourceResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsBulkMutationResult {
    pub total: usize,
    pub created: usize,
    pub updated: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl DnsBulkMutationResult {
    fn new(total: usize) -> Self {
        Self {
            total,
            created: 0,
            updated: 0,
            failed: 0,
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DnsApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn dns(&self) -> DnsApi<'_, T> {
        DnsApi { client: self }
    }
}

impl<T> DnsApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_entries(&self) -> Result<Vec<DnsHostEntryCreate>> {
        match self.client.execute(&SophosRequest::read(RESOURCE)) {
            Ok(response) => entries_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == RESOURCE => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    pub fn get_entry(&self, host_name: impl AsRef<str>) -> Result<Option<DnsHostEntryCreate>> {
        let host_name = normalize_host_name(host_name.as_ref())?;
        let request = SophosRequest::read(RESOURCE)
            .for_object(host_name.clone())
            .with_object_key(HOST_KEY);

        match self.client.execute(&request) {
            Ok(response) => Ok(entries_from_response(&response.resources)?
                .into_iter()
                .find(|entry| entry.host_name == host_name)),
            Err(Error::ZeroRecords { resource }) if resource == RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn add_entry(&self, entry: DnsHostEntryCreate, force: bool) -> Result<DnsMutationOutcome> {
        let existing = self.get_entry(entry.host_name())?;
        if existing.is_some() && !force {
            return Err(Error::InvalidRequest(format!(
                "DNS entry '{}' already exists",
                entry.host_name()
            )));
        }

        let action = if existing.is_some() {
            DnsMutationAction::Updated
        } else {
            DnsMutationAction::Created
        };
        let request_action = if existing.is_some() {
            Action::Update
        } else {
            Action::Create
        };
        let response = self.submit_entry(&entry, request_action)?;
        Ok(DnsMutationOutcome { action, response })
    }

    pub fn update_entry(&self, entry: DnsHostEntryUpdate) -> Result<ResourceResponse> {
        if entry.addresses.is_none() && entry.add_reverse_dns_lookup.is_none() {
            return Err(Error::InvalidRequest(
                "At least one of 'addresses' or 'add_reverse_dns_lookup' must be provided"
                    .to_string(),
            ));
        }

        let existing = self.get_entry(entry.host_name())?.ok_or_else(|| {
            Error::InvalidRequest(format!("DNS entry '{}' does not exist", entry.host_name()))
        })?;

        let merged = DnsHostEntryCreate {
            host_name: entry.host_name,
            addresses: entry.addresses.unwrap_or(existing.addresses),
            add_reverse_dns_lookup: entry
                .add_reverse_dns_lookup
                .unwrap_or(existing.add_reverse_dns_lookup),
        };

        self.submit_entry(&merged, Action::Update)
    }

    pub fn delete_entry(&self, host_name: impl AsRef<str>) -> Result<ResourceResponse> {
        let host_name = normalize_host_name(host_name.as_ref())?;
        if self.get_entry(&host_name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "DNS entry '{host_name}' does not exist"
            )));
        }

        let request = SophosRequest::new(Action::Delete, RESOURCE)
            .for_object(host_name)
            .with_object_key(HOST_KEY);
        first_resource(self.client.execute(&request)?.resources)
    }

    pub fn add_many(
        &self,
        entries: Vec<DnsHostEntryCreate>,
        force: bool,
        continue_on_error: bool,
    ) -> DnsBulkMutationResult {
        let mut result = DnsBulkMutationResult::new(entries.len());
        for entry in entries {
            let host_name = entry.host_name().to_string();
            match self.add_entry(entry, force) {
                Ok(outcome) => match outcome.action {
                    DnsMutationAction::Created => result.created += 1,
                    DnsMutationAction::Updated => result.updated += 1,
                },
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(format!("{host_name}: {error}"));
                    if !continue_on_error {
                        break;
                    }
                }
            }
        }
        result
    }

    pub fn update_many(
        &self,
        entries: Vec<DnsHostEntryUpdate>,
        continue_on_error: bool,
    ) -> DnsBulkMutationResult {
        let mut result = DnsBulkMutationResult::new(entries.len());
        for entry in entries {
            let host_name = entry.host_name().to_string();
            match self.update_entry(entry) {
                Ok(_) => result.updated += 1,
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(format!("{host_name}: {error}"));
                    if !continue_on_error {
                        break;
                    }
                }
            }
        }
        result
    }

    fn submit_entry(&self, entry: &DnsHostEntryCreate, action: Action) -> Result<ResourceResponse> {
        let request = SophosRequest::new(action, RESOURCE)
            .for_object(entry.host_name())
            .with_object_key(HOST_KEY)
            .with_payload(entry_payload(entry));
        first_resource(self.client.execute(&request)?.resources)
    }
}

fn normalize_host_name(value: &str) -> Result<String> {
    let normalized = value.trim().trim_end_matches('.');
    if normalized.is_empty() {
        return Err(Error::InvalidRequest(
            "hostname must not be empty".to_string(),
        ));
    }
    if normalized.len() > 253 {
        return Err(Error::InvalidRequest(
            "hostname must be 253 characters or less".to_string(),
        ));
    }

    for label in normalized.split('.') {
        validate_hostname_label(label)?;
    }

    Ok(normalized.to_string())
}

fn validate_hostname_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 63 {
        return Err(Error::InvalidRequest(format!(
            "invalid hostname label: {label}"
        )));
    }

    let bytes = label.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_alphanumeric();
    if !valid_edge(bytes[0]) || !valid_edge(bytes[bytes.len() - 1]) {
        return Err(Error::InvalidRequest(format!(
            "invalid hostname label: {label}"
        )));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(Error::InvalidRequest(format!(
            "invalid hostname label: {label}"
        )));
    }

    Ok(())
}

fn validate_addresses(addresses: &[DnsHostAddress]) -> Result<()> {
    if addresses.is_empty() {
        return Err(Error::InvalidRequest(
            "addresses must not be empty".to_string(),
        ));
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(Error::InvalidRequest(format!(
            "addresses must contain {MAX_ADDRESSES} items or fewer"
        )));
    }
    Ok(())
}

fn validate_ip_address(family: IpFamily, ip_address: &str) -> Result<()> {
    let parsed: IpAddr = ip_address
        .parse()
        .map_err(|_| Error::InvalidRequest(format!("Invalid IP address: {ip_address}")))?;

    match (family, parsed) {
        (IpFamily::IPv4, IpAddr::V4(address)) => validate_ipv4(address),
        (IpFamily::IPv6, IpAddr::V6(address)) => validate_ipv6(address),
        (IpFamily::IPv4, IpAddr::V6(_)) => Err(Error::InvalidRequest(
            "ip_family=IPv4 requires an IPv4 address".to_string(),
        )),
        (IpFamily::IPv6, IpAddr::V4(_)) => Err(Error::InvalidRequest(
            "ip_family=IPv6 requires an IPv6 address".to_string(),
        )),
    }
}

fn validate_ipv4(address: Ipv4Addr) -> Result<()> {
    if address.is_multicast() {
        return Err(Error::InvalidRequest(
            "Multicast addresses are not supported".to_string(),
        ));
    }
    if address.octets()[0] >= 240 {
        return Err(Error::InvalidRequest(
            "Reserved addresses are not supported".to_string(),
        ));
    }
    if address.is_unspecified() {
        return Err(Error::InvalidRequest(
            "Unspecified addresses are not supported".to_string(),
        ));
    }
    if address.is_link_local() {
        return Err(Error::InvalidRequest(
            "Link-local addresses are not supported".to_string(),
        ));
    }
    if address == Ipv4Addr::BROADCAST {
        return Err(Error::InvalidRequest(
            "Broadcast addresses are not supported".to_string(),
        ));
    }
    Ok(())
}

fn validate_ipv6(address: Ipv6Addr) -> Result<()> {
    if address.is_multicast() {
        return Err(Error::InvalidRequest(
            "Multicast addresses are not supported".to_string(),
        ));
    }
    if address.is_loopback() || address.segments() == [0x0100, 0, 0, 0, 0, 0, 0, 0] {
        return Err(Error::InvalidRequest(
            "Reserved addresses are not supported".to_string(),
        ));
    }
    if address.is_unspecified() {
        return Err(Error::InvalidRequest(
            "Unspecified addresses are not supported".to_string(),
        ));
    }
    if address.is_unicast_link_local() {
        return Err(Error::InvalidRequest(
            "Link-local addresses are not supported".to_string(),
        ));
    }
    Ok(())
}

fn entry_payload(entry: &DnsHostEntryCreate) -> serde_json::Value {
    json!({
        "HostName": entry.host_name,
        "AddressList": {
            "Address": entry.addresses.iter().map(address_payload).collect::<Vec<_>>()
        },
        "AddReverseDNSLookUp": if entry.add_reverse_dns_lookup { "Enable" } else { "Disable" },
    })
}

fn address_payload(address: &DnsHostAddress) -> serde_json::Value {
    json!({
        "EntryType": address.entry_type.as_str(),
        "IPFamily": address.ip_family.as_str(),
        "IPAddress": address.ip_address,
        "TTL": address.ttl,
        "Weight": address.weight,
        "PublishOnWAN": address.publish_on_wan.as_str(),
    })
}

fn entries_from_response(resources: &[ResourceResponse]) -> Result<Vec<DnsHostEntryCreate>> {
    let mut entries = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == RESOURCE)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes.iter().filter(|node| node.name == RESOURCE) {
            if let Some(entry) = entry_from_node(node) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

fn first_resource(resources: Vec<ResourceResponse>) -> Result<ResourceResponse> {
    resources
        .into_iter()
        .find(|resource| resource.name == RESOURCE)
        .ok_or_else(|| Error::ResponseParse(format!("missing {RESOURCE} response")))
}

fn entry_from_node(node: &XmlNode) -> Option<DnsHostEntryCreate> {
    let host_name = node.child_text("HostName")?;
    let addresses = addresses_from_node(node.child("AddressList")?);
    if addresses.is_empty() {
        return None;
    }
    let reverse = node
        .child_text("AddReverseDNSLookUp")
        .is_some_and(|value| value.eq_ignore_ascii_case("enable"));

    DnsHostEntryCreate::new(host_name, addresses)
        .ok()
        .map(|entry| entry.with_add_reverse_dns_lookup(reverse))
}

fn addresses_from_node(address_list: &XmlNode) -> Vec<DnsHostAddress> {
    address_list
        .children_named("Address")
        .filter_map(|address| {
            let entry_type = EntryType::from_sophos(address.child_text("EntryType"));
            let ip_family = IpFamily::from_sophos(address.child_text("IPFamily"));
            let ip_address = address.child_text("IPAddress")?;
            let ttl = parse_u32(address.child_text("TTL"), DEFAULT_TTL);
            let weight = parse_u8(address.child_text("Weight"), DEFAULT_WEIGHT);
            let publish_on_wan = PublishOnWan::from_sophos(address.child_text("PublishOnWAN"));
            DnsHostAddress::with_options(
                entry_type,
                ip_family,
                ip_address,
                ttl,
                weight,
                publish_on_wan,
            )
            .ok()
        })
        .collect()
}

fn parse_u32(value: Option<&str>, default: u32) -> u32 {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_u8(value: Option<&str>, default: u8) -> u8 {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn new(name: String) -> Self {
        Self {
            name,
            text: String::new(),
            children: Vec::new(),
        }
    }

    fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).and_then(|child| {
            let text = child.text.trim();
            if text.is_empty() { None } else { Some(text) }
        })
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }
}

fn parse_xml_nodes(xml: &str) -> Result<Vec<XmlNode>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut roots = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();

    loop {
        match reader
            .read_event()
            .map_err(|error| Error::ResponseParse(error.to_string()))?
        {
            Event::Start(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                stack.push(XmlNode::new(name));
            }
            Event::Empty(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                push_node(XmlNode::new(name), &mut stack, &mut roots);
            }
            Event::Text(text) => {
                if let Some(node) = stack.last_mut() {
                    let content = text
                        .xml_content()
                        .map_err(|error| Error::ResponseParse(error.to_string()))?;
                    node.text.push_str(&content);
                }
            }
            Event::CData(text) => {
                if let Some(node) = stack.last_mut() {
                    let content = text
                        .xml_content()
                        .map_err(|error| Error::ResponseParse(error.to_string()))?;
                    node.text.push_str(&content);
                }
            }
            Event::End(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                let node = stack.pop().ok_or_else(|| {
                    Error::ResponseParse(format!("unexpected closing XML tag {name:?}"))
                })?;
                if node.name != name {
                    return Err(Error::ResponseParse(format!(
                        "unexpected closing XML tag {name:?}"
                    )));
                }
                push_node(node, &mut stack, &mut roots);
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::Comment(_)
            | Event::GeneralRef(_) => {}
        }
    }

    if let Some(node) = stack.last() {
        return Err(Error::ResponseParse(format!(
            "unexpected end of XML inside {:?}",
            node.name
        )));
    }

    Ok(roots)
}

fn push_node(node: XmlNode, stack: &mut [XmlNode], roots: &mut Vec<XmlNode>) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        roots.push(node);
    }
}
