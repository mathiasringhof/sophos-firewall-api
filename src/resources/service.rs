use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

const SERVICES_RESOURCE: &str = "Services";
const SERVICE_GROUP_RESOURCE: &str = "ServiceGroup";
const URL_GROUP_RESOURCE: &str = "WebFilterURLGroup";
const NAME_KEY: &str = "Name";
const DEFAULT_SOURCE_PORT: &str = "1:65535";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    TcpOrUdp,
    Ip,
    Icmp,
    IcmpV6,
}

impl ServiceType {
    fn as_xml(self) -> &'static str {
        match self {
            Self::TcpOrUdp => "TCPorUDP",
            Self::Ip => "IP",
            Self::Icmp => "ICMP",
            Self::IcmpV6 => "ICMPv6",
        }
    }

    fn from_xml(value: &str) -> Option<Self> {
        match value {
            "TCPorUDP" => Some(Self::TcpOrUdp),
            "IP" => Some(Self::Ip),
            "ICMP" => Some(Self::Icmp),
            "ICMPv6" => Some(Self::IcmpV6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    protocol: Option<String>,
    src_port: Option<String>,
    dst_port: Option<String>,
    icmp_type: Option<String>,
    icmp_code: Option<String>,
}

impl ServiceEntry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tcp_udp(protocol: impl Into<String>, dst_port: impl Into<String>) -> Self {
        Self::new()
            .with_protocol(protocol)
            .with_source_port(DEFAULT_SOURCE_PORT)
            .with_destination_port(dst_port)
    }

    pub fn tcp_udp_with_source(
        protocol: impl Into<String>,
        src_port: impl Into<String>,
        dst_port: impl Into<String>,
    ) -> Self {
        Self::new()
            .with_protocol(protocol)
            .with_source_port(src_port)
            .with_destination_port(dst_port)
    }

    pub fn ip(protocol: impl Into<String>) -> Self {
        Self::new().with_protocol(protocol)
    }

    pub fn icmp(icmp_type: impl Into<String>, icmp_code: impl Into<String>) -> Self {
        Self::new()
            .with_icmp_type(icmp_type)
            .with_icmp_code(icmp_code)
    }

    pub fn icmp_v6(icmp_type: impl Into<String>, icmp_code: impl Into<String>) -> Self {
        Self::icmp(icmp_type, icmp_code)
    }

    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub fn with_source_port(mut self, src_port: impl Into<String>) -> Self {
        self.src_port = Some(src_port.into());
        self
    }

    pub fn with_destination_port(mut self, dst_port: impl Into<String>) -> Self {
        self.dst_port = Some(dst_port.into());
        self
    }

    pub fn with_icmp_type(mut self, icmp_type: impl Into<String>) -> Self {
        self.icmp_type = Some(icmp_type.into());
        self
    }

    pub fn with_icmp_code(mut self, icmp_code: impl Into<String>) -> Self {
        self.icmp_code = Some(icmp_code.into());
        self
    }

    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub fn src_port(&self) -> Option<&str> {
        self.src_port.as_deref()
    }

    pub fn dst_port(&self) -> Option<&str> {
        self.dst_port.as_deref()
    }

    pub fn icmp_type(&self) -> Option<&str> {
        self.icmp_type.as_deref()
    }

    pub fn icmp_code(&self) -> Option<&str> {
        self.icmp_code.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    name: String,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
}

impl Service {
    fn new_unchecked(name: String, service_type: ServiceType, entries: Vec<ServiceEntry>) -> Self {
        Self {
            name,
            service_type,
            entries,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn service_type(&self) -> ServiceType {
        self.service_type
    }

    pub fn entries(&self) -> &[ServiceEntry] {
        &self.entries
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCreate {
    name: String,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
}

impl ServiceCreate {
    pub fn new<S, I>(name: S, service_type: ServiceType, entries: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = ServiceEntry>,
    {
        Ok(Self {
            name: normalize_name("service name", name.as_ref())?,
            service_type,
            entries: normalize_service_entries(service_type, entries, true)?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn service_type(&self) -> ServiceType {
        self.service_type
    }

    pub fn entries(&self) -> &[ServiceEntry] {
        &self.entries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceUpdateAction {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUpdate {
    name: String,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
    action: ServiceUpdateAction,
}

impl ServiceUpdate {
    pub fn new<S, I>(
        name: S,
        service_type: ServiceType,
        entries: I,
        action: ServiceUpdateAction,
    ) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = ServiceEntry>,
    {
        Ok(Self {
            name: normalize_name("service name", name.as_ref())?,
            service_type,
            entries: normalize_service_entries(service_type, entries, true)?,
            action,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServicesApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn services(&self) -> ServicesApi<'_, T> {
        ServicesApi { client: self }
    }

    pub fn service_groups(&self) -> ServiceGroupsApi<'_, T> {
        ServiceGroupsApi { client: self }
    }

    pub fn url_groups(&self) -> UrlGroupsApi<'_, T> {
        UrlGroupsApi { client: self }
    }
}

impl<T> ServicesApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_services(&self) -> Result<Vec<Service>> {
        match self.client.execute(&SophosRequest::read(SERVICES_RESOURCE)) {
            Ok(response) => services_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == SERVICES_RESOURCE => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    pub fn get_service(&self, name: impl AsRef<str>) -> Result<Option<Service>> {
        let name = normalize_name("service name", name.as_ref())?;
        let request = SophosRequest::read(SERVICES_RESOURCE)
            .for_object(name.clone())
            .with_object_key(NAME_KEY);

        match self.client.execute(&request) {
            Ok(response) => Ok(services_from_response(&response.resources)?
                .into_iter()
                .find(|service| service.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == SERVICES_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_service(&self, service: ServiceCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, SERVICES_RESOURCE)
            .for_object(service.name())
            .with_object_key(NAME_KEY)
            .with_payload(service_payload(
                service.name(),
                service.service_type(),
                service.entries(),
            ));
        first_named_resource(self.client.execute(&request)?.resources, SERVICES_RESOURCE)
    }

    pub fn update_service(&self, update: ServiceUpdate) -> Result<ResourceResponse> {
        self.update_entries(
            update.name,
            update.service_type,
            update.entries,
            update.action,
        )
    }

    pub fn add_entries<I>(
        &self,
        name: impl AsRef<str>,
        service_type: ServiceType,
        entries: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = ServiceEntry>,
    {
        let update = ServiceUpdate::new(name, service_type, entries, ServiceUpdateAction::Add)?;
        self.update_service(update)
    }

    pub fn remove_entries<I>(
        &self,
        name: impl AsRef<str>,
        service_type: ServiceType,
        entries: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = ServiceEntry>,
    {
        let update = ServiceUpdate::new(name, service_type, entries, ServiceUpdateAction::Remove)?;
        self.update_service(update)
    }

    pub fn replace_entries<I>(
        &self,
        name: impl AsRef<str>,
        service_type: ServiceType,
        entries: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = ServiceEntry>,
    {
        let update = ServiceUpdate::new(name, service_type, entries, ServiceUpdateAction::Replace)?;
        self.update_service(update)
    }

    pub fn delete_service(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("service name", name.as_ref())?;
        if self.get_service(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "service '{name}' does not exist"
            )));
        }

        let request = SophosRequest::new(Action::Delete, SERVICES_RESOURCE)
            .for_object(name)
            .with_object_key(NAME_KEY);
        first_named_resource(self.client.execute(&request)?.resources, SERVICES_RESOURCE)
    }

    fn update_entries(
        &self,
        name: String,
        service_type: ServiceType,
        requested: Vec<ServiceEntry>,
        action: ServiceUpdateAction,
    ) -> Result<ResourceResponse> {
        let existing = self
            .get_service(&name)?
            .ok_or_else(|| Error::InvalidRequest(format!("service '{name}' does not exist")))?;

        if existing.service_type != service_type {
            return Err(Error::InvalidRequest(format!(
                "service '{name}' has type {}, not {}",
                existing.service_type.as_xml(),
                service_type.as_xml()
            )));
        }

        let updated_entries = match action {
            ServiceUpdateAction::Add => add_unique(existing.entries, requested),
            ServiceUpdateAction::Remove => remove_requested(existing.entries, &requested),
            ServiceUpdateAction::Replace => requested,
        };

        let request = SophosRequest::new(Action::Update, SERVICES_RESOURCE)
            .for_object(&name)
            .with_object_key(NAME_KEY)
            .with_payload(service_payload(&name, service_type, &updated_entries));
        first_named_resource(self.client.execute(&request)?.resources, SERVICES_RESOURCE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroup {
    name: String,
    services: Vec<String>,
    description: Option<String>,
}

impl ServiceGroup {
    fn new_unchecked(name: String, services: Vec<String>, description: Option<String>) -> Self {
        Self {
            name,
            services,
            description,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn services(&self) -> &[String] {
        &self.services
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroupCreate {
    name: String,
    services: Vec<String>,
    description: Option<String>,
}

impl ServiceGroupCreate {
    pub fn new<S, I, M>(name: S, services: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = M>,
        M: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("service group name", name.as_ref())?,
            services: normalize_named_list("service", services, true)?,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn services(&self) -> &[String] {
        &self.services
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceGroupUpdateAction {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroupUpdate {
    name: String,
    services: Vec<String>,
    action: ServiceGroupUpdateAction,
    description: Option<String>,
}

impl ServiceGroupUpdate {
    pub fn new<S, I, M>(name: S, services: I, action: ServiceGroupUpdateAction) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = M>,
        M: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("service group name", name.as_ref())?,
            services: normalize_named_list("service", services, true)?,
            action,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceGroupsApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> ServiceGroupsApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_groups(&self) -> Result<Vec<ServiceGroup>> {
        match self
            .client
            .execute(&SophosRequest::read(SERVICE_GROUP_RESOURCE))
        {
            Ok(response) => service_groups_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == SERVICE_GROUP_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_group(&self, name: impl AsRef<str>) -> Result<Option<ServiceGroup>> {
        let name = normalize_name("service group name", name.as_ref())?;
        let request = SophosRequest::read(SERVICE_GROUP_RESOURCE)
            .for_object(name.clone())
            .with_object_key(NAME_KEY);

        match self.client.execute(&request) {
            Ok(response) => Ok(service_groups_from_response(&response.resources)?
                .into_iter()
                .find(|group| group.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == SERVICE_GROUP_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_group(&self, group: ServiceGroupCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, SERVICE_GROUP_RESOURCE)
            .for_object(group.name())
            .with_object_key(NAME_KEY)
            .with_set_operation("set")
            .with_payload(service_group_payload(
                group.name(),
                group.services(),
                group.description(),
            ));
        first_named_resource(
            self.client.execute(&request)?.resources,
            SERVICE_GROUP_RESOURCE,
        )
    }

    pub fn update_group(&self, update: ServiceGroupUpdate) -> Result<ResourceResponse> {
        self.update_services(
            update.name,
            update.services,
            update.action,
            update.description,
        )
    }

    pub fn add_services<I, M>(&self, name: impl AsRef<str>, services: I) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = M>,
        M: AsRef<str>,
    {
        let update = ServiceGroupUpdate::new(name, services, ServiceGroupUpdateAction::Add)?;
        self.update_group(update)
    }

    pub fn remove_services<I, M>(
        &self,
        name: impl AsRef<str>,
        services: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = M>,
        M: AsRef<str>,
    {
        let update = ServiceGroupUpdate::new(name, services, ServiceGroupUpdateAction::Remove)?;
        self.update_group(update)
    }

    pub fn replace_services<I, M>(
        &self,
        name: impl AsRef<str>,
        services: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = M>,
        M: AsRef<str>,
    {
        let update = ServiceGroupUpdate::new(name, services, ServiceGroupUpdateAction::Replace)?;
        self.update_group(update)
    }

    pub fn delete_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("service group name", name.as_ref())?;
        if self.get_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "service group '{name}' does not exist"
            )));
        }

        let request = SophosRequest::new(Action::Delete, SERVICE_GROUP_RESOURCE)
            .for_object(name)
            .with_object_key(NAME_KEY);
        first_named_resource(
            self.client.execute(&request)?.resources,
            SERVICE_GROUP_RESOURCE,
        )
    }

    fn update_services(
        &self,
        name: String,
        requested: Vec<String>,
        action: ServiceGroupUpdateAction,
        description: Option<String>,
    ) -> Result<ResourceResponse> {
        let existing = self.get_group(&name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("service group '{name}' does not exist"))
        })?;

        let updated_services = match action {
            ServiceGroupUpdateAction::Add => add_unique(existing.services.clone(), requested),
            ServiceGroupUpdateAction::Remove => {
                remove_requested(existing.services.clone(), &requested)
            }
            ServiceGroupUpdateAction::Replace => requested,
        };
        let description = description.as_deref().or(existing.description.as_deref());

        let request = SophosRequest::new(Action::Update, SERVICE_GROUP_RESOURCE)
            .for_object(&name)
            .with_object_key(NAME_KEY)
            .with_payload(service_group_payload(&name, &updated_services, description));
        first_named_resource(
            self.client.execute(&request)?.resources,
            SERVICE_GROUP_RESOURCE,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlGroup {
    name: String,
    domains: Vec<String>,
}

impl UrlGroup {
    fn new_unchecked(name: String, domains: Vec<String>) -> Self {
        Self { name, domains }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlGroupCreate {
    name: String,
    domains: Vec<String>,
}

impl UrlGroupCreate {
    pub fn new<S, I, D>(name: S, domains: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("URL group name", name.as_ref())?,
            domains: normalize_named_list("domain", domains, true)?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

impl From<UrlGroupCreate> for UrlGroup {
    fn from(group: UrlGroupCreate) -> Self {
        Self {
            name: group.name,
            domains: group.domains,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UrlGroupsApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> UrlGroupsApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_groups(&self) -> Result<Vec<UrlGroup>> {
        match self
            .client
            .execute(&SophosRequest::read(URL_GROUP_RESOURCE))
        {
            Ok(response) => url_groups_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == URL_GROUP_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_group(&self, name: impl AsRef<str>) -> Result<Option<UrlGroup>> {
        let name = normalize_name("URL group name", name.as_ref())?;
        let request = SophosRequest::read(URL_GROUP_RESOURCE)
            .for_object(name.clone())
            .with_object_key(NAME_KEY);

        match self.client.execute(&request) {
            Ok(response) => Ok(url_groups_from_response(&response.resources)?
                .into_iter()
                .find(|group| group.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == URL_GROUP_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_group(&self, group: UrlGroupCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, URL_GROUP_RESOURCE)
            .for_object(group.name())
            .with_object_key(NAME_KEY)
            .with_set_operation("set")
            .with_payload(url_group_payload(group.name(), group.domains()));
        first_named_resource(self.client.execute(&request)?.resources, URL_GROUP_RESOURCE)
    }

    pub fn add_domains<I, D>(&self, name: impl AsRef<str>, domains: I) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Add)
    }

    pub fn remove_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Remove)
    }

    pub fn replace_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Replace)
    }

    pub fn delete_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("URL group name", name.as_ref())?;
        if self.get_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "URL group '{name}' does not exist"
            )));
        }

        let request = SophosRequest::new(Action::Delete, URL_GROUP_RESOURCE)
            .for_object(name)
            .with_object_key(NAME_KEY);
        first_named_resource(self.client.execute(&request)?.resources, URL_GROUP_RESOURCE)
    }

    fn update_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
        action: DomainUpdateAction,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        let name = normalize_name("URL group name", name.as_ref())?;
        let requested = normalize_named_list("domain", domains, true)?;
        let existing = self
            .get_group(&name)?
            .ok_or_else(|| Error::InvalidRequest(format!("URL group '{name}' does not exist")))?;

        let updated_domains = match action {
            DomainUpdateAction::Add => add_unique(existing.domains, requested),
            DomainUpdateAction::Remove => remove_requested(existing.domains, &requested),
            DomainUpdateAction::Replace => requested,
        };

        let request = SophosRequest::new(Action::Update, URL_GROUP_RESOURCE)
            .for_object(&name)
            .with_object_key(NAME_KEY)
            .with_payload(url_group_payload(&name, &updated_domains));
        first_named_resource(self.client.execute(&request)?.resources, URL_GROUP_RESOURCE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainUpdateAction {
    Add,
    Remove,
    Replace,
}

fn normalize_name(label: &str, value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(Error::InvalidRequest(format!("{label} must not be empty")));
    }
    Ok(normalized.to_string())
}

fn normalize_named_list<I, V>(
    label: &str,
    values: I,
    require_non_empty: bool,
) -> Result<Vec<String>>
where
    I: IntoIterator<Item = V>,
    V: AsRef<str>,
{
    let mut normalized = Vec::new();
    for value in values {
        let value = value.as_ref().trim();
        if value.is_empty() {
            return Err(Error::InvalidRequest(format!("{label} must not be empty")));
        }
        if !normalized.iter().any(|existing| existing == value) {
            normalized.push(value.to_string());
        }
    }

    if require_non_empty && normalized.is_empty() {
        return Err(Error::InvalidRequest(format!("{label}s must not be empty")));
    }

    Ok(normalized)
}

fn normalize_service_entries<I>(
    service_type: ServiceType,
    entries: I,
    require_non_empty: bool,
) -> Result<Vec<ServiceEntry>>
where
    I: IntoIterator<Item = ServiceEntry>,
{
    let mut normalized = Vec::new();
    for entry in entries {
        let entry = normalize_service_entry(service_type, entry)?;
        if !normalized.contains(&entry) {
            normalized.push(entry);
        }
    }

    if require_non_empty && normalized.is_empty() {
        return Err(Error::InvalidRequest(
            "service entries must not be empty".to_string(),
        ));
    }

    Ok(normalized)
}

fn normalize_service_entry(service_type: ServiceType, entry: ServiceEntry) -> Result<ServiceEntry> {
    match service_type {
        ServiceType::TcpOrUdp => {
            let protocol = required_entry_field(
                "TCPorUDP entries require protocol and dst_port",
                entry.protocol.as_deref(),
            )?;
            let dst_port = required_entry_field(
                "TCPorUDP entries require protocol and dst_port",
                entry.dst_port.as_deref(),
            )?;
            let src_port = entry
                .src_port
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(DEFAULT_SOURCE_PORT)
                .to_string();
            Ok(ServiceEntry {
                protocol: Some(protocol),
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                icmp_type: None,
                icmp_code: None,
            })
        }
        ServiceType::Ip => {
            let protocol =
                required_entry_field("IP entries require protocol", entry.protocol.as_deref())?;
            Ok(ServiceEntry {
                protocol: Some(protocol),
                src_port: None,
                dst_port: None,
                icmp_type: None,
                icmp_code: None,
            })
        }
        ServiceType::Icmp | ServiceType::IcmpV6 => {
            let label = format!(
                "{} entries require icmp_type and icmp_code",
                service_type.as_xml()
            );
            let icmp_type = required_entry_field(&label, entry.icmp_type.as_deref())?;
            let icmp_code = required_entry_field(&label, entry.icmp_code.as_deref())?;
            Ok(ServiceEntry {
                protocol: None,
                src_port: None,
                dst_port: None,
                icmp_type: Some(icmp_type),
                icmp_code: Some(icmp_code),
            })
        }
    }
}

fn required_entry_field(error: &str, value: Option<&str>) -> Result<String> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    value
        .map(ToString::to_string)
        .ok_or_else(|| Error::InvalidRequest(error.to_string()))
}

fn add_unique<T: PartialEq>(mut existing: Vec<T>, requested: Vec<T>) -> Vec<T> {
    for value in requested {
        if !existing.contains(&value) {
            existing.push(value);
        }
    }
    existing
}

fn remove_requested<T: PartialEq>(existing: Vec<T>, requested: &[T]) -> Vec<T> {
    existing
        .into_iter()
        .filter(|value| !requested.contains(value))
        .collect()
}

fn service_payload(
    name: &str,
    service_type: ServiceType,
    entries: &[ServiceEntry],
) -> serde_json::Value {
    let service_details = entries
        .iter()
        .map(|entry| service_entry_payload(service_type, entry))
        .collect::<Vec<_>>();

    json!({
        "Name": name,
        "Type": service_type.as_xml(),
        "ServiceDetails": {
            "ServiceDetail": service_details,
        },
    })
}

fn service_entry_payload(service_type: ServiceType, entry: &ServiceEntry) -> serde_json::Value {
    match service_type {
        ServiceType::TcpOrUdp => json!({
            "SourcePort": entry.src_port.as_deref().unwrap_or(DEFAULT_SOURCE_PORT),
            "DestinationPort": entry.dst_port.as_deref().unwrap_or_default(),
            "Protocol": entry.protocol.as_deref().unwrap_or_default(),
        }),
        ServiceType::Ip => json!({
            "ProtocolName": entry.protocol.as_deref().unwrap_or_default(),
        }),
        ServiceType::Icmp => json!({
            "ICMPType": entry.icmp_type.as_deref().unwrap_or_default(),
            "ICMPCode": entry.icmp_code.as_deref().unwrap_or_default(),
        }),
        ServiceType::IcmpV6 => json!({
            "ICMPv6Type": entry.icmp_type.as_deref().unwrap_or_default(),
            "ICMPv6Code": entry.icmp_code.as_deref().unwrap_or_default(),
        }),
    }
}

fn service_group_payload(
    name: &str,
    services: &[String],
    description: Option<&str>,
) -> serde_json::Value {
    json!({
        "Name": name,
        "Description": description.unwrap_or_default(),
        "ServiceList": {
            "Service": services,
        },
    })
}

fn url_group_payload(name: &str, domains: &[String]) -> serde_json::Value {
    json!({
        "Name": name,
        "URLlist": {
            "URL": domains,
        },
    })
}

fn services_from_response(resources: &[ResourceResponse]) -> Result<Vec<Service>> {
    let mut services = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == SERVICES_RESOURCE)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes.iter().filter(|node| node.name == SERVICES_RESOURCE) {
            if let Some(service) = service_from_node(node)? {
                services.push(service);
            }
        }
    }
    Ok(services)
}

fn service_from_node(node: &XmlNode) -> Result<Option<Service>> {
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let Some(service_type) = node.child_text("Type").and_then(ServiceType::from_xml) else {
        return Ok(None);
    };
    let entries = node
        .child("ServiceDetails")
        .map(|details| service_entries_from_node(service_type, details))
        .transpose()?
        .unwrap_or_default();
    Ok(Some(Service::new_unchecked(
        normalize_name("service name", name)?,
        service_type,
        entries,
    )))
}

fn service_entries_from_node(
    service_type: ServiceType,
    details: &XmlNode,
) -> Result<Vec<ServiceEntry>> {
    let entries = details
        .children_named("ServiceDetail")
        .map(|detail| service_entry_from_node(service_type, detail))
        .collect::<Vec<_>>();
    normalize_service_entries(service_type, entries, false)
}

fn service_entry_from_node(service_type: ServiceType, node: &XmlNode) -> ServiceEntry {
    match service_type {
        ServiceType::TcpOrUdp => ServiceEntry::new()
            .with_protocol(node.child_text("Protocol").unwrap_or_default())
            .with_source_port(node.child_text("SourcePort").unwrap_or(DEFAULT_SOURCE_PORT))
            .with_destination_port(node.child_text("DestinationPort").unwrap_or_default()),
        ServiceType::Ip => ServiceEntry::ip(node.child_text("ProtocolName").unwrap_or_default()),
        ServiceType::Icmp => ServiceEntry::icmp(
            node.child_text("ICMPType").unwrap_or_default(),
            node.child_text("ICMPCode").unwrap_or_default(),
        ),
        ServiceType::IcmpV6 => ServiceEntry::icmp_v6(
            node.child_text("ICMPv6Type").unwrap_or_default(),
            node.child_text("ICMPv6Code").unwrap_or_default(),
        ),
    }
}

fn service_groups_from_response(resources: &[ResourceResponse]) -> Result<Vec<ServiceGroup>> {
    let mut groups = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == SERVICE_GROUP_RESOURCE)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes
            .iter()
            .filter(|node| node.name == SERVICE_GROUP_RESOURCE)
        {
            if let Some(group) = service_group_from_node(node)? {
                groups.push(group);
            }
        }
    }
    Ok(groups)
}

fn service_group_from_node(node: &XmlNode) -> Result<Option<ServiceGroup>> {
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let services = node
        .child("ServiceList")
        .map(|service_list| values_from_children(service_list, "Service"))
        .unwrap_or_default();
    let description = node.child_text("Description").map(ToString::to_string);
    Ok(Some(ServiceGroup::new_unchecked(
        normalize_name("service group name", name)?,
        services,
        description,
    )))
}

fn url_groups_from_response(resources: &[ResourceResponse]) -> Result<Vec<UrlGroup>> {
    let mut groups = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == URL_GROUP_RESOURCE)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes.iter().filter(|node| node.name == URL_GROUP_RESOURCE) {
            if let Some(group) = url_group_from_node(node) {
                groups.push(group);
            }
        }
    }
    Ok(groups)
}

fn url_group_from_node(node: &XmlNode) -> Option<UrlGroup> {
    let name = normalize_name("URL group name", node.child_text(NAME_KEY)?).ok()?;
    let domains = node
        .child("URLlist")
        .map(|url_list| values_from_children(url_list, "URL"))
        .unwrap_or_default();
    Some(UrlGroup::new_unchecked(name, domains))
}

fn values_from_children(node: &XmlNode, child_name: &str) -> Vec<String> {
    let mut values = Vec::new();
    for child in node.children_named(child_name) {
        let value = child.text.trim();
        if !value.is_empty() && !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
    values
}

fn first_named_resource(
    resources: Vec<ResourceResponse>,
    resource_name: &str,
) -> Result<ResourceResponse> {
    resources
        .into_iter()
        .find(|resource| resource.name == resource_name)
        .ok_or_else(|| Error::ResponseParse(format!("missing {resource_name} response")))
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
