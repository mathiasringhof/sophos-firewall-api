use std::net::Ipv4Addr;

use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

const IP_HOST_RESOURCE: &str = "IPHost";
const IP_HOST_GROUP_RESOURCE: &str = "IPHostGroup";
const FQDN_HOST_RESOURCE: &str = "FQDNHost";
const FQDN_HOST_GROUP_RESOURCE: &str = "FQDNHostGroup";
const NAME_KEY: &str = "Name";
const IPV4: &str = "IPv4";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHost {
    name: String,
    ip_address: String,
}

impl IpHost {
    fn new_unchecked(name: String, ip_address: String) -> Self {
        Self { name, ip_address }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHostCreate {
    name: String,
    ip_address: String,
}

impl IpHostCreate {
    pub fn new(name: impl AsRef<str>, ip_address: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: normalize_name("IP host name", name.as_ref())?,
            ip_address: normalize_ipv4("ip_address", ip_address.as_ref())?.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpNetwork {
    name: String,
    ip_address: String,
    subnet: String,
}

impl IpNetwork {
    fn new_unchecked(name: String, ip_address: String, subnet: String) -> Self {
        Self {
            name,
            ip_address,
            subnet,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    pub fn subnet(&self) -> &str {
        &self.subnet
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpNetworkCreate {
    name: String,
    ip_address: String,
    subnet: String,
}

impl IpNetworkCreate {
    pub fn new(
        name: impl AsRef<str>,
        ip_address: impl AsRef<str>,
        subnet: impl AsRef<str>,
    ) -> Result<Self> {
        Ok(Self {
            name: normalize_name("IP network name", name.as_ref())?,
            ip_address: normalize_ipv4("ip_address", ip_address.as_ref())?.to_string(),
            subnet: normalize_ipv4("subnet", subnet.as_ref())?.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    pub fn subnet(&self) -> &str {
        &self.subnet
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRange {
    name: String,
    start_ip: String,
    end_ip: String,
}

impl IpRange {
    fn new_unchecked(name: String, start_ip: String, end_ip: String) -> Self {
        Self {
            name,
            start_ip,
            end_ip,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn start_ip(&self) -> &str {
        &self.start_ip
    }

    pub fn end_ip(&self) -> &str {
        &self.end_ip
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRangeCreate {
    name: String,
    start_ip: String,
    end_ip: String,
}

impl IpRangeCreate {
    pub fn new(
        name: impl AsRef<str>,
        start_ip: impl AsRef<str>,
        end_ip: impl AsRef<str>,
    ) -> Result<Self> {
        let start = normalize_ipv4("start_ip", start_ip.as_ref())?;
        let end = normalize_ipv4("end_ip", end_ip.as_ref())?;
        if u32::from(start) > u32::from(end) {
            return Err(Error::InvalidRequest(
                "start_ip must be less than or equal to end_ip".to_string(),
            ));
        }
        Ok(Self {
            name: normalize_name("IP range name", name.as_ref())?,
            start_ip: start.to_string(),
            end_ip: end.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn start_ip(&self) -> &str {
        &self.start_ip
    }

    pub fn end_ip(&self) -> &str {
        &self.end_ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkGroupUpdateAction {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHostGroup {
    name: String,
    hosts: Vec<String>,
    description: Option<String>,
}

impl IpHostGroup {
    fn new_unchecked(name: String, hosts: Vec<String>, description: Option<String>) -> Self {
        Self {
            name,
            hosts,
            description,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHostGroupCreate {
    name: String,
    hosts: Vec<String>,
    description: Option<String>,
}

impl IpHostGroupCreate {
    pub fn new<S, I, H>(name: S, hosts: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("IP host group name", name.as_ref())?,
            hosts: normalize_named_list("host", hosts, true)?,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHostGroupUpdate {
    name: String,
    hosts: Vec<String>,
    action: NetworkGroupUpdateAction,
    description: Option<String>,
}

impl IpHostGroupUpdate {
    pub fn new<S, I, H>(name: S, hosts: I, action: NetworkGroupUpdateAction) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("IP host group name", name.as_ref())?,
            hosts: normalize_named_list("host", hosts, true)?,
            action,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHost {
    name: String,
    fqdn: String,
    groups: Vec<String>,
    description: Option<String>,
}

impl FqdnHost {
    fn new_unchecked(
        name: String,
        fqdn: String,
        groups: Vec<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            name,
            fqdn,
            groups,
            description,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHostCreate {
    name: String,
    fqdn: String,
    groups: Vec<String>,
    description: Option<String>,
}

impl FqdnHostCreate {
    pub fn new(name: impl AsRef<str>, fqdn: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: normalize_name("FQDN host name", name.as_ref())?,
            fqdn: normalize_name("FQDN", fqdn.as_ref())?,
            groups: Vec::new(),
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }

    pub fn with_groups<I, G>(mut self, groups: I) -> Result<Self>
    where
        I: IntoIterator<Item = G>,
        G: AsRef<str>,
    {
        self.groups = normalize_named_list("FQDN host group", groups, false)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHostUpdate {
    name: String,
    fqdn: Option<String>,
    groups: Option<Vec<String>>,
    description: Option<String>,
}

impl FqdnHostUpdate {
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: normalize_name("FQDN host name", name.as_ref())?,
            fqdn: None,
            groups: None,
            description: None,
        })
    }

    pub fn with_fqdn(mut self, fqdn: impl AsRef<str>) -> Result<Self> {
        self.fqdn = Some(normalize_name("FQDN", fqdn.as_ref())?);
        Ok(self)
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }

    pub fn with_groups<I, G>(mut self, groups: I) -> Result<Self>
    where
        I: IntoIterator<Item = G>,
        G: AsRef<str>,
    {
        self.groups = Some(normalize_named_list("FQDN host group", groups, false)?);
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHostGroup {
    name: String,
    hosts: Vec<String>,
    description: Option<String>,
}

impl FqdnHostGroup {
    fn new_unchecked(name: String, hosts: Vec<String>, description: Option<String>) -> Self {
        Self {
            name,
            hosts,
            description,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHostGroupCreate {
    name: String,
    hosts: Vec<String>,
    description: Option<String>,
}

impl FqdnHostGroupCreate {
    pub fn new<S, I, H>(name: S, hosts: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("FQDN host group name", name.as_ref())?,
            hosts: normalize_named_list("FQDN host", hosts, true)?,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FqdnHostGroupUpdate {
    name: String,
    hosts: Vec<String>,
    action: NetworkGroupUpdateAction,
    description: Option<String>,
}

impl FqdnHostGroupUpdate {
    pub fn new<S, I, H>(name: S, hosts: I, action: NetworkGroupUpdateAction) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Ok(Self {
            name: normalize_name("FQDN host group name", name.as_ref())?,
            hosts: normalize_named_list("FQDN host", hosts, true)?,
            action,
            description: None,
        })
    }

    pub fn with_description(mut self, description: impl AsRef<str>) -> Self {
        self.description = Some(description.as_ref().trim().to_string());
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn network(&self) -> NetworkApi<'_, T> {
        NetworkApi { client: self }
    }
}

impl<T> NetworkApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_ip_hosts(&self) -> Result<Vec<IpHost>> {
        self.ip_hosts_by_variant(IpHostVariant::Host)
            .map(|records| {
                records
                    .into_iter()
                    .filter_map(ParsedIpHost::into_host)
                    .collect()
            })
    }

    pub fn get_ip_host(&self, name: impl AsRef<str>) -> Result<Option<IpHost>> {
        let name = normalize_name("IP host name", name.as_ref())?;
        Ok(self
            .get_ip_host_record(&name)?
            .and_then(ParsedIpHost::into_host))
    }

    pub fn create_ip_host(&self, host: IpHostCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Create, ip_host_payload(&host))
    }

    pub fn update_ip_host(&self, host: IpHostCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Update, ip_host_payload(&host))
    }

    pub fn delete_ip_host(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("IP host name", name.as_ref())?;
        if self.get_ip_host(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "IP host '{name}' does not exist"
            )));
        }
        self.delete_named(IP_HOST_RESOURCE, name)
    }

    pub fn list_ip_networks(&self) -> Result<Vec<IpNetwork>> {
        self.ip_hosts_by_variant(IpHostVariant::Network)
            .map(|records| {
                records
                    .into_iter()
                    .filter_map(ParsedIpHost::into_network)
                    .collect()
            })
    }

    pub fn get_ip_network(&self, name: impl AsRef<str>) -> Result<Option<IpNetwork>> {
        let name = normalize_name("IP network name", name.as_ref())?;
        Ok(self
            .get_ip_host_record(&name)?
            .and_then(ParsedIpHost::into_network))
    }

    pub fn create_ip_network(&self, network: IpNetworkCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Create, ip_network_payload(&network))
    }

    pub fn update_ip_network(&self, network: IpNetworkCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Update, ip_network_payload(&network))
    }

    pub fn delete_ip_network(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("IP network name", name.as_ref())?;
        if self.get_ip_network(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "IP network '{name}' does not exist"
            )));
        }
        self.delete_named(IP_HOST_RESOURCE, name)
    }

    pub fn list_ip_ranges(&self) -> Result<Vec<IpRange>> {
        self.ip_hosts_by_variant(IpHostVariant::Range)
            .map(|records| {
                records
                    .into_iter()
                    .filter_map(ParsedIpHost::into_range)
                    .collect()
            })
    }

    pub fn get_ip_range(&self, name: impl AsRef<str>) -> Result<Option<IpRange>> {
        let name = normalize_name("IP range name", name.as_ref())?;
        Ok(self
            .get_ip_host_record(&name)?
            .and_then(ParsedIpHost::into_range))
    }

    pub fn create_ip_range(&self, range: IpRangeCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Create, ip_range_payload(&range))
    }

    pub fn update_ip_range(&self, range: IpRangeCreate) -> Result<ResourceResponse> {
        self.write_ip_host(Action::Update, ip_range_payload(&range))
    }

    pub fn delete_ip_range(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("IP range name", name.as_ref())?;
        if self.get_ip_range(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "IP range '{name}' does not exist"
            )));
        }
        self.delete_named(IP_HOST_RESOURCE, name)
    }

    pub fn list_ip_host_groups(&self) -> Result<Vec<IpHostGroup>> {
        match self
            .client
            .execute(&SophosRequest::read(IP_HOST_GROUP_RESOURCE))
        {
            Ok(response) => ip_host_groups_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == IP_HOST_GROUP_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_ip_host_group(&self, name: impl AsRef<str>) -> Result<Option<IpHostGroup>> {
        let name = normalize_name("IP host group name", name.as_ref())?;
        let request = read_named(IP_HOST_GROUP_RESOURCE, &name);
        match self.client.execute(&request) {
            Ok(response) => Ok(ip_host_groups_from_response(&response.resources)?
                .into_iter()
                .find(|group| group.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == IP_HOST_GROUP_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_ip_host_group(&self, group: IpHostGroupCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, IP_HOST_GROUP_RESOURCE)
            .for_object(&group.name)
            .with_object_key(NAME_KEY)
            .with_payload(ip_host_group_payload(
                &group.name,
                &group.hosts,
                group.description.as_deref(),
            ));
        first_named_resource(
            self.client.execute(&request)?.resources,
            IP_HOST_GROUP_RESOURCE,
        )
    }

    pub fn update_ip_host_group(&self, update: IpHostGroupUpdate) -> Result<ResourceResponse> {
        let existing = self.get_ip_host_group(&update.name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("IP host group '{}' does not exist", update.name))
        })?;
        let hosts = apply_group_update(existing.hosts, update.hosts, update.action);
        let description = update
            .description
            .as_deref()
            .or(existing.description.as_deref());
        let request = SophosRequest::new(Action::Update, IP_HOST_GROUP_RESOURCE)
            .for_object(&update.name)
            .with_object_key(NAME_KEY)
            .with_payload(ip_host_group_payload(&update.name, &hosts, description));
        first_named_resource(
            self.client.execute(&request)?.resources,
            IP_HOST_GROUP_RESOURCE,
        )
    }

    pub fn delete_ip_host_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("IP host group name", name.as_ref())?;
        if self.get_ip_host_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "IP host group '{name}' does not exist"
            )));
        }
        self.delete_named(IP_HOST_GROUP_RESOURCE, name)
    }

    pub fn list_fqdn_hosts(&self) -> Result<Vec<FqdnHost>> {
        match self
            .client
            .execute(&SophosRequest::read(FQDN_HOST_RESOURCE))
        {
            Ok(response) => fqdn_hosts_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == FQDN_HOST_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_fqdn_host(&self, name: impl AsRef<str>) -> Result<Option<FqdnHost>> {
        let name = normalize_name("FQDN host name", name.as_ref())?;
        let request = read_named(FQDN_HOST_RESOURCE, &name);
        match self.client.execute(&request) {
            Ok(response) => Ok(fqdn_hosts_from_response(&response.resources)?
                .into_iter()
                .find(|host| host.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == FQDN_HOST_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_fqdn_host(&self, host: FqdnHostCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, FQDN_HOST_RESOURCE)
            .for_object(&host.name)
            .with_object_key(NAME_KEY)
            .with_payload(fqdn_host_payload(
                &host.name,
                &host.fqdn,
                &host.groups,
                host.description.as_deref(),
            ));
        first_named_resource(self.client.execute(&request)?.resources, FQDN_HOST_RESOURCE)
    }

    pub fn update_fqdn_host(&self, update: FqdnHostUpdate) -> Result<ResourceResponse> {
        let existing = self.get_fqdn_host(&update.name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("FQDN host '{}' does not exist", update.name))
        })?;
        let fqdn = update.fqdn.as_deref().unwrap_or(&existing.fqdn);
        let groups = update.groups.unwrap_or(existing.groups);
        let description = update
            .description
            .as_deref()
            .or(existing.description.as_deref());
        let request = SophosRequest::new(Action::Update, FQDN_HOST_RESOURCE)
            .for_object(&update.name)
            .with_object_key(NAME_KEY)
            .with_payload(fqdn_host_payload(&update.name, fqdn, &groups, description));
        first_named_resource(self.client.execute(&request)?.resources, FQDN_HOST_RESOURCE)
    }

    pub fn delete_fqdn_host(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("FQDN host name", name.as_ref())?;
        if self.get_fqdn_host(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "FQDN host '{name}' does not exist"
            )));
        }
        self.delete_named(FQDN_HOST_RESOURCE, name)
    }

    pub fn list_fqdn_host_groups(&self) -> Result<Vec<FqdnHostGroup>> {
        match self
            .client
            .execute(&SophosRequest::read(FQDN_HOST_GROUP_RESOURCE))
        {
            Ok(response) => fqdn_host_groups_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == FQDN_HOST_GROUP_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_fqdn_host_group(&self, name: impl AsRef<str>) -> Result<Option<FqdnHostGroup>> {
        let name = normalize_name("FQDN host group name", name.as_ref())?;
        let request = read_named(FQDN_HOST_GROUP_RESOURCE, &name);
        match self.client.execute(&request) {
            Ok(response) => Ok(fqdn_host_groups_from_response(&response.resources)?
                .into_iter()
                .find(|group| group.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == FQDN_HOST_GROUP_RESOURCE => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub fn create_fqdn_host_group(&self, group: FqdnHostGroupCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, FQDN_HOST_GROUP_RESOURCE)
            .for_object(&group.name)
            .with_object_key(NAME_KEY)
            .with_payload(fqdn_host_group_payload(
                &group.name,
                &group.hosts,
                group.description.as_deref(),
            ));
        first_named_resource(
            self.client.execute(&request)?.resources,
            FQDN_HOST_GROUP_RESOURCE,
        )
    }

    pub fn update_fqdn_host_group(&self, update: FqdnHostGroupUpdate) -> Result<ResourceResponse> {
        let existing = self.get_fqdn_host_group(&update.name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("FQDN host group '{}' does not exist", update.name))
        })?;
        let hosts = apply_group_update(existing.hosts, update.hosts, update.action);
        let description = update
            .description
            .as_deref()
            .or(existing.description.as_deref());
        let request = SophosRequest::new(Action::Update, FQDN_HOST_GROUP_RESOURCE)
            .for_object(&update.name)
            .with_object_key(NAME_KEY)
            .with_payload(fqdn_host_group_payload(&update.name, &hosts, description));
        first_named_resource(
            self.client.execute(&request)?.resources,
            FQDN_HOST_GROUP_RESOURCE,
        )
    }

    pub fn delete_fqdn_host_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("FQDN host group name", name.as_ref())?;
        if self.get_fqdn_host_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "FQDN host group '{name}' does not exist"
            )));
        }
        self.delete_named(FQDN_HOST_GROUP_RESOURCE, name)
    }

    fn ip_hosts_by_variant(&self, variant: IpHostVariant) -> Result<Vec<ParsedIpHost>> {
        match self.client.execute(&SophosRequest::read(IP_HOST_RESOURCE)) {
            Ok(response) => Ok(ip_hosts_from_response(&response.resources)?
                .into_iter()
                .filter(|host| host.variant == variant)
                .collect()),
            Err(Error::ZeroRecords { resource }) if resource == IP_HOST_RESOURCE => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn get_ip_host_record(&self, name: &str) -> Result<Option<ParsedIpHost>> {
        match self.client.execute(&read_named(IP_HOST_RESOURCE, name)) {
            Ok(response) => Ok(ip_hosts_from_response(&response.resources)?
                .into_iter()
                .find(|host| host.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == IP_HOST_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn write_ip_host(
        &self,
        action: Action,
        payload: serde_json::Value,
    ) -> Result<ResourceResponse> {
        let name = payload
            .get(NAME_KEY)
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error::InvalidRequest("IPHost payload missing Name".to_string()))?;
        let request = SophosRequest::new(action, IP_HOST_RESOURCE)
            .for_object(name)
            .with_object_key(NAME_KEY)
            .with_payload(payload);
        first_named_resource(self.client.execute(&request)?.resources, IP_HOST_RESOURCE)
    }

    fn delete_named(&self, resource: &str, name: String) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Delete, resource)
            .for_object(name)
            .with_object_key(NAME_KEY);
        first_named_resource(self.client.execute(&request)?.resources, resource)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpHostVariant {
    Host,
    Network,
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedIpHost {
    variant: IpHostVariant,
    name: String,
    ip_address: Option<String>,
    subnet: Option<String>,
    start_ip: Option<String>,
    end_ip: Option<String>,
}

impl ParsedIpHost {
    fn into_host(self) -> Option<IpHost> {
        if self.variant != IpHostVariant::Host {
            return None;
        }
        Some(IpHost::new_unchecked(self.name, self.ip_address?))
    }

    fn into_network(self) -> Option<IpNetwork> {
        if self.variant != IpHostVariant::Network {
            return None;
        }
        Some(IpNetwork::new_unchecked(
            self.name,
            self.ip_address?,
            self.subnet?,
        ))
    }

    fn into_range(self) -> Option<IpRange> {
        if self.variant != IpHostVariant::Range {
            return None;
        }
        Some(IpRange::new_unchecked(
            self.name,
            self.start_ip?,
            self.end_ip?,
        ))
    }
}

fn read_named(resource: &str, name: &str) -> SophosRequest {
    SophosRequest::read(resource)
        .for_object(name.to_string())
        .with_object_key(NAME_KEY)
}

fn normalize_name(label: &str, value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(Error::InvalidRequest(format!("{label} must not be empty")));
    }
    Ok(normalized.to_string())
}

fn normalize_ipv4(label: &str, value: &str) -> Result<Ipv4Addr> {
    let value = normalize_name(label, value)?;
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| Error::InvalidRequest(format!("{label} must be an IPv4 address")))
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
        let value = normalize_name(label, value.as_ref())?;
        if !normalized.iter().any(|existing| existing == &value) {
            normalized.push(value);
        }
    }

    if require_non_empty && normalized.is_empty() {
        return Err(Error::InvalidRequest(format!("{label}s must not be empty")));
    }

    Ok(normalized)
}

fn add_unique(mut existing: Vec<String>, requested: Vec<String>) -> Vec<String> {
    for value in requested {
        if !existing.contains(&value) {
            existing.push(value);
        }
    }
    existing
}

fn remove_requested(existing: Vec<String>, requested: &[String]) -> Vec<String> {
    existing
        .into_iter()
        .filter(|value| !requested.contains(value))
        .collect()
}

fn apply_group_update(
    existing: Vec<String>,
    requested: Vec<String>,
    action: NetworkGroupUpdateAction,
) -> Vec<String> {
    match action {
        NetworkGroupUpdateAction::Add => add_unique(existing, requested),
        NetworkGroupUpdateAction::Remove => remove_requested(existing, &requested),
        NetworkGroupUpdateAction::Replace => requested,
    }
}

fn ip_host_payload(host: &IpHostCreate) -> serde_json::Value {
    json!({
        "Name": host.name(),
        "HostType": "IP",
        "IPFamily": IPV4,
        "IPAddress": host.ip_address(),
    })
}

fn ip_network_payload(network: &IpNetworkCreate) -> serde_json::Value {
    json!({
        "Name": network.name(),
        "HostType": "Network",
        "IPFamily": IPV4,
        "IPAddress": network.ip_address(),
        "Subnet": network.subnet(),
    })
}

fn ip_range_payload(range: &IpRangeCreate) -> serde_json::Value {
    json!({
        "Name": range.name(),
        "HostType": "IPRange",
        "IPFamily": IPV4,
        "StartIPAddress": range.start_ip(),
        "EndIPAddress": range.end_ip(),
    })
}

fn ip_host_group_payload(
    name: &str,
    hosts: &[String],
    description: Option<&str>,
) -> serde_json::Value {
    json!({
        "Name": name,
        "IPFamily": IPV4,
        "Description": description.unwrap_or_default(),
        "HostList": {
            "Host": hosts,
        },
    })
}

fn fqdn_host_payload(
    name: &str,
    fqdn: &str,
    groups: &[String],
    description: Option<&str>,
) -> serde_json::Value {
    json!({
        "Name": name,
        "Description": description.unwrap_or_default(),
        "FQDN": fqdn,
        "FQDNHostGroupList": {
            "FQDNHostGroup": groups,
        },
    })
}

fn fqdn_host_group_payload(
    name: &str,
    hosts: &[String],
    description: Option<&str>,
) -> serde_json::Value {
    json!({
        "Name": name,
        "Description": description.unwrap_or_default(),
        "FQDNHostList": {
            "FQDNHost": hosts,
        },
    })
}

fn ip_hosts_from_response(resources: &[ResourceResponse]) -> Result<Vec<ParsedIpHost>> {
    let mut hosts = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == IP_HOST_RESOURCE)
    {
        for node in parse_xml_nodes(&resource.body_xml)?
            .iter()
            .filter(|node| node.name == IP_HOST_RESOURCE)
        {
            if let Some(host) = ip_host_from_node(node)? {
                hosts.push(host);
            }
        }
    }
    Ok(hosts)
}

fn ip_host_from_node(node: &XmlNode) -> Result<Option<ParsedIpHost>> {
    if node
        .child_text("IPFamily")
        .is_some_and(|family| family != IPV4)
    {
        return Ok(None);
    }
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let Some(host_type) = node.child_text("HostType") else {
        return Ok(None);
    };
    let name = normalize_name("IP host name", name)?;
    let host = match host_type {
        "IP" => ParsedIpHost {
            variant: IpHostVariant::Host,
            name,
            ip_address: child_ipv4(node, "IPAddress")?,
            subnet: None,
            start_ip: None,
            end_ip: None,
        },
        "Network" => ParsedIpHost {
            variant: IpHostVariant::Network,
            name,
            ip_address: child_ipv4(node, "IPAddress")?,
            subnet: child_ipv4(node, "Subnet")?,
            start_ip: None,
            end_ip: None,
        },
        "IPRange" => ParsedIpHost {
            variant: IpHostVariant::Range,
            name,
            ip_address: None,
            subnet: None,
            start_ip: child_ipv4(node, "StartIPAddress")?,
            end_ip: child_ipv4(node, "EndIPAddress")?,
        },
        _ => return Ok(None),
    };
    Ok(Some(host))
}

fn child_ipv4(node: &XmlNode, child: &str) -> Result<Option<String>> {
    node.child_text(child)
        .map(|value| normalize_ipv4(child, value).map(|ip| ip.to_string()))
        .transpose()
}

fn ip_host_groups_from_response(resources: &[ResourceResponse]) -> Result<Vec<IpHostGroup>> {
    let mut groups = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == IP_HOST_GROUP_RESOURCE)
    {
        for node in parse_xml_nodes(&resource.body_xml)?
            .iter()
            .filter(|node| node.name == IP_HOST_GROUP_RESOURCE)
        {
            if let Some(group) = ip_host_group_from_node(node)? {
                groups.push(group);
            }
        }
    }
    Ok(groups)
}

fn ip_host_group_from_node(node: &XmlNode) -> Result<Option<IpHostGroup>> {
    if node
        .child_text("IPFamily")
        .is_some_and(|family| family != IPV4)
    {
        return Ok(None);
    }
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let hosts = node
        .child("HostList")
        .map(|host_list| values_from_children(host_list, "Host"))
        .unwrap_or_default();
    let description = node.child_text("Description").map(ToString::to_string);
    Ok(Some(IpHostGroup::new_unchecked(
        normalize_name("IP host group name", name)?,
        hosts,
        description,
    )))
}

fn fqdn_hosts_from_response(resources: &[ResourceResponse]) -> Result<Vec<FqdnHost>> {
    let mut hosts = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == FQDN_HOST_RESOURCE)
    {
        for node in parse_xml_nodes(&resource.body_xml)?
            .iter()
            .filter(|node| node.name == FQDN_HOST_RESOURCE)
        {
            if let Some(host) = fqdn_host_from_node(node)? {
                hosts.push(host);
            }
        }
    }
    Ok(hosts)
}

fn fqdn_host_from_node(node: &XmlNode) -> Result<Option<FqdnHost>> {
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let Some(fqdn) = node.child_text("FQDN") else {
        return Ok(None);
    };
    let groups = node
        .child("FQDNHostGroupList")
        .map(|group_list| values_from_children(group_list, "FQDNHostGroup"))
        .unwrap_or_default();
    let description = node.child_text("Description").map(ToString::to_string);
    Ok(Some(FqdnHost::new_unchecked(
        normalize_name("FQDN host name", name)?,
        normalize_name("FQDN", fqdn)?,
        groups,
        description,
    )))
}

fn fqdn_host_groups_from_response(resources: &[ResourceResponse]) -> Result<Vec<FqdnHostGroup>> {
    let mut groups = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == FQDN_HOST_GROUP_RESOURCE)
    {
        for node in parse_xml_nodes(&resource.body_xml)?
            .iter()
            .filter(|node| node.name == FQDN_HOST_GROUP_RESOURCE)
        {
            if let Some(group) = fqdn_host_group_from_node(node)? {
                groups.push(group);
            }
        }
    }
    Ok(groups)
}

fn fqdn_host_group_from_node(node: &XmlNode) -> Result<Option<FqdnHostGroup>> {
    let Some(name) = node.child_text(NAME_KEY) else {
        return Ok(None);
    };
    let hosts = node
        .child("FQDNHostList")
        .map(|host_list| values_from_children(host_list, "FQDNHost"))
        .unwrap_or_default();
    let description = node.child_text("Description").map(ToString::to_string);
    Ok(Some(FqdnHostGroup::new_unchecked(
        normalize_name("FQDN host group name", name)?,
        hosts,
        description,
    )))
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
