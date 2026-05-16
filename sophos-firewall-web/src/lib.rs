use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sophos_firewall_api::{
    AdminAuthentication, AdminProfile, AdminProfileCreate, AdminProfileUpdate, AdminSettings,
    Backup, BackupUpdate, DnsForwarders, DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate,
    DnsMutationAction, EntryType, Error, FirewallRule, FirewallRuleCreate, FirewallRuleGroup,
    FirewallRuleGroupCreate, FirewallRuleGroupUpdate, FirewallRuleUpdate, FqdnHost, FqdnHostCreate,
    FqdnHostGroup, FqdnHostGroupCreate, FqdnHostGroupUpdate, FqdnHostUpdate, Interface, IpFamily,
    IpHost, IpHostCreate, IpHostGroup, IpHostGroupCreate, IpHostGroupUpdate, IpNetwork,
    IpNetworkCreate, IpRange, IpRangeCreate, LocalServiceAcl, LocalServiceAclCreate,
    LocalServiceAclUpdate, NetworkGroupUpdateAction, Notification, NotificationList, PublishOnWan,
    ReportsRetention, ResourceResponse, Service, ServiceCreate, ServiceEntry, ServiceGroup,
    ServiceGroupCreate, ServiceGroupUpdate, ServiceGroupUpdateAction, ServiceType, ServiceUpdate,
    ServiceUpdateAction, SophosClient, SophosConnection, SophosTransport, UrlGroup, UrlGroupCreate,
    User, UserActivity, UserActivityCreate, UserCreate, Vlan, WebFilterPolicy,
    WebFilterPolicyCreate, WebFilterPolicyUpdate, Zone, ZoneCreate, ZoneUpdate,
};

pub type Result<T> = std::result::Result<T, WebError>;

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error(transparent)]
    Api(#[from] Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub connection: SophosConnection,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = required_env("SOPHOS_FIREWALL_HOST")?;
        let username = required_env("SOPHOS_FIREWALL_USERNAME")?;
        let password = required_env("SOPHOS_FIREWALL_PASSWORD")?;

        let mut connection = SophosConnection::new(host, username, password);
        if let Some(port) = optional_env("SOPHOS_FIREWALL_PORT")? {
            connection.port = port.parse().map_err(|_| {
                WebError::InvalidConfig("SOPHOS_FIREWALL_PORT must be a u16".into())
            })?;
        }
        if let Some(verify_tls) = optional_env("SOPHOS_FIREWALL_VERIFY_TLS")? {
            connection.verify_tls = parse_bool("SOPHOS_FIREWALL_VERIFY_TLS", &verify_tls)?;
        }

        let bind = optional_env("SOPHOS_FIREWALL_WEB_BIND")?
            .unwrap_or_else(|| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(|_| {
                WebError::InvalidConfig(
                    "SOPHOS_FIREWALL_WEB_BIND must be an address like 127.0.0.1:8080".into(),
                )
            })?;

        Ok(Self { bind, connection })
    }
}

fn required_env(name: &'static str) -> Result<String> {
    optional_env(name)?.ok_or(WebError::MissingEnv(name))
}

fn optional_env(name: &'static str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        Ok(_) => Ok(None),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(WebError::InvalidConfig(format!("{name}: {error}"))),
    }
}

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(WebError::InvalidConfig(format!(
            "{name} must be true or false"
        ))),
    }
}

pub trait FirewallClient: Clone + Send + Sync + 'static {
    fn list_dns_entries(&self) -> sophos_firewall_api::Result<Vec<DnsHostEntryCreate>>;
    fn get_dns_entry(
        &self,
        host_name: &str,
    ) -> sophos_firewall_api::Result<Option<DnsHostEntryCreate>>;
    fn add_dns_entry(
        &self,
        entry: DnsHostEntryCreate,
        force: bool,
    ) -> sophos_firewall_api::Result<DnsMutationDto>;
    fn update_dns_entry(
        &self,
        entry: DnsHostEntryUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_dns_entry(&self, host_name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_url_groups(&self) -> sophos_firewall_api::Result<Vec<UrlGroup>>;
    fn get_url_group(&self, name: &str) -> sophos_firewall_api::Result<Option<UrlGroup>>;
    fn create_url_group(
        &self,
        group: UrlGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_url_group_domains(
        &self,
        name: &str,
        action: UrlGroupDomainAction,
        domains: Vec<String>,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_url_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_firewall_rules(&self) -> sophos_firewall_api::Result<Vec<FirewallRule>>;
    fn get_firewall_rule(&self, name: &str) -> sophos_firewall_api::Result<Option<FirewallRule>>;
    fn create_firewall_rule(
        &self,
        rule: FirewallRuleCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_firewall_rule(
        &self,
        rule: FirewallRuleUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_firewall_rule(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_firewall_rule_groups(&self) -> sophos_firewall_api::Result<Vec<FirewallRuleGroup>>;
    fn get_firewall_rule_group(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<FirewallRuleGroup>>;
    fn create_firewall_rule_group(
        &self,
        group: FirewallRuleGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_firewall_rule_group(
        &self,
        group: FirewallRuleGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_firewall_rule_group(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_ip_hosts(&self) -> sophos_firewall_api::Result<Vec<IpHost>>;
    fn get_ip_host(&self, name: &str) -> sophos_firewall_api::Result<Option<IpHost>>;
    fn create_ip_host(&self, host: IpHostCreate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_ip_host(&self, host: IpHostCreate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_ip_host(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_ip_networks(&self) -> sophos_firewall_api::Result<Vec<IpNetwork>>;
    fn get_ip_network(&self, name: &str) -> sophos_firewall_api::Result<Option<IpNetwork>>;
    fn create_ip_network(
        &self,
        network: IpNetworkCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_ip_network(
        &self,
        network: IpNetworkCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_ip_network(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_ip_ranges(&self) -> sophos_firewall_api::Result<Vec<IpRange>>;
    fn get_ip_range(&self, name: &str) -> sophos_firewall_api::Result<Option<IpRange>>;
    fn create_ip_range(
        &self,
        range: IpRangeCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_ip_range(
        &self,
        range: IpRangeCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_ip_range(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_ip_host_groups(&self) -> sophos_firewall_api::Result<Vec<IpHostGroup>>;
    fn get_ip_host_group(&self, name: &str) -> sophos_firewall_api::Result<Option<IpHostGroup>>;
    fn create_ip_host_group(
        &self,
        group: IpHostGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_ip_host_group(
        &self,
        group: IpHostGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_ip_host_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_fqdn_hosts(&self) -> sophos_firewall_api::Result<Vec<FqdnHost>>;
    fn get_fqdn_host(&self, name: &str) -> sophos_firewall_api::Result<Option<FqdnHost>>;
    fn create_fqdn_host(
        &self,
        host: FqdnHostCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_fqdn_host(
        &self,
        host: FqdnHostUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_fqdn_host(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_fqdn_host_groups(&self) -> sophos_firewall_api::Result<Vec<FqdnHostGroup>>;
    fn get_fqdn_host_group(&self, name: &str)
    -> sophos_firewall_api::Result<Option<FqdnHostGroup>>;
    fn create_fqdn_host_group(
        &self,
        group: FqdnHostGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_fqdn_host_group(
        &self,
        group: FqdnHostGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_fqdn_host_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_services(&self) -> sophos_firewall_api::Result<Vec<Service>>;
    fn get_service(&self, name: &str) -> sophos_firewall_api::Result<Option<Service>>;
    fn create_service(
        &self,
        service: ServiceCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_service(
        &self,
        service: ServiceUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_service(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_service_groups(&self) -> sophos_firewall_api::Result<Vec<ServiceGroup>>;
    fn get_service_group(&self, name: &str) -> sophos_firewall_api::Result<Option<ServiceGroup>>;
    fn create_service_group(
        &self,
        group: ServiceGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_service_group(
        &self,
        group: ServiceGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_service_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_acl_rules(&self) -> sophos_firewall_api::Result<Vec<LocalServiceAcl>>;
    fn get_acl_rule(&self, name: &str) -> sophos_firewall_api::Result<Option<LocalServiceAcl>>;
    fn create_acl_rule(
        &self,
        acl: LocalServiceAclCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_acl_rule(
        &self,
        acl: LocalServiceAclUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_acl_rule(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_webfilter_policies(&self) -> sophos_firewall_api::Result<Vec<WebFilterPolicy>>;
    fn get_webfilter_policy(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<WebFilterPolicy>>;
    fn create_webfilter_policy(
        &self,
        policy: WebFilterPolicyCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_webfilter_policy(
        &self,
        policy: WebFilterPolicyUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_webfilter_policy(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_user_activities(&self) -> sophos_firewall_api::Result<Vec<UserActivity>>;
    fn get_user_activity(&self, name: &str) -> sophos_firewall_api::Result<Option<UserActivity>>;
    fn create_user_activity(
        &self,
        activity: UserActivityCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_user_activity(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn list_zones(&self) -> sophos_firewall_api::Result<Vec<Zone>>;
    fn get_zone(&self, name: &str) -> sophos_firewall_api::Result<Option<Zone>>;
    fn create_zone(&self, zone: ZoneCreate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_zone(&self, zone: ZoneUpdate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_zone(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_interfaces(&self) -> sophos_firewall_api::Result<Vec<Interface>>;
    fn get_interface(&self, name: &str) -> sophos_firewall_api::Result<Option<Interface>>;
    fn list_vlans(&self) -> sophos_firewall_api::Result<Vec<Vlan>>;
    fn get_vlan(&self, name: &str) -> sophos_firewall_api::Result<Option<Vlan>>;
    fn get_dns_forwarders(&self) -> sophos_firewall_api::Result<DnsForwarders>;

    fn list_admin_profiles(&self) -> sophos_firewall_api::Result<Vec<AdminProfile>>;
    fn get_admin_profile(&self, name: &str) -> sophos_firewall_api::Result<Option<AdminProfile>>;
    fn create_admin_profile(
        &self,
        profile: AdminProfileCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_admin_profile(
        &self,
        profile: AdminProfileUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_admin_profile(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse>;
    fn get_admin_authentication(&self) -> sophos_firewall_api::Result<AdminAuthentication>;
    fn get_admin_settings(&self) -> sophos_firewall_api::Result<AdminSettings>;

    fn list_users(&self) -> sophos_firewall_api::Result<Vec<User>>;
    fn get_user(&self, username: &str) -> sophos_firewall_api::Result<Option<User>>;
    fn create_user(&self, user: UserCreate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn update_user_password(
        &self,
        username: &str,
        new_password: String,
    ) -> sophos_firewall_api::Result<ResourceResponse>;
    fn delete_user(&self, username: &str) -> sophos_firewall_api::Result<ResourceResponse>;

    fn get_backup(&self) -> sophos_firewall_api::Result<Backup>;
    fn update_backup(&self, backup: BackupUpdate) -> sophos_firewall_api::Result<ResourceResponse>;
    fn list_notifications(&self) -> sophos_firewall_api::Result<Vec<Notification>>;
    fn get_notification(&self, name: &str) -> sophos_firewall_api::Result<Option<Notification>>;
    fn list_notification_items(&self) -> sophos_firewall_api::Result<Vec<NotificationList>>;
    fn get_notification_item(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<NotificationList>>;
    fn get_reports_retention(&self) -> sophos_firewall_api::Result<ReportsRetention>;
}

impl<T> FirewallClient for SophosClient<T>
where
    T: SophosTransport + Clone + Send + Sync + 'static,
{
    fn list_dns_entries(&self) -> sophos_firewall_api::Result<Vec<DnsHostEntryCreate>> {
        self.dns().list_entries()
    }

    fn get_dns_entry(
        &self,
        host_name: &str,
    ) -> sophos_firewall_api::Result<Option<DnsHostEntryCreate>> {
        self.dns().get_entry(host_name)
    }

    fn add_dns_entry(
        &self,
        entry: DnsHostEntryCreate,
        force: bool,
    ) -> sophos_firewall_api::Result<DnsMutationDto> {
        let outcome = self.dns().add_entry(entry, force)?;
        Ok(DnsMutationDto {
            action: match outcome.action {
                DnsMutationAction::Created => MutationAction::Created,
                DnsMutationAction::Updated => MutationAction::Updated,
            },
            response: outcome.response.into(),
        })
    }

    fn update_dns_entry(
        &self,
        entry: DnsHostEntryUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.dns().update_entry(entry)
    }

    fn delete_dns_entry(&self, host_name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.dns().delete_entry(host_name)
    }

    fn list_url_groups(&self) -> sophos_firewall_api::Result<Vec<UrlGroup>> {
        self.url_groups().list_groups()
    }

    fn get_url_group(&self, name: &str) -> sophos_firewall_api::Result<Option<UrlGroup>> {
        self.url_groups().get_group(name)
    }

    fn create_url_group(
        &self,
        group: UrlGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.url_groups().create_group(group)
    }

    fn update_url_group_domains(
        &self,
        name: &str,
        action: UrlGroupDomainAction,
        domains: Vec<String>,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        match action {
            UrlGroupDomainAction::Add => self.url_groups().add_domains(name, domains),
            UrlGroupDomainAction::Remove => self.url_groups().remove_domains(name, domains),
            UrlGroupDomainAction::Replace => self.url_groups().replace_domains(name, domains),
        }
    }

    fn delete_url_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.url_groups().delete_group(name)
    }

    fn list_firewall_rules(&self) -> sophos_firewall_api::Result<Vec<FirewallRule>> {
        self.firewall().list_rules()
    }

    fn get_firewall_rule(&self, name: &str) -> sophos_firewall_api::Result<Option<FirewallRule>> {
        self.firewall().get_rule(name)
    }

    fn create_firewall_rule(
        &self,
        rule: FirewallRuleCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().create_rule(rule)
    }

    fn update_firewall_rule(
        &self,
        rule: FirewallRuleUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().update_rule(rule)
    }

    fn delete_firewall_rule(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().delete_rule(name)
    }

    fn list_firewall_rule_groups(&self) -> sophos_firewall_api::Result<Vec<FirewallRuleGroup>> {
        self.firewall().list_rule_groups()
    }

    fn get_firewall_rule_group(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<FirewallRuleGroup>> {
        self.firewall().get_rule_group(name)
    }

    fn create_firewall_rule_group(
        &self,
        group: FirewallRuleGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().create_rule_group(group)
    }

    fn update_firewall_rule_group(
        &self,
        group: FirewallRuleGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().update_rule_group(group)
    }

    fn delete_firewall_rule_group(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().delete_rule_group(name)
    }

    fn list_ip_hosts(&self) -> sophos_firewall_api::Result<Vec<IpHost>> {
        self.network().list_ip_hosts()
    }

    fn get_ip_host(&self, name: &str) -> sophos_firewall_api::Result<Option<IpHost>> {
        self.network().get_ip_host(name)
    }

    fn create_ip_host(&self, host: IpHostCreate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_ip_host(host)
    }

    fn update_ip_host(&self, host: IpHostCreate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_ip_host(host)
    }

    fn delete_ip_host(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_ip_host(name)
    }

    fn list_ip_networks(&self) -> sophos_firewall_api::Result<Vec<IpNetwork>> {
        self.network().list_ip_networks()
    }

    fn get_ip_network(&self, name: &str) -> sophos_firewall_api::Result<Option<IpNetwork>> {
        self.network().get_ip_network(name)
    }

    fn create_ip_network(
        &self,
        network: IpNetworkCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_ip_network(network)
    }

    fn update_ip_network(
        &self,
        network: IpNetworkCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_ip_network(network)
    }

    fn delete_ip_network(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_ip_network(name)
    }

    fn list_ip_ranges(&self) -> sophos_firewall_api::Result<Vec<IpRange>> {
        self.network().list_ip_ranges()
    }

    fn get_ip_range(&self, name: &str) -> sophos_firewall_api::Result<Option<IpRange>> {
        self.network().get_ip_range(name)
    }

    fn create_ip_range(
        &self,
        range: IpRangeCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_ip_range(range)
    }

    fn update_ip_range(
        &self,
        range: IpRangeCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_ip_range(range)
    }

    fn delete_ip_range(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_ip_range(name)
    }

    fn list_ip_host_groups(&self) -> sophos_firewall_api::Result<Vec<IpHostGroup>> {
        self.network().list_ip_host_groups()
    }

    fn get_ip_host_group(&self, name: &str) -> sophos_firewall_api::Result<Option<IpHostGroup>> {
        self.network().get_ip_host_group(name)
    }

    fn create_ip_host_group(
        &self,
        group: IpHostGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_ip_host_group(group)
    }

    fn update_ip_host_group(
        &self,
        group: IpHostGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_ip_host_group(group)
    }

    fn delete_ip_host_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_ip_host_group(name)
    }

    fn list_fqdn_hosts(&self) -> sophos_firewall_api::Result<Vec<FqdnHost>> {
        self.network().list_fqdn_hosts()
    }

    fn get_fqdn_host(&self, name: &str) -> sophos_firewall_api::Result<Option<FqdnHost>> {
        self.network().get_fqdn_host(name)
    }

    fn create_fqdn_host(
        &self,
        host: FqdnHostCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_fqdn_host(host)
    }

    fn update_fqdn_host(
        &self,
        host: FqdnHostUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_fqdn_host(host)
    }

    fn delete_fqdn_host(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_fqdn_host(name)
    }

    fn list_fqdn_host_groups(&self) -> sophos_firewall_api::Result<Vec<FqdnHostGroup>> {
        self.network().list_fqdn_host_groups()
    }

    fn get_fqdn_host_group(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<FqdnHostGroup>> {
        self.network().get_fqdn_host_group(name)
    }

    fn create_fqdn_host_group(
        &self,
        group: FqdnHostGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().create_fqdn_host_group(group)
    }

    fn update_fqdn_host_group(
        &self,
        group: FqdnHostGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().update_fqdn_host_group(group)
    }

    fn delete_fqdn_host_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.network().delete_fqdn_host_group(name)
    }

    fn list_services(&self) -> sophos_firewall_api::Result<Vec<Service>> {
        self.services().list_services()
    }

    fn get_service(&self, name: &str) -> sophos_firewall_api::Result<Option<Service>> {
        self.services().get_service(name)
    }

    fn create_service(
        &self,
        service: ServiceCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.services().create_service(service)
    }

    fn update_service(
        &self,
        service: ServiceUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.services().update_service(service)
    }

    fn delete_service(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.services().delete_service(name)
    }

    fn list_service_groups(&self) -> sophos_firewall_api::Result<Vec<ServiceGroup>> {
        self.service_groups().list_groups()
    }

    fn get_service_group(&self, name: &str) -> sophos_firewall_api::Result<Option<ServiceGroup>> {
        self.service_groups().get_group(name)
    }

    fn create_service_group(
        &self,
        group: ServiceGroupCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.service_groups().create_group(group)
    }

    fn update_service_group(
        &self,
        group: ServiceGroupUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.service_groups().update_group(group)
    }

    fn delete_service_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.service_groups().delete_group(name)
    }

    fn list_acl_rules(&self) -> sophos_firewall_api::Result<Vec<LocalServiceAcl>> {
        self.firewall().list_acl_rules()
    }

    fn get_acl_rule(&self, name: &str) -> sophos_firewall_api::Result<Option<LocalServiceAcl>> {
        self.firewall().get_acl_rule(name)
    }

    fn create_acl_rule(
        &self,
        acl: LocalServiceAclCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().create_acl_rule(acl)
    }

    fn update_acl_rule(
        &self,
        acl: LocalServiceAclUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().update_acl_rule(acl)
    }

    fn delete_acl_rule(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.firewall().delete_acl_rule(name)
    }

    fn list_webfilter_policies(&self) -> sophos_firewall_api::Result<Vec<WebFilterPolicy>> {
        self.webfilter().list_policies()
    }

    fn get_webfilter_policy(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<WebFilterPolicy>> {
        self.webfilter().get_policy(name)
    }

    fn create_webfilter_policy(
        &self,
        policy: WebFilterPolicyCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.webfilter().create_policy(policy)
    }

    fn update_webfilter_policy(
        &self,
        policy: WebFilterPolicyUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.webfilter().update_policy(policy)
    }

    fn delete_webfilter_policy(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.webfilter().delete_policy(name)
    }

    fn list_user_activities(&self) -> sophos_firewall_api::Result<Vec<UserActivity>> {
        self.webfilter().list_user_activities()
    }

    fn get_user_activity(&self, name: &str) -> sophos_firewall_api::Result<Option<UserActivity>> {
        self.webfilter().get_user_activity(name)
    }

    fn create_user_activity(
        &self,
        activity: UserActivityCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.webfilter().create_user_activity(activity)
    }

    fn delete_user_activity(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.webfilter().delete_user_activity(name)
    }

    fn list_zones(&self) -> sophos_firewall_api::Result<Vec<Zone>> {
        self.zones().list_zones()
    }

    fn get_zone(&self, name: &str) -> sophos_firewall_api::Result<Option<Zone>> {
        self.zones().get_zone(name)
    }

    fn create_zone(&self, zone: ZoneCreate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.zones().create_zone(zone)
    }

    fn update_zone(&self, zone: ZoneUpdate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.zones().update_zone(zone)
    }

    fn delete_zone(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.zones().delete_zone(name)
    }

    fn list_interfaces(&self) -> sophos_firewall_api::Result<Vec<Interface>> {
        self.zones().list_interfaces()
    }

    fn get_interface(&self, name: &str) -> sophos_firewall_api::Result<Option<Interface>> {
        self.zones().get_interface(name)
    }

    fn list_vlans(&self) -> sophos_firewall_api::Result<Vec<Vlan>> {
        self.zones().list_vlans()
    }

    fn get_vlan(&self, name: &str) -> sophos_firewall_api::Result<Option<Vlan>> {
        self.zones().get_vlan(name)
    }

    fn get_dns_forwarders(&self) -> sophos_firewall_api::Result<DnsForwarders> {
        self.zones().get_dns_forwarders()
    }

    fn list_admin_profiles(&self) -> sophos_firewall_api::Result<Vec<AdminProfile>> {
        self.admin().list_profiles()
    }

    fn get_admin_profile(&self, name: &str) -> sophos_firewall_api::Result<Option<AdminProfile>> {
        self.admin().get_profile(name)
    }

    fn create_admin_profile(
        &self,
        profile: AdminProfileCreate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.admin().create_profile(profile)
    }

    fn update_admin_profile(
        &self,
        profile: AdminProfileUpdate,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.admin().update_profile(profile)
    }

    fn delete_admin_profile(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.admin().delete_profile(name)
    }

    fn get_admin_authentication(&self) -> sophos_firewall_api::Result<AdminAuthentication> {
        self.admin().get_authentication()
    }

    fn get_admin_settings(&self) -> sophos_firewall_api::Result<AdminSettings> {
        self.admin().get_settings()
    }

    fn list_users(&self) -> sophos_firewall_api::Result<Vec<User>> {
        self.users().list_users()
    }

    fn get_user(&self, username: &str) -> sophos_firewall_api::Result<Option<User>> {
        self.users().get_user(username)
    }

    fn create_user(&self, user: UserCreate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.users().create_user(user)
    }

    fn update_user_password(
        &self,
        username: &str,
        new_password: String,
    ) -> sophos_firewall_api::Result<ResourceResponse> {
        self.users().update_password(username, new_password)
    }

    fn delete_user(&self, username: &str) -> sophos_firewall_api::Result<ResourceResponse> {
        self.users().delete_user(username)
    }

    fn get_backup(&self) -> sophos_firewall_api::Result<Backup> {
        self.system().get_backup()
    }

    fn update_backup(&self, backup: BackupUpdate) -> sophos_firewall_api::Result<ResourceResponse> {
        self.system().update_backup(backup)
    }

    fn list_notifications(&self) -> sophos_firewall_api::Result<Vec<Notification>> {
        self.system().list_notifications()
    }

    fn get_notification(&self, name: &str) -> sophos_firewall_api::Result<Option<Notification>> {
        self.system().get_notification(name)
    }

    fn list_notification_items(&self) -> sophos_firewall_api::Result<Vec<NotificationList>> {
        self.system().list_notification_items()
    }

    fn get_notification_item(
        &self,
        name: &str,
    ) -> sophos_firewall_api::Result<Option<NotificationList>> {
        self.system().get_notification_item(name)
    }

    fn get_reports_retention(&self) -> sophos_firewall_api::Result<ReportsRetention> {
        self.system().get_reports_retention()
    }
}

pub struct AppState<C> {
    client: Arc<C>,
}

impl<C> AppState<C> {
    pub fn new(client: C) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

impl<C> Clone for AppState<C> {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
        }
    }
}

pub fn routes<C>(state: AppState<C>) -> Router
where
    C: FirewallClient,
{
    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/dns/host-entries",
            get(list_dns_entries::<C>).post(create_dns_entry::<C>),
        )
        .route(
            "/v1/dns/host-entries/{host_name}",
            get(get_dns_entry::<C>)
                .put(upsert_dns_entry::<C>)
                .patch(update_dns_entry::<C>)
                .delete(delete_dns_entry::<C>),
        )
        .route(
            "/v1/url-groups",
            get(list_url_groups::<C>).post(create_url_group::<C>),
        )
        .route(
            "/v1/url-groups/{name}",
            get(get_url_group::<C>).delete(delete_url_group::<C>),
        )
        .route(
            "/v1/url-groups/{name}/domains",
            patch(update_url_group_domains::<C>),
        )
        .route(
            "/v1/firewall/rules",
            get(list_firewall_rules::<C>).post(create_firewall_rule::<C>),
        )
        .route(
            "/v1/firewall/rules/{name}",
            get(get_firewall_rule::<C>)
                .patch(update_firewall_rule::<C>)
                .delete(delete_firewall_rule::<C>),
        )
        .route(
            "/v1/firewall/rule-groups",
            get(list_firewall_rule_groups::<C>).post(create_firewall_rule_group::<C>),
        )
        .route(
            "/v1/firewall/rule-groups/{name}",
            get(get_firewall_rule_group::<C>)
                .patch(update_firewall_rule_group::<C>)
                .delete(delete_firewall_rule_group::<C>),
        )
        .route(
            "/v1/network/ip-hosts",
            get(list_ip_hosts::<C>).post(create_ip_host::<C>),
        )
        .route(
            "/v1/network/ip-hosts/{name}",
            get(get_ip_host::<C>)
                .put(update_ip_host::<C>)
                .delete(delete_ip_host::<C>),
        )
        .route(
            "/v1/network/ip-networks",
            get(list_ip_networks::<C>).post(create_ip_network::<C>),
        )
        .route(
            "/v1/network/ip-networks/{name}",
            get(get_ip_network::<C>)
                .put(update_ip_network::<C>)
                .delete(delete_ip_network::<C>),
        )
        .route(
            "/v1/network/ip-ranges",
            get(list_ip_ranges::<C>).post(create_ip_range::<C>),
        )
        .route(
            "/v1/network/ip-ranges/{name}",
            get(get_ip_range::<C>)
                .put(update_ip_range::<C>)
                .delete(delete_ip_range::<C>),
        )
        .route(
            "/v1/network/ip-host-groups",
            get(list_ip_host_groups::<C>).post(create_ip_host_group::<C>),
        )
        .route(
            "/v1/network/ip-host-groups/{name}",
            get(get_ip_host_group::<C>)
                .patch(update_ip_host_group::<C>)
                .delete(delete_ip_host_group::<C>),
        )
        .route(
            "/v1/network/fqdn-hosts",
            get(list_fqdn_hosts::<C>).post(create_fqdn_host::<C>),
        )
        .route(
            "/v1/network/fqdn-hosts/{name}",
            get(get_fqdn_host::<C>)
                .patch(update_fqdn_host::<C>)
                .delete(delete_fqdn_host::<C>),
        )
        .route(
            "/v1/network/fqdn-host-groups",
            get(list_fqdn_host_groups::<C>).post(create_fqdn_host_group::<C>),
        )
        .route(
            "/v1/network/fqdn-host-groups/{name}",
            get(get_fqdn_host_group::<C>)
                .patch(update_fqdn_host_group::<C>)
                .delete(delete_fqdn_host_group::<C>),
        )
        .route(
            "/v1/services",
            get(list_services::<C>).post(create_service::<C>),
        )
        .route(
            "/v1/services/{name}",
            get(get_service::<C>)
                .patch(update_service::<C>)
                .delete(delete_service::<C>),
        )
        .route(
            "/v1/service-groups",
            get(list_service_groups::<C>).post(create_service_group::<C>),
        )
        .route(
            "/v1/service-groups/{name}",
            get(get_service_group::<C>)
                .patch(update_service_group::<C>)
                .delete(delete_service_group::<C>),
        )
        .route(
            "/v1/firewall/acl-rules",
            get(list_acl_rules::<C>).post(create_acl_rule::<C>),
        )
        .route(
            "/v1/firewall/acl-rules/{name}",
            get(get_acl_rule::<C>)
                .patch(update_acl_rule::<C>)
                .delete(delete_acl_rule::<C>),
        )
        .route(
            "/v1/webfilter/policies",
            get(list_webfilter_policies::<C>).post(create_webfilter_policy::<C>),
        )
        .route(
            "/v1/webfilter/policies/{name}",
            get(get_webfilter_policy::<C>)
                .patch(update_webfilter_policy::<C>)
                .delete(delete_webfilter_policy::<C>),
        )
        .route(
            "/v1/webfilter/user-activities",
            get(list_user_activities::<C>).post(create_user_activity::<C>),
        )
        .route(
            "/v1/webfilter/user-activities/{name}",
            get(get_user_activity::<C>).delete(delete_user_activity::<C>),
        )
        .route("/v1/zones", get(list_zones::<C>).post(create_zone::<C>))
        .route(
            "/v1/zones/{name}",
            get(get_zone::<C>)
                .patch(update_zone::<C>)
                .delete(delete_zone::<C>),
        )
        .route("/v1/interfaces", get(list_interfaces::<C>))
        .route("/v1/interfaces/{name}", get(get_interface::<C>))
        .route("/v1/vlans", get(list_vlans::<C>))
        .route("/v1/vlans/{name}", get(get_vlan::<C>))
        .route("/v1/dns/forwarders", get(get_dns_forwarders::<C>))
        .route(
            "/v1/admin/profiles",
            get(list_admin_profiles::<C>).post(create_admin_profile::<C>),
        )
        .route(
            "/v1/admin/profiles/{name}",
            get(get_admin_profile::<C>)
                .patch(update_admin_profile::<C>)
                .delete(delete_admin_profile::<C>),
        )
        .route(
            "/v1/admin/authentication",
            get(get_admin_authentication::<C>),
        )
        .route("/v1/admin/settings", get(get_admin_settings::<C>))
        .route("/v1/users", get(list_users::<C>).post(create_user::<C>))
        .route(
            "/v1/users/{username}",
            get(get_user::<C>).delete(delete_user::<C>),
        )
        .route(
            "/v1/users/{username}/password",
            patch(update_user_password::<C>),
        )
        .route(
            "/v1/system/backup",
            get(get_backup::<C>).patch(update_backup::<C>),
        )
        .route("/v1/system/notifications", get(list_notifications::<C>))
        .route(
            "/v1/system/notifications/{name}",
            get(get_notification::<C>),
        )
        .route(
            "/v1/system/notification-items",
            get(list_notification_items::<C>),
        )
        .route(
            "/v1/system/notification-items/{name}",
            get(get_notification_item::<C>),
        )
        .route(
            "/v1/system/reports-retention",
            get(get_reports_retention::<C>),
        )
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn list_dns_entries<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<DnsHostEntryDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let entries = run_blocking(move || client.list_dns_entries()).await?;
    Ok(Json(entries.into_iter().map(Into::into).collect()))
}

async fn get_dns_entry<C>(
    State(state): State<AppState<C>>,
    Path(host_name): Path<String>,
) -> ApiResult<DnsHostEntryDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let entry = run_blocking(move || client.get_dns_entry(&host_name)).await?;
    let entry = entry
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("DNS entry not found"))?;
    Ok(Json(entry))
}

async fn create_dns_entry<C>(
    State(state): State<AppState<C>>,
    Query(query): Query<ForceQuery>,
    Json(body): Json<DnsHostEntryBody>,
) -> ApiResult<DnsMutationDto>
where
    C: FirewallClient,
{
    let entry = body.into_create(None)?;
    let force = query.force.unwrap_or(false);
    let client = state.client.clone();
    let outcome = run_blocking(move || client.add_dns_entry(entry, force)).await?;
    Ok(Json(outcome))
}

async fn upsert_dns_entry<C>(
    State(state): State<AppState<C>>,
    Path(host_name): Path<String>,
    Json(body): Json<DnsHostEntryBody>,
) -> ApiResult<DnsMutationDto>
where
    C: FirewallClient,
{
    let entry = body.into_create(Some(host_name))?;
    let client = state.client.clone();
    let outcome = run_blocking(move || client.add_dns_entry(entry, true)).await?;
    Ok(Json(outcome))
}

async fn update_dns_entry<C>(
    State(state): State<AppState<C>>,
    Path(host_name): Path<String>,
    Json(body): Json<DnsHostEntryPatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let entry = body.into_update(host_name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_dns_entry(entry)).await?;
    Ok(Json(response.into()))
}

async fn delete_dns_entry<C>(
    State(state): State<AppState<C>>,
    Path(host_name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_dns_entry(&host_name)).await?;
    Ok(Json(response.into()))
}

async fn list_url_groups<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<UrlGroupDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let groups = run_blocking(move || client.list_url_groups()).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_url_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<UrlGroupDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let group = run_blocking(move || client.get_url_group(&name)).await?;
    let group = group
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("URL group not found"))?;
    Ok(Json(group))
}

async fn create_url_group<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<UrlGroupBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_url_group(group)).await?;
    Ok(Json(response.into()))
}

async fn update_url_group_domains<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<UrlGroupDomainsBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response =
        run_blocking(move || client.update_url_group_domains(&name, body.action, body.domains))
            .await?;
    Ok(Json(response.into()))
}

async fn delete_url_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_url_group(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_firewall_rules<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let rules = run_blocking(move || client.list_firewall_rules()).await?;
    Ok(Json(rules.into_iter().map(Into::into).collect()))
}

async fn get_firewall_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let rule = run_blocking(move || client.get_firewall_rule(&name)).await?;
    let rule = rule
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("firewall rule not found"))?;
    Ok(Json(rule))
}

async fn create_firewall_rule<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let rule = body.into_rule_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_firewall_rule(rule)).await?;
    Ok(Json(response.into()))
}

async fn update_firewall_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let rule = body.into_rule_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_firewall_rule(rule)).await?;
    Ok(Json(response.into()))
}

async fn delete_firewall_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_firewall_rule(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_firewall_rule_groups<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let groups = run_blocking(move || client.list_firewall_rule_groups()).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_firewall_rule_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let group = run_blocking(move || client.get_firewall_rule_group(&name)).await?;
    let group = group
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("firewall rule group not found"))?;
    Ok(Json(group))
}

async fn create_firewall_rule_group<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_rule_group_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_firewall_rule_group(group)).await?;
    Ok(Json(response.into()))
}

async fn update_firewall_rule_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_rule_group_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_firewall_rule_group(group)).await?;
    Ok(Json(response.into()))
}

async fn delete_firewall_rule_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_firewall_rule_group(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_ip_hosts<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<IpHostDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let hosts = run_blocking(move || client.list_ip_hosts()).await?;
    Ok(Json(hosts.into_iter().map(Into::into).collect()))
}

async fn get_ip_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<IpHostDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let host = run_blocking(move || client.get_ip_host(&name)).await?;
    let host = host
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("IP host not found"))?;
    Ok(Json(host))
}

async fn create_ip_host<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<IpHostBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let host = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_ip_host(host)).await?;
    Ok(Json(response.into()))
}

async fn update_ip_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<IpHostBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let host = body.into_create(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_ip_host(host)).await?;
    Ok(Json(response.into()))
}

async fn delete_ip_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_ip_host(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_ip_networks<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<IpNetworkDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let networks = run_blocking(move || client.list_ip_networks()).await?;
    Ok(Json(networks.into_iter().map(Into::into).collect()))
}

async fn get_ip_network<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<IpNetworkDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let network = run_blocking(move || client.get_ip_network(&name)).await?;
    let network = network
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("IP network not found"))?;
    Ok(Json(network))
}

async fn create_ip_network<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<IpNetworkBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let network = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_ip_network(network)).await?;
    Ok(Json(response.into()))
}

async fn update_ip_network<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<IpNetworkBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let network = body.into_create(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_ip_network(network)).await?;
    Ok(Json(response.into()))
}

async fn delete_ip_network<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_ip_network(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_ip_ranges<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<IpRangeDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let ranges = run_blocking(move || client.list_ip_ranges()).await?;
    Ok(Json(ranges.into_iter().map(Into::into).collect()))
}

async fn get_ip_range<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<IpRangeDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let range = run_blocking(move || client.get_ip_range(&name)).await?;
    let range = range
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("IP range not found"))?;
    Ok(Json(range))
}

async fn create_ip_range<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<IpRangeBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let range = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_ip_range(range)).await?;
    Ok(Json(response.into()))
}

async fn update_ip_range<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<IpRangeBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let range = body.into_create(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_ip_range(range)).await?;
    Ok(Json(response.into()))
}

async fn delete_ip_range<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_ip_range(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_ip_host_groups<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<NetworkGroupDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let groups = run_blocking(move || client.list_ip_host_groups()).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_ip_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<NetworkGroupDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let group = run_blocking(move || client.get_ip_host_group(&name)).await?;
    let group = group
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("IP host group not found"))?;
    Ok(Json(group))
}

async fn create_ip_host_group<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<NetworkGroupBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_ip_host_group_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_ip_host_group(group)).await?;
    Ok(Json(response.into()))
}

async fn update_ip_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<NetworkGroupPatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_ip_host_group_update(name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_ip_host_group(group)).await?;
    Ok(Json(response.into()))
}

async fn delete_ip_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_ip_host_group(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_fqdn_hosts<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FqdnHostDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let hosts = run_blocking(move || client.list_fqdn_hosts()).await?;
    Ok(Json(hosts.into_iter().map(Into::into).collect()))
}

async fn get_fqdn_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FqdnHostDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let host = run_blocking(move || client.get_fqdn_host(&name)).await?;
    let host = host
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("FQDN host not found"))?;
    Ok(Json(host))
}

async fn create_fqdn_host<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FqdnHostBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let host = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_fqdn_host(host)).await?;
    Ok(Json(response.into()))
}

async fn update_fqdn_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FqdnHostPatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let host = body.into_update(name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_fqdn_host(host)).await?;
    Ok(Json(response.into()))
}

async fn delete_fqdn_host<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_fqdn_host(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_fqdn_host_groups<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<NetworkGroupDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let groups = run_blocking(move || client.list_fqdn_host_groups()).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_fqdn_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<NetworkGroupDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let group = run_blocking(move || client.get_fqdn_host_group(&name)).await?;
    let group = group
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("FQDN host group not found"))?;
    Ok(Json(group))
}

async fn create_fqdn_host_group<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<NetworkGroupBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_fqdn_host_group_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_fqdn_host_group(group)).await?;
    Ok(Json(response.into()))
}

async fn update_fqdn_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<NetworkGroupPatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_fqdn_host_group_update(name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_fqdn_host_group(group)).await?;
    Ok(Json(response.into()))
}

async fn delete_fqdn_host_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_fqdn_host_group(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_services<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<ServiceDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let services = run_blocking(move || client.list_services()).await?;
    Ok(Json(services.into_iter().map(Into::into).collect()))
}

async fn get_service<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ServiceDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let service = run_blocking(move || client.get_service(&name)).await?;
    let service = service
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("service not found"))?;
    Ok(Json(service))
}

async fn create_service<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<ServiceBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let service = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_service(service)).await?;
    Ok(Json(response.into()))
}

async fn update_service<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<ServicePatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let service = body.into_update(name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_service(service)).await?;
    Ok(Json(response.into()))
}

async fn delete_service<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_service(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_service_groups<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<ServiceGroupDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let groups = run_blocking(move || client.list_service_groups()).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_service_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ServiceGroupDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let group = run_blocking(move || client.get_service_group(&name)).await?;
    let group = group
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("service group not found"))?;
    Ok(Json(group))
}

async fn create_service_group<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<ServiceGroupBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_service_group(group)).await?;
    Ok(Json(response.into()))
}

async fn update_service_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<ServiceGroupPatch>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let group = body.into_update(name)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_service_group(group)).await?;
    Ok(Json(response.into()))
}

async fn delete_service_group<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_service_group(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_acl_rules<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let rules = run_blocking(move || client.list_acl_rules()).await?;
    Ok(Json(rules.into_iter().map(Into::into).collect()))
}

async fn get_acl_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let rule = run_blocking(move || client.get_acl_rule(&name)).await?;
    let rule = rule
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("ACL rule not found"))?;
    Ok(Json(rule))
}

async fn create_acl_rule<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let acl = body.into_acl_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_acl_rule(acl)).await?;
    Ok(Json(response.into()))
}

async fn update_acl_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let acl = body.into_acl_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_acl_rule(acl)).await?;
    Ok(Json(response.into()))
}

async fn delete_acl_rule<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_acl_rule(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_webfilter_policies<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let policies = run_blocking(move || client.list_webfilter_policies()).await?;
    Ok(Json(policies.into_iter().map(Into::into).collect()))
}

async fn get_webfilter_policy<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let policy = run_blocking(move || client.get_webfilter_policy(&name)).await?;
    let policy = policy
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("web filter policy not found"))?;
    Ok(Json(policy))
}

async fn create_webfilter_policy<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let policy = body.into_webfilter_policy_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_webfilter_policy(policy)).await?;
    Ok(Json(response.into()))
}

async fn update_webfilter_policy<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let policy = body.into_webfilter_policy_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_webfilter_policy(policy)).await?;
    Ok(Json(response.into()))
}

async fn delete_webfilter_policy<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_webfilter_policy(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_user_activities<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let activities = run_blocking(move || client.list_user_activities()).await?;
    Ok(Json(activities.into_iter().map(Into::into).collect()))
}

async fn get_user_activity<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let activity = run_blocking(move || client.get_user_activity(&name)).await?;
    let activity = activity
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("user activity not found"))?;
    Ok(Json(activity))
}

async fn create_user_activity<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let activity = body.into_user_activity_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_user_activity(activity)).await?;
    Ok(Json(response.into()))
}

async fn delete_user_activity<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_user_activity(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_zones<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let zones = run_blocking(move || client.list_zones()).await?;
    Ok(Json(zones.into_iter().map(Into::into).collect()))
}

async fn get_zone<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let zone = run_blocking(move || client.get_zone(&name)).await?;
    let zone = zone
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("zone not found"))?;
    Ok(Json(zone))
}

async fn create_zone<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<ZoneBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let zone = body.into_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_zone(zone)).await?;
    Ok(Json(response.into()))
}

async fn update_zone<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let zone = body.into_zone_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_zone(zone)).await?;
    Ok(Json(response.into()))
}

async fn delete_zone<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_zone(&name)).await?;
    Ok(Json(response.into()))
}

async fn list_interfaces<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let interfaces = run_blocking(move || client.list_interfaces()).await?;
    Ok(Json(interfaces.into_iter().map(Into::into).collect()))
}

async fn get_interface<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let interface = run_blocking(move || client.get_interface(&name)).await?;
    let interface = interface
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("interface not found"))?;
    Ok(Json(interface))
}

async fn list_vlans<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let vlans = run_blocking(move || client.list_vlans()).await?;
    Ok(Json(vlans.into_iter().map(Into::into).collect()))
}

async fn get_vlan<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let vlan = run_blocking(move || client.get_vlan(&name)).await?;
    let vlan = vlan
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("VLAN not found"))?;
    Ok(Json(vlan))
}

async fn get_dns_forwarders<C>(State(state): State<AppState<C>>) -> ApiResult<SingletonDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let forwarders = run_blocking(move || client.get_dns_forwarders()).await?;
    Ok(Json(forwarders.into()))
}

async fn list_admin_profiles<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let profiles = run_blocking(move || client.list_admin_profiles()).await?;
    Ok(Json(profiles.into_iter().map(Into::into).collect()))
}

async fn get_admin_profile<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let profile = run_blocking(move || client.get_admin_profile(&name)).await?;
    let profile = profile
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("admin profile not found"))?;
    Ok(Json(profile))
}

async fn create_admin_profile<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let profile = body.into_admin_profile_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_admin_profile(profile)).await?;
    Ok(Json(response.into()))
}

async fn update_admin_profile<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let profile = body.into_admin_profile_update(Some(name))?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_admin_profile(profile)).await?;
    Ok(Json(response.into()))
}

async fn delete_admin_profile<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_admin_profile(&name)).await?;
    Ok(Json(response.into()))
}

async fn get_admin_authentication<C>(State(state): State<AppState<C>>) -> ApiResult<SingletonDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let auth = run_blocking(move || client.get_admin_authentication()).await?;
    Ok(Json(auth.into()))
}

async fn get_admin_settings<C>(State(state): State<AppState<C>>) -> ApiResult<SingletonDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let settings = run_blocking(move || client.get_admin_settings()).await?;
    Ok(Json(settings.into()))
}

async fn list_users<C>(State(state): State<AppState<C>>) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let users = run_blocking(move || client.list_users()).await?;
    Ok(Json(users.into_iter().map(Into::into).collect()))
}

async fn get_user<C>(
    State(state): State<AppState<C>>,
    Path(username): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let user = run_blocking(move || client.get_user(&username)).await?;
    let user = user
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    Ok(Json(user))
}

async fn create_user<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<FirewallObjectBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let user = body.into_user_create(None)?;
    let client = state.client.clone();
    let response = run_blocking(move || client.create_user(user)).await?;
    Ok(Json(response.into()))
}

async fn update_user_password<C>(
    State(state): State<AppState<C>>,
    Path(username): Path<String>,
    Json(body): Json<UserPasswordBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response =
        run_blocking(move || client.update_user_password(&username, body.new_password)).await?;
    Ok(Json(response.into()))
}

async fn delete_user<C>(
    State(state): State<AppState<C>>,
    Path(username): Path<String>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let response = run_blocking(move || client.delete_user(&username)).await?;
    Ok(Json(response.into()))
}

async fn get_backup<C>(State(state): State<AppState<C>>) -> ApiResult<SingletonDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let backup = run_blocking(move || client.get_backup()).await?;
    Ok(Json(backup.into()))
}

async fn update_backup<C>(
    State(state): State<AppState<C>>,
    Json(body): Json<BackupUpdateBody>,
) -> ApiResult<ResourceResponseDto>
where
    C: FirewallClient,
{
    let backup = body.into_update()?;
    let client = state.client.clone();
    let response = run_blocking(move || client.update_backup(backup)).await?;
    Ok(Json(response.into()))
}

async fn list_notifications<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let notifications = run_blocking(move || client.list_notifications()).await?;
    Ok(Json(notifications.into_iter().map(Into::into).collect()))
}

async fn get_notification<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let notification = run_blocking(move || client.get_notification(&name)).await?;
    let notification = notification
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("notification not found"))?;
    Ok(Json(notification))
}

async fn list_notification_items<C>(
    State(state): State<AppState<C>>,
) -> ApiResult<Vec<FirewallObjectDto>>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let items = run_blocking(move || client.list_notification_items()).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

async fn get_notification_item<C>(
    State(state): State<AppState<C>>,
    Path(name): Path<String>,
) -> ApiResult<FirewallObjectDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let item = run_blocking(move || client.get_notification_item(&name)).await?;
    let item = item
        .map(Into::into)
        .ok_or_else(|| ApiError::not_found("notification item not found"))?;
    Ok(Json(item))
}

async fn get_reports_retention<C>(State(state): State<AppState<C>>) -> ApiResult<SingletonDto>
where
    C: FirewallClient,
{
    let client = state.client.clone();
    let retention = run_blocking(move || client.get_reports_retention()).await?;
    Ok(Json(retention.into()))
}

async fn run_blocking<R>(
    operation: impl FnOnce() -> sophos_firewall_api::Result<R> + Send + 'static,
) -> std::result::Result<R, ApiError>
where
    R: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| ApiError::internal(format!("worker task failed: {error}")))?
        .map_err(Into::into)
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    code: &'static str,
    message: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        let (status, code) = match error {
            Error::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Error::ZeroRecords { .. } => (StatusCode::NOT_FOUND, "not_found"),
            Error::Transport(_) => (StatusCode::BAD_GATEWAY, "transport_error"),
            Error::ApiError { .. } => (StatusCode::BAD_GATEWAY, "sophos_api_error"),
            Error::ResponseParse(_) => (StatusCode::BAD_GATEWAY, "response_parse_error"),
        };
        Self {
            status,
            code,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ForceQuery {
    force: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsHostEntryBody {
    host_name: Option<String>,
    addresses: Vec<DnsHostAddressBody>,
    #[serde(default)]
    add_reverse_dns_lookup: bool,
}

impl DnsHostEntryBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<DnsHostEntryCreate, ApiError> {
        let host_name = path_name
            .or(self.host_name)
            .ok_or_else(|| Error::InvalidRequest("host_name is required".into()))?;
        let addresses = self
            .addresses
            .into_iter()
            .map(DnsHostAddressBody::try_into_address)
            .collect::<sophos_firewall_api::Result<Vec<_>>>()?;
        Ok(DnsHostEntryCreate::new(host_name, addresses)?
            .with_add_reverse_dns_lookup(self.add_reverse_dns_lookup))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsHostEntryPatch {
    addresses: Option<Vec<DnsHostAddressBody>>,
    add_reverse_dns_lookup: Option<bool>,
}

impl DnsHostEntryPatch {
    fn into_update(self, host_name: String) -> std::result::Result<DnsHostEntryUpdate, ApiError> {
        let mut update = DnsHostEntryUpdate::new(host_name)?;
        if let Some(addresses) = self.addresses {
            update = update.with_addresses(
                addresses
                    .into_iter()
                    .map(DnsHostAddressBody::try_into_address)
                    .collect::<sophos_firewall_api::Result<Vec<_>>>()?,
            )?;
        }
        if let Some(add_reverse_dns_lookup) = self.add_reverse_dns_lookup {
            update = update.with_add_reverse_dns_lookup(add_reverse_dns_lookup);
        }
        Ok(update)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsHostAddressBody {
    #[serde(default = "default_entry_type")]
    entry_type: EntryType,
    ip_family: IpFamily,
    ip_address: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default)]
    weight: u8,
    #[serde(default = "default_publish_on_wan")]
    publish_on_wan: PublishOnWan,
}

impl DnsHostAddressBody {
    fn try_into_address(self) -> sophos_firewall_api::Result<DnsHostAddress> {
        DnsHostAddress::with_options(
            self.entry_type,
            self.ip_family,
            self.ip_address,
            self.ttl,
            self.weight,
            self.publish_on_wan,
        )
    }
}

fn default_entry_type() -> EntryType {
    EntryType::Manual
}

fn default_ttl() -> u32 {
    3600
}

fn default_publish_on_wan() -> PublishOnWan {
    PublishOnWan::Disable
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHostEntryDto {
    host_name: String,
    addresses: Vec<DnsHostAddressDto>,
    add_reverse_dns_lookup: bool,
}

impl From<DnsHostEntryCreate> for DnsHostEntryDto {
    fn from(entry: DnsHostEntryCreate) -> Self {
        Self {
            host_name: entry.host_name().to_string(),
            addresses: entry.addresses().iter().map(Into::into).collect(),
            add_reverse_dns_lookup: entry.add_reverse_dns_lookup(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHostAddressDto {
    entry_type: EntryType,
    ip_family: IpFamily,
    ip_address: String,
    ttl: u32,
    weight: u8,
    publish_on_wan: PublishOnWan,
}

impl From<&DnsHostAddress> for DnsHostAddressDto {
    fn from(address: &DnsHostAddress) -> Self {
        Self {
            entry_type: address.entry_type(),
            ip_family: address.ip_family(),
            ip_address: address.ip_address().to_string(),
            ttl: address.ttl(),
            weight: address.weight(),
            publish_on_wan: address.publish_on_wan(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsMutationDto {
    action: MutationAction,
    response: ResourceResponseDto,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationAction {
    Created,
    Updated,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlGroupBody {
    name: Option<String>,
    domains: Vec<String>,
}

impl UrlGroupBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<UrlGroupCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok(UrlGroupCreate::new(name, self.domains)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlGroupDto {
    name: String,
    domains: Vec<String>,
}

impl From<UrlGroup> for UrlGroupDto {
    fn from(group: UrlGroup) -> Self {
        Self {
            name: group.name().to_string(),
            domains: group.domains().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlGroupDomainsBody {
    action: UrlGroupDomainAction,
    domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UrlGroupDomainAction {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpHostDto {
    name: String,
    ip_address: String,
}

impl From<IpHost> for IpHostDto {
    fn from(host: IpHost) -> Self {
        Self {
            name: host.name().to_string(),
            ip_address: host.ip_address().to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpHostBody {
    name: Option<String>,
    ip_address: String,
}

impl IpHostBody {
    fn into_create(self, path_name: Option<String>) -> std::result::Result<IpHostCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok(IpHostCreate::new(name, self.ip_address)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpNetworkDto {
    name: String,
    ip_address: String,
    subnet: String,
}

impl From<IpNetwork> for IpNetworkDto {
    fn from(network: IpNetwork) -> Self {
        Self {
            name: network.name().to_string(),
            ip_address: network.ip_address().to_string(),
            subnet: network.subnet().to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpNetworkBody {
    name: Option<String>,
    ip_address: String,
    subnet: String,
}

impl IpNetworkBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<IpNetworkCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok(IpNetworkCreate::new(name, self.ip_address, self.subnet)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpRangeDto {
    name: String,
    start_ip: String,
    end_ip: String,
}

impl From<IpRange> for IpRangeDto {
    fn from(range: IpRange) -> Self {
        Self {
            name: range.name().to_string(),
            start_ip: range.start_ip().to_string(),
            end_ip: range.end_ip().to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpRangeBody {
    name: Option<String>,
    start_ip: String,
    end_ip: String,
}

impl IpRangeBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<IpRangeCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok(IpRangeCreate::new(name, self.start_ip, self.end_ip)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkGroupDto {
    name: String,
    hosts: Vec<String>,
    description: Option<String>,
}

impl From<IpHostGroup> for NetworkGroupDto {
    fn from(group: IpHostGroup) -> Self {
        Self {
            name: group.name().to_string(),
            hosts: group.hosts().to_vec(),
            description: group.description().map(ToString::to_string),
        }
    }
}

impl From<FqdnHostGroup> for NetworkGroupDto {
    fn from(group: FqdnHostGroup) -> Self {
        Self {
            name: group.name().to_string(),
            hosts: group.hosts().to_vec(),
            description: group.description().map(ToString::to_string),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkGroupBody {
    name: Option<String>,
    hosts: Vec<String>,
    description: Option<String>,
}

impl NetworkGroupBody {
    fn object_name(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<(String, Vec<String>, Option<String>), ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok((name, self.hosts, self.description))
    }

    fn into_ip_host_group_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<IpHostGroupCreate, ApiError> {
        let (name, hosts, description) = self.object_name(path_name)?;
        let mut group = IpHostGroupCreate::new(name, hosts)?;
        if let Some(description) = description {
            group = group.with_description(description);
        }
        Ok(group)
    }

    fn into_fqdn_host_group_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FqdnHostGroupCreate, ApiError> {
        let (name, hosts, description) = self.object_name(path_name)?;
        let mut group = FqdnHostGroupCreate::new(name, hosts)?;
        if let Some(description) = description {
            group = group.with_description(description);
        }
        Ok(group)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkGroupPatch {
    action: GroupUpdateAction,
    hosts: Vec<String>,
    description: Option<String>,
}

impl NetworkGroupPatch {
    fn into_ip_host_group_update(
        self,
        name: String,
    ) -> std::result::Result<IpHostGroupUpdate, ApiError> {
        let mut group = IpHostGroupUpdate::new(name, self.hosts, self.action.into_network())?;
        if let Some(description) = self.description {
            group = group.with_description(description);
        }
        Ok(group)
    }

    fn into_fqdn_host_group_update(
        self,
        name: String,
    ) -> std::result::Result<FqdnHostGroupUpdate, ApiError> {
        let mut group = FqdnHostGroupUpdate::new(name, self.hosts, self.action.into_network())?;
        if let Some(description) = self.description {
            group = group.with_description(description);
        }
        Ok(group)
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupUpdateAction {
    Add,
    Remove,
    Replace,
}

impl GroupUpdateAction {
    fn into_network(self) -> NetworkGroupUpdateAction {
        match self {
            Self::Add => NetworkGroupUpdateAction::Add,
            Self::Remove => NetworkGroupUpdateAction::Remove,
            Self::Replace => NetworkGroupUpdateAction::Replace,
        }
    }

    fn into_service_group(self) -> ServiceGroupUpdateAction {
        match self {
            Self::Add => ServiceGroupUpdateAction::Add,
            Self::Remove => ServiceGroupUpdateAction::Remove,
            Self::Replace => ServiceGroupUpdateAction::Replace,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FqdnHostDto {
    name: String,
    fqdn: String,
    groups: Vec<String>,
    description: Option<String>,
}

impl From<FqdnHost> for FqdnHostDto {
    fn from(host: FqdnHost) -> Self {
        Self {
            name: host.name().to_string(),
            fqdn: host.fqdn().to_string(),
            groups: host.groups().to_vec(),
            description: host.description().map(ToString::to_string),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FqdnHostBody {
    name: Option<String>,
    fqdn: String,
    #[serde(default)]
    groups: Vec<String>,
    description: Option<String>,
}

impl FqdnHostBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FqdnHostCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        let mut host = FqdnHostCreate::new(name, self.fqdn)?;
        host = host.with_groups(self.groups)?;
        if let Some(description) = self.description {
            host = host.with_description(description);
        }
        Ok(host)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FqdnHostPatch {
    fqdn: Option<String>,
    groups: Option<Vec<String>>,
    description: Option<String>,
}

impl FqdnHostPatch {
    fn into_update(self, name: String) -> std::result::Result<FqdnHostUpdate, ApiError> {
        let mut host = FqdnHostUpdate::new(name)?;
        if let Some(fqdn) = self.fqdn {
            host = host.with_fqdn(fqdn)?;
        }
        if let Some(groups) = self.groups {
            host = host.with_groups(groups)?;
        }
        if let Some(description) = self.description {
            host = host.with_description(description);
        }
        Ok(host)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceDto {
    name: String,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
}

impl From<Service> for ServiceDto {
    fn from(service: Service) -> Self {
        Self {
            name: service.name().to_string(),
            service_type: service.service_type(),
            entries: service.entries().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceBody {
    name: Option<String>,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
}

impl ServiceBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<ServiceCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok(ServiceCreate::new(name, self.service_type, self.entries)?)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServicePatch {
    action: ServiceEntryAction,
    service_type: ServiceType,
    entries: Vec<ServiceEntry>,
}

impl ServicePatch {
    fn into_update(self, name: String) -> std::result::Result<ServiceUpdate, ApiError> {
        Ok(ServiceUpdate::new(
            name,
            self.service_type,
            self.entries,
            self.action.into_service(),
        )?)
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceEntryAction {
    Add,
    Remove,
    Replace,
}

impl ServiceEntryAction {
    fn into_service(self) -> ServiceUpdateAction {
        match self {
            Self::Add => ServiceUpdateAction::Add,
            Self::Remove => ServiceUpdateAction::Remove,
            Self::Replace => ServiceUpdateAction::Replace,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceGroupDto {
    name: String,
    services: Vec<String>,
    description: Option<String>,
}

impl From<ServiceGroup> for ServiceGroupDto {
    fn from(group: ServiceGroup) -> Self {
        Self {
            name: group.name().to_string(),
            services: group.services().to_vec(),
            description: group.description().map(ToString::to_string),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceGroupBody {
    name: Option<String>,
    services: Vec<String>,
    description: Option<String>,
}

impl ServiceGroupBody {
    fn into_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<ServiceGroupCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        let mut group = ServiceGroupCreate::new(name, self.services)?;
        if let Some(description) = self.description {
            group = group.with_description(description);
        }
        Ok(group)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceGroupPatch {
    action: GroupUpdateAction,
    services: Vec<String>,
    description: Option<String>,
}

impl ServiceGroupPatch {
    fn into_update(self, name: String) -> std::result::Result<ServiceGroupUpdate, ApiError> {
        let mut group =
            ServiceGroupUpdate::new(name, self.services, self.action.into_service_group())?;
        if let Some(description) = self.description {
            group = group.with_description(description);
        }
        Ok(group)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallObjectDto {
    name: String,
    fields: Map<String, Value>,
}

impl From<FirewallRule> for FirewallObjectDto {
    fn from(rule: FirewallRule) -> Self {
        Self {
            name: rule.name().to_string(),
            fields: rule.fields().clone(),
        }
    }
}

impl From<FirewallRuleGroup> for FirewallObjectDto {
    fn from(group: FirewallRuleGroup) -> Self {
        Self {
            name: group.name().to_string(),
            fields: group.fields().clone(),
        }
    }
}

macro_rules! raw_object_dto {
    ($type:ty, $name_method:ident) => {
        impl From<$type> for FirewallObjectDto {
            fn from(object: $type) -> Self {
                Self {
                    name: object.$name_method().to_string(),
                    fields: object.fields().clone(),
                }
            }
        }
    };
}

raw_object_dto!(LocalServiceAcl, rule_name);
raw_object_dto!(WebFilterPolicy, name);
raw_object_dto!(UserActivity, name);
raw_object_dto!(Zone, name);
raw_object_dto!(Interface, name);
raw_object_dto!(Vlan, name);
raw_object_dto!(AdminProfile, name);
raw_object_dto!(User, name);
raw_object_dto!(Notification, name);
raw_object_dto!(NotificationList, name);

#[derive(Debug, Clone, Serialize)]
pub struct SingletonDto {
    fields: Map<String, Value>,
}

macro_rules! singleton_dto {
    ($type:ty) => {
        impl From<$type> for SingletonDto {
            fn from(object: $type) -> Self {
                Self {
                    fields: object.fields().clone(),
                }
            }
        }
    };
}

singleton_dto!(DnsForwarders);
singleton_dto!(AdminAuthentication);
singleton_dto!(AdminSettings);
singleton_dto!(Backup);
singleton_dto!(ReportsRetention);

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallObjectBody {
    name: Option<String>,
    #[serde(default)]
    fields: Map<String, Value>,
}

impl FirewallObjectBody {
    fn object_name(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<(String, Map<String, Value>), ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        Ok((name, self.fields))
    }

    fn into_rule_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FirewallRuleCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut rule = FirewallRuleCreate::new(name)?;
        for (field, value) in fields {
            rule = rule.with_field(field, value)?;
        }
        Ok(rule)
    }

    fn into_rule_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FirewallRuleUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut rule = FirewallRuleUpdate::new(name)?;
        for (field, value) in fields {
            rule = rule.with_field(field, value)?;
        }
        Ok(rule)
    }

    fn into_rule_group_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FirewallRuleGroupCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut group = FirewallRuleGroupCreate::new(name)?;
        for (field, value) in fields {
            group = group.with_field(field, value)?;
        }
        Ok(group)
    }

    fn into_rule_group_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<FirewallRuleGroupUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut group = FirewallRuleGroupUpdate::new(name)?;
        for (field, value) in fields {
            group = group.with_field(field, value)?;
        }
        Ok(group)
    }

    fn into_acl_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<LocalServiceAclCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut acl = LocalServiceAclCreate::new(name)?;
        for (field, value) in fields {
            acl = acl.with_field(field, value)?;
        }
        Ok(acl)
    }

    fn into_acl_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<LocalServiceAclUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut acl = LocalServiceAclUpdate::new(name)?;
        for (field, value) in fields {
            acl = acl.with_field(field, value)?;
        }
        Ok(acl)
    }

    fn into_webfilter_policy_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<WebFilterPolicyCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut policy = WebFilterPolicyCreate::new(name)?;
        for (field, value) in fields {
            policy = policy.with_field(field, value)?;
        }
        Ok(policy)
    }

    fn into_webfilter_policy_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<WebFilterPolicyUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut policy = WebFilterPolicyUpdate::new(name)?;
        for (field, value) in fields {
            policy = policy.with_field(field, value)?;
        }
        Ok(policy)
    }

    fn into_user_activity_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<UserActivityCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut activity = UserActivityCreate::new(name)?;
        for (field, value) in fields {
            activity = activity.with_field(field, value)?;
        }
        Ok(activity)
    }

    fn into_zone_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<ZoneUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut zone = ZoneUpdate::new(name)?;
        for (field, value) in fields {
            zone = zone.with_field(field, value)?;
        }
        Ok(zone)
    }

    fn into_admin_profile_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<AdminProfileCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut profile = AdminProfileCreate::new(name)?;
        for (field, value) in fields {
            profile = profile.with_field(field, value)?;
        }
        Ok(profile)
    }

    fn into_admin_profile_update(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<AdminProfileUpdate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut profile = AdminProfileUpdate::new(name)?;
        for (field, value) in fields {
            profile = profile.with_field(field, value)?;
        }
        Ok(profile)
    }

    fn into_user_create(
        self,
        path_name: Option<String>,
    ) -> std::result::Result<UserCreate, ApiError> {
        let (name, fields) = self.object_name(path_name)?;
        let mut user = UserCreate::new(name)?;
        for (field, value) in fields {
            user = user.with_field(field, value)?;
        }
        Ok(user)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZoneBody {
    name: Option<String>,
    zone_type: String,
    #[serde(default)]
    fields: Map<String, Value>,
}

impl ZoneBody {
    fn into_create(self, path_name: Option<String>) -> std::result::Result<ZoneCreate, ApiError> {
        let name = path_name
            .or(self.name)
            .ok_or_else(|| Error::InvalidRequest("name is required".into()))?;
        let mut zone = ZoneCreate::new(name, self.zone_type)?;
        for (field, value) in self.fields {
            zone = zone.with_field(field, value)?;
        }
        Ok(zone)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserPasswordBody {
    new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupUpdateBody {
    #[serde(default)]
    schedule_fields: Map<String, Value>,
}

impl BackupUpdateBody {
    fn into_update(self) -> std::result::Result<BackupUpdate, ApiError> {
        let mut update = BackupUpdate::new();
        for (field, value) in self.schedule_fields {
            update = update.with_schedule_field(field, value)?;
        }
        Ok(update)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceResponseDto {
    resource: String,
    status_code: Option<String>,
    status: String,
}

impl From<ResourceResponse> for ResourceResponseDto {
    fn from(response: ResourceResponse) -> Self {
        Self {
            resource: response.name,
            status_code: response.status.code,
            status: response.status.text,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use pretty_assertions::assert_eq;
    use serde_json::Value;
    use sophos_firewall_api::ResourceStatus;
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone, Default)]
    struct FakeClient {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl FakeClient {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }

        fn record(&self, call: impl Into<String>) {
            self.calls.lock().expect("calls lock").push(call.into());
        }
    }

    impl FirewallClient for FakeClient {
        fn list_dns_entries(&self) -> sophos_firewall_api::Result<Vec<DnsHostEntryCreate>> {
            self.record("list_dns_entries");
            Ok(vec![DnsHostEntryCreate::new(
                "app.local",
                vec![DnsHostAddress::new(
                    EntryType::Manual,
                    IpFamily::IPv4,
                    "10.0.0.10",
                )?],
            )?])
        }

        fn get_dns_entry(
            &self,
            host_name: &str,
        ) -> sophos_firewall_api::Result<Option<DnsHostEntryCreate>> {
            self.record(format!("get_dns_entry:{host_name}"));
            Ok(None)
        }

        fn add_dns_entry(
            &self,
            entry: DnsHostEntryCreate,
            force: bool,
        ) -> sophos_firewall_api::Result<DnsMutationDto> {
            self.record(format!("add_dns_entry:{}:{force}", entry.host_name()));
            Ok(DnsMutationDto {
                action: MutationAction::Created,
                response: ok_response("DNSHostEntry").into(),
            })
        }

        fn update_dns_entry(
            &self,
            entry: DnsHostEntryUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("update_dns_entry:{}", entry.host_name()));
            Ok(ok_response("DNSHostEntry"))
        }

        fn delete_dns_entry(
            &self,
            host_name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("delete_dns_entry:{host_name}"));
            Ok(ok_response("DNSHostEntry"))
        }

        fn list_url_groups(&self) -> sophos_firewall_api::Result<Vec<UrlGroup>> {
            self.record("list_url_groups");
            Ok(Vec::new())
        }

        fn get_url_group(&self, name: &str) -> sophos_firewall_api::Result<Option<UrlGroup>> {
            self.record(format!("get_url_group:{name}"));
            Ok(None)
        }

        fn create_url_group(
            &self,
            group: UrlGroupCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("create_url_group:{}", group.name()));
            Ok(ok_response("WebFilterURLGroup"))
        }

        fn update_url_group_domains(
            &self,
            name: &str,
            action: UrlGroupDomainAction,
            domains: Vec<String>,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            let action = match action {
                UrlGroupDomainAction::Add => "add",
                UrlGroupDomainAction::Remove => "remove",
                UrlGroupDomainAction::Replace => "replace",
            };
            self.record(format!(
                "update_url_group_domains:{name}:{action}:{}",
                domains.join(",")
            ));
            Ok(ok_response("WebFilterURLGroup"))
        }

        fn delete_url_group(&self, name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("delete_url_group:{name}"));
            Ok(ok_response("WebFilterURLGroup"))
        }

        fn list_firewall_rules(&self) -> sophos_firewall_api::Result<Vec<FirewallRule>> {
            self.record("list_firewall_rules");
            Ok(Vec::new())
        }

        fn get_firewall_rule(
            &self,
            name: &str,
        ) -> sophos_firewall_api::Result<Option<FirewallRule>> {
            self.record(format!("get_firewall_rule:{name}"));
            Ok(None)
        }

        fn create_firewall_rule(
            &self,
            rule: FirewallRuleCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("create_firewall_rule:{}", rule.name()));
            Ok(ok_response("FirewallRule"))
        }

        fn update_firewall_rule(
            &self,
            rule: FirewallRuleUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("update_firewall_rule:{}", rule.name()));
            Ok(ok_response("FirewallRule"))
        }

        fn delete_firewall_rule(
            &self,
            name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("delete_firewall_rule:{name}"));
            Ok(ok_response("FirewallRule"))
        }

        fn list_firewall_rule_groups(&self) -> sophos_firewall_api::Result<Vec<FirewallRuleGroup>> {
            self.record("list_firewall_rule_groups");
            Ok(Vec::new())
        }

        fn get_firewall_rule_group(
            &self,
            name: &str,
        ) -> sophos_firewall_api::Result<Option<FirewallRuleGroup>> {
            self.record(format!("get_firewall_rule_group:{name}"));
            Ok(None)
        }

        fn create_firewall_rule_group(
            &self,
            group: FirewallRuleGroupCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("create_firewall_rule_group:{}", group.name()));
            Ok(ok_response("FirewallRuleGroup"))
        }

        fn update_firewall_rule_group(
            &self,
            group: FirewallRuleGroupUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("update_firewall_rule_group:{}", group.name()));
            Ok(ok_response("FirewallRuleGroup"))
        }

        fn delete_firewall_rule_group(
            &self,
            name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("delete_firewall_rule_group:{name}"));
            Ok(ok_response("FirewallRuleGroup"))
        }
        fn list_ip_hosts(&self) -> sophos_firewall_api::Result<Vec<IpHost>> {
            unsupported()
        }
        fn get_ip_host(&self, _name: &str) -> sophos_firewall_api::Result<Option<IpHost>> {
            unsupported()
        }
        fn create_ip_host(
            &self,
            host: IpHostCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("create_ip_host:{}", host.name()));
            Ok(ok_response("IPHost"))
        }
        fn update_ip_host(
            &self,
            _host: IpHostCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_ip_host(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_ip_networks(&self) -> sophos_firewall_api::Result<Vec<IpNetwork>> {
            unsupported()
        }
        fn get_ip_network(&self, _name: &str) -> sophos_firewall_api::Result<Option<IpNetwork>> {
            unsupported()
        }
        fn create_ip_network(
            &self,
            _network: IpNetworkCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_ip_network(
            &self,
            _network: IpNetworkCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_ip_network(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_ip_ranges(&self) -> sophos_firewall_api::Result<Vec<IpRange>> {
            unsupported()
        }
        fn get_ip_range(&self, _name: &str) -> sophos_firewall_api::Result<Option<IpRange>> {
            unsupported()
        }
        fn create_ip_range(
            &self,
            _range: IpRangeCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_ip_range(
            &self,
            _range: IpRangeCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_ip_range(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_ip_host_groups(&self) -> sophos_firewall_api::Result<Vec<IpHostGroup>> {
            unsupported()
        }
        fn get_ip_host_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<IpHostGroup>> {
            unsupported()
        }
        fn create_ip_host_group(
            &self,
            _group: IpHostGroupCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_ip_host_group(
            &self,
            _group: IpHostGroupUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_ip_host_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_fqdn_hosts(&self) -> sophos_firewall_api::Result<Vec<FqdnHost>> {
            unsupported()
        }
        fn get_fqdn_host(&self, _name: &str) -> sophos_firewall_api::Result<Option<FqdnHost>> {
            unsupported()
        }
        fn create_fqdn_host(
            &self,
            _host: FqdnHostCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_fqdn_host(
            &self,
            _host: FqdnHostUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_fqdn_host(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_fqdn_host_groups(&self) -> sophos_firewall_api::Result<Vec<FqdnHostGroup>> {
            unsupported()
        }
        fn get_fqdn_host_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<FqdnHostGroup>> {
            unsupported()
        }
        fn create_fqdn_host_group(
            &self,
            _group: FqdnHostGroupCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_fqdn_host_group(
            &self,
            _group: FqdnHostGroupUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_fqdn_host_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_services(&self) -> sophos_firewall_api::Result<Vec<Service>> {
            unsupported()
        }
        fn get_service(&self, _name: &str) -> sophos_firewall_api::Result<Option<Service>> {
            unsupported()
        }
        fn create_service(
            &self,
            _service: ServiceCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_service(
            &self,
            _service: ServiceUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_service(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_service_groups(&self) -> sophos_firewall_api::Result<Vec<ServiceGroup>> {
            unsupported()
        }
        fn get_service_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<ServiceGroup>> {
            unsupported()
        }
        fn create_service_group(
            &self,
            _group: ServiceGroupCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_service_group(
            &self,
            _group: ServiceGroupUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record("update_service_group");
            Ok(ok_response("ServiceGroup"))
        }
        fn delete_service_group(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_acl_rules(&self) -> sophos_firewall_api::Result<Vec<LocalServiceAcl>> {
            unsupported()
        }
        fn get_acl_rule(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<LocalServiceAcl>> {
            unsupported()
        }
        fn create_acl_rule(
            &self,
            _acl: LocalServiceAclCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_acl_rule(
            &self,
            _acl: LocalServiceAclUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_acl_rule(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_webfilter_policies(&self) -> sophos_firewall_api::Result<Vec<WebFilterPolicy>> {
            unsupported()
        }
        fn get_webfilter_policy(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<WebFilterPolicy>> {
            unsupported()
        }
        fn create_webfilter_policy(
            &self,
            _policy: WebFilterPolicyCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_webfilter_policy(
            &self,
            _policy: WebFilterPolicyUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_webfilter_policy(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_user_activities(&self) -> sophos_firewall_api::Result<Vec<UserActivity>> {
            unsupported()
        }
        fn get_user_activity(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<UserActivity>> {
            unsupported()
        }
        fn create_user_activity(
            &self,
            _activity: UserActivityCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_user_activity(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_zones(&self) -> sophos_firewall_api::Result<Vec<Zone>> {
            unsupported()
        }
        fn get_zone(&self, _name: &str) -> sophos_firewall_api::Result<Option<Zone>> {
            unsupported()
        }
        fn create_zone(&self, _zone: ZoneCreate) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_zone(&self, _zone: ZoneUpdate) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_zone(&self, _name: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn list_interfaces(&self) -> sophos_firewall_api::Result<Vec<Interface>> {
            unsupported()
        }
        fn get_interface(&self, _name: &str) -> sophos_firewall_api::Result<Option<Interface>> {
            unsupported()
        }
        fn list_vlans(&self) -> sophos_firewall_api::Result<Vec<Vlan>> {
            unsupported()
        }
        fn get_vlan(&self, _name: &str) -> sophos_firewall_api::Result<Option<Vlan>> {
            unsupported()
        }
        fn get_dns_forwarders(&self) -> sophos_firewall_api::Result<DnsForwarders> {
            unsupported()
        }
        fn list_admin_profiles(&self) -> sophos_firewall_api::Result<Vec<AdminProfile>> {
            unsupported()
        }
        fn get_admin_profile(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<AdminProfile>> {
            unsupported()
        }
        fn create_admin_profile(
            &self,
            _profile: AdminProfileCreate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_admin_profile(
            &self,
            _profile: AdminProfileUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn delete_admin_profile(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn get_admin_authentication(&self) -> sophos_firewall_api::Result<AdminAuthentication> {
            unsupported()
        }
        fn get_admin_settings(&self) -> sophos_firewall_api::Result<AdminSettings> {
            unsupported()
        }
        fn list_users(&self) -> sophos_firewall_api::Result<Vec<User>> {
            unsupported()
        }
        fn get_user(&self, _username: &str) -> sophos_firewall_api::Result<Option<User>> {
            unsupported()
        }
        fn create_user(&self, _user: UserCreate) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn update_user_password(
            &self,
            username: &str,
            _new_password: String,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record(format!("update_user_password:{username}"));
            Ok(ok_response("User"))
        }
        fn delete_user(&self, _username: &str) -> sophos_firewall_api::Result<ResourceResponse> {
            unsupported()
        }
        fn get_backup(&self) -> sophos_firewall_api::Result<Backup> {
            unsupported()
        }
        fn update_backup(
            &self,
            _backup: BackupUpdate,
        ) -> sophos_firewall_api::Result<ResourceResponse> {
            self.record("update_backup");
            Ok(ok_response("BackupRestore"))
        }
        fn list_notifications(&self) -> sophos_firewall_api::Result<Vec<Notification>> {
            unsupported()
        }
        fn get_notification(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<Notification>> {
            unsupported()
        }
        fn list_notification_items(&self) -> sophos_firewall_api::Result<Vec<NotificationList>> {
            unsupported()
        }
        fn get_notification_item(
            &self,
            _name: &str,
        ) -> sophos_firewall_api::Result<Option<NotificationList>> {
            unsupported()
        }
        fn get_reports_retention(&self) -> sophos_firewall_api::Result<ReportsRetention> {
            unsupported()
        }
    }

    fn unsupported<T>() -> sophos_firewall_api::Result<T> {
        Err(Error::InvalidRequest(
            "test fake does not implement this web route".to_string(),
        ))
    }

    fn ok_response(resource: &str) -> ResourceResponse {
        ResourceResponse {
            name: resource.to_string(),
            status: ResourceStatus {
                code: Some("200".to_string()),
                text: "Configuration applied successfully.".to_string(),
            },
            body_xml: String::new(),
        }
    }

    fn app(client: FakeClient) -> Router {
        routes(AppState::new(client))
    }

    async fn json_request(app: Router, method: &str, uri: &str, body: &str) -> (StatusCode, Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = serde_json::from_slice(&bytes).expect("json body");
        (status, body)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (status, body) = json_request(app(FakeClient::default()), "GET", "/health", "").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn dns_list_uses_client_and_returns_validated_dto() {
        let client = FakeClient::default();
        let (status, body) =
            json_request(app(client.clone()), "GET", "/v1/dns/host-entries", "").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[0]["host_name"], "app.local");
        assert_eq!(body[0]["addresses"][0]["ip_address"], "10.0.0.10");
        assert_eq!(client.calls(), vec!["list_dns_entries"]);
    }

    #[tokio::test]
    async fn dns_upsert_takes_name_from_path_and_forces_update() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PUT",
            "/v1/dns/host-entries/web.local",
            r#"{
                "addresses": [
                    { "ip_family": "IPv4", "ip_address": "10.0.0.20" }
                ]
            }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["action"], "created");
        assert_eq!(client.calls(), vec!["add_dns_entry:web.local:true"]);
    }

    #[tokio::test]
    async fn url_group_domain_patch_maps_operation() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PATCH",
            "/v1/url-groups/kids/domains",
            r#"{ "action": "add", "domains": ["example.com"] }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "WebFilterURLGroup");
        assert_eq!(
            client.calls(),
            vec!["update_url_group_domains:kids:add:example.com"]
        );
    }

    #[tokio::test]
    async fn firewall_rule_patch_passes_path_name_and_fields() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PATCH",
            "/v1/firewall/rules/allow-web",
            r#"{ "fields": { "Status": "Disable" } }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "FirewallRule");
        assert_eq!(client.calls(), vec!["update_firewall_rule:allow-web"]);
    }

    #[tokio::test]
    async fn network_ip_host_create_uses_typed_body() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "POST",
            "/v1/network/ip-hosts",
            r#"{ "name": "app-host", "ip_address": "10.0.0.30" }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "IPHost");
        assert_eq!(client.calls(), vec!["create_ip_host:app-host"]);
    }

    #[tokio::test]
    async fn service_group_patch_maps_membership_action() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PATCH",
            "/v1/service-groups/web-services",
            r#"{ "action": "add", "services": ["HTTPS"] }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "ServiceGroup");
        assert_eq!(client.calls(), vec!["update_service_group"]);
    }

    #[tokio::test]
    async fn user_password_patch_uses_path_username() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PATCH",
            "/v1/users/alice/password",
            r#"{ "new_password": "correct-horse" }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "User");
        assert_eq!(client.calls(), vec!["update_user_password:alice"]);
    }

    #[tokio::test]
    async fn system_backup_patch_wraps_schedule_fields() {
        let client = FakeClient::default();
        let (status, body) = json_request(
            app(client.clone()),
            "PATCH",
            "/v1/system/backup",
            r#"{ "schedule_fields": { "BackupMode": "Local" } }"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"], "BackupRestore");
        assert_eq!(client.calls(), vec!["update_backup"]);
    }
}
