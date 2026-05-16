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
    DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate, DnsMutationAction, EntryType, Error,
    FirewallRule, FirewallRuleCreate, FirewallRuleGroup, FirewallRuleGroupCreate,
    FirewallRuleGroupUpdate, FirewallRuleUpdate, IpFamily, PublishOnWan, ResourceResponse,
    SophosClient, SophosConnection, SophosTransport, UrlGroup, UrlGroupCreate,
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
}
