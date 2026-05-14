//! Sophos Firewall API primitives.
//!
//! This crate is intentionally library-only. Web servers and CLIs should consume
//! this crate instead of duplicating Sophos API and authorization behavior.

mod authz;
mod client;
mod request;
mod resources;
mod response;
mod transport;
mod xml;

pub use authz::{AuthorizationPolicy, AuthorizationRule, Decision, ObjectScope};
pub use client::SophosClient;
pub use request::{Action, SophosConnection, SophosRequest};
pub use resources::dns::{
    DnsApi, DnsBulkMutationResult, DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate,
    DnsMutationAction, DnsMutationOutcome, EntryType, IpFamily, PublishOnWan,
};
pub use resources::service::{UrlGroup, UrlGroupCreate, UrlGroupsApi};
pub use response::{ResourceResponse, ResourceStatus, SophosResponse, parse_response_xml};
pub use transport::SophosTransport;
pub use xml::build_request_xml;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("response parse error: {0}")]
    ResponseParse(String),
    #[error("zero records for {resource}")]
    ZeroRecords { resource: String },
    #[error("Sophos API error for {resource}: {code:?} {message}")]
    ApiError {
        resource: String,
        code: Option<String>,
        message: String,
    },
    #[error("transport error: {0}")]
    Transport(String),
}
