//! Sophos Firewall API primitives.
//!
//! This crate is intentionally library-only. Web servers and CLIs should consume
//! this crate instead of duplicating Sophos API and authorization behavior.

mod authz;
mod request;
mod xml;

pub use authz::{AuthorizationPolicy, AuthorizationRule, Decision, ObjectScope};
pub use request::{Action, SophosConnection, SophosRequest};
pub use xml::build_request_xml;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}
