use std::time::Duration;

use crate::{Error, Result, SophosConnection, SophosTransport};

/// Blocking reqwest-backed transport for the Sophos Firewall XML API.
///
/// Enable with the `blocking-http` feature. The transport posts the XML payload
/// as Sophos expects: form data field `reqxml=<request_xml>` with
/// `Accept: application/xml`.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::blocking::Client,
}

impl HttpTransport {
    /// Default network timeout, matching the Python SDK's 30 second timeout.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Build a transport from connection settings.
    ///
    /// `connection.verify_tls` controls whether invalid TLS certificates are
    /// rejected. Use the default unless you are talking to a lab firewall with a
    /// self-signed certificate and have accepted that risk.
    pub fn from_connection(connection: &SophosConnection) -> Result<Self> {
        Self::with_timeout(connection, Self::DEFAULT_TIMEOUT)
    }

    /// Build a transport with an explicit request timeout.
    pub fn with_timeout(connection: &SophosConnection, timeout: Duration) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(!connection.verify_tls)
            .build()
            .map_err(|error| transport_error("failed to build HTTP client", error))?;

        Ok(Self { client })
    }
}

impl SophosTransport for HttpTransport {
    fn send_xml(&self, api_url: &str, request_xml: &str) -> Result<String> {
        let response = self
            .client
            .post(api_url)
            .header(reqwest::header::ACCEPT, "application/xml")
            .form(&[("reqxml", request_xml)])
            .send()
            .map_err(|error| transport_error("HTTP request failed", error))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transport(format!(
                "HTTP status {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("unknown")
            )));
        }

        response
            .text()
            .map_err(|error| transport_error("HTTP response read failed", error))
    }
}

fn transport_error(context: &str, error: reqwest::Error) -> Error {
    Error::Transport(format!("{context}: {}", error.without_url()))
}
