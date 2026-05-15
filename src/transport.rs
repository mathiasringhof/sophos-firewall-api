use crate::Result;

/// Minimal transport seam for Sophos XML requests.
///
/// The trait is synchronous to keep XML/response tests deterministic and to
/// match the optional blocking HTTP transport.
pub trait SophosTransport {
    fn send_xml(&self, api_url: &str, request_xml: &str) -> Result<String>;
}
