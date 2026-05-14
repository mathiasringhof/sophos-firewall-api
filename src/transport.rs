use crate::Result;

/// Minimal transport seam for Sophos XML requests.
///
/// The trait is synchronous for this first slice because there is no live HTTP
/// implementation yet. Keeping it tiny makes authorization/XML/response tests
/// deterministic and lets a future reqwest-backed transport choose its async
/// shape when we actually add network I/O.
pub trait SophosTransport {
    fn send_xml(&self, api_url: &str, request_xml: &str) -> Result<String>;
}
