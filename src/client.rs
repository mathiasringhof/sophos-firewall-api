use crate::{
    Result, SophosConnection, SophosRequest, SophosResponse, SophosTransport, build_request_xml,
    parse_response_xml,
};

/// Sophos API client that owns connection settings and transport.
#[derive(Debug, Clone)]
pub struct SophosClient<T> {
    connection: SophosConnection,
    transport: T,
}

impl<T> SophosClient<T> {
    pub fn new(connection: SophosConnection, transport: T) -> Self {
        Self {
            connection,
            transport,
        }
    }

    pub fn connection(&self) -> &SophosConnection {
        &self.connection
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn execute(&self, request: &SophosRequest) -> Result<SophosResponse> {
        let request_xml = build_request_xml(&self.connection, request)?;
        let response_xml = self
            .transport
            .send_xml(&self.connection.api_url(), &request_xml)?;
        parse_response_xml(&response_xml)
    }
}
