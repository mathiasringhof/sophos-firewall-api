use crate::{
    AuthorizationPolicy, Result, SophosConnection, SophosRequest, SophosResponse, SophosTransport,
    build_request_xml, parse_response_xml,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationContext {
    subject: String,
    policy: AuthorizationPolicy,
}

/// Sophos API client that owns connection settings, transport, and optional authorization.
#[derive(Debug, Clone)]
pub struct SophosClient<T> {
    connection: SophosConnection,
    transport: T,
    authorization: Option<AuthorizationContext>,
}

impl<T> SophosClient<T> {
    pub fn new(connection: SophosConnection, transport: T) -> Self {
        Self {
            connection,
            transport,
            authorization: None,
        }
    }

    pub fn with_authorization(
        mut self,
        subject: impl Into<String>,
        policy: AuthorizationPolicy,
    ) -> Self {
        self.authorization = Some(AuthorizationContext {
            subject: subject.into(),
            policy,
        });
        self
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
        if let Some(authorization) = &self.authorization {
            authorization
                .policy
                .authorize(&authorization.subject, request)?;
        }

        let request_xml = build_request_xml(&self.connection, request)?;
        let response_xml = self
            .transport
            .send_xml(&self.connection.api_url(), &request_xml)?;
        parse_response_xml(&response_xml)
    }
}
