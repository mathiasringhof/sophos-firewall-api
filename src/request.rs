use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Read,
    Create,
    Update,
    Delete,
}

impl Action {
    pub fn is_change(self) -> bool {
        matches!(self, Self::Create | Self::Update | Self::Delete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SophosConnection {
    pub host: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub verify_tls: bool,
}

impl SophosConnection {
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            username: username.into(),
            password: password.into(),
            port: 4444,
            verify_tls: true,
        }
    }

    pub fn api_url(&self) -> String {
        format!(
            "https://{}:{}/webconsole/APIController",
            self.host, self.port
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SophosRequest {
    pub action: Action,
    pub resource: String,
    pub object_name: Option<String>,
    #[serde(default)]
    pub object_key: Option<String>,
    #[serde(default)]
    pub set_operation: Option<String>,
    pub payload: Value,
}

impl SophosRequest {
    pub fn new(action: Action, resource: impl Into<String>) -> Self {
        Self {
            action,
            resource: resource.into(),
            object_name: None,
            object_key: None,
            set_operation: None,
            payload: Value::Object(Default::default()),
        }
    }

    pub fn read(resource: impl Into<String>) -> Self {
        Self::new(Action::Read, resource)
    }

    pub fn update(resource: impl Into<String>, object_name: impl Into<String>) -> Self {
        Self::new(Action::Update, resource).for_object(object_name)
    }

    pub fn for_object(mut self, object_name: impl Into<String>) -> Self {
        self.object_name = Some(object_name.into());
        self
    }

    pub fn with_object_key(mut self, object_key: impl Into<String>) -> Self {
        self.object_key = Some(object_key.into());
        self
    }

    pub fn with_set_operation(mut self, operation: impl Into<String>) -> Self {
        self.set_operation = Some(operation.into());
        self
    }

    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }
}
