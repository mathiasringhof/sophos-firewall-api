use serde_json::Value;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

use super::common::{
    ApiObject, ObjectFields, first_named_resource, merge_fields, normalize_name,
    objects_from_response, payload_with_key,
};

const WEB_FILTER_POLICY_RESOURCE: &str = "WebFilterPolicy";
const USER_ACTIVITY_RESOURCE: &str = "UserActivity";
const NAME_KEY: &str = "Name";

macro_rules! object_wrapper {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            inner: ApiObject,
        }

        impl $name {
            fn new(inner: ApiObject) -> Self {
                Self { inner }
            }

            pub fn name(&self) -> &str {
                self.inner.name()
            }

            pub fn field(&self, path: &str) -> Option<&str> {
                self.inner.field(path)
            }

            pub fn fields(&self) -> &serde_json::Map<String, Value> {
                self.inner.fields()
            }
        }
    };
}

macro_rules! payload_wrapper {
    ($create:ident, $update:ident, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $create {
            inner: ObjectFields,
        }

        impl $create {
            pub fn new(name: impl AsRef<str>) -> Result<Self> {
                Ok(Self {
                    inner: ObjectFields::new($label, name)?,
                })
            }

            pub fn name(&self) -> &str {
                self.inner.name()
            }

            pub fn with_field(
                mut self,
                field: impl AsRef<str>,
                value: impl Into<Value>,
            ) -> Result<Self> {
                self.inner = self.inner.with_field(field, value)?;
                Ok(self)
            }

            pub fn into_update(self) -> $update {
                $update { inner: self.inner }
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $update {
            inner: ObjectFields,
        }

        impl $update {
            pub fn new(name: impl AsRef<str>) -> Result<Self> {
                Ok(Self {
                    inner: ObjectFields::new($label, name)?,
                })
            }

            pub fn name(&self) -> &str {
                self.inner.name()
            }

            pub fn with_field(
                mut self,
                field: impl AsRef<str>,
                value: impl Into<Value>,
            ) -> Result<Self> {
                self.inner = self.inner.with_field(field, value)?;
                Ok(self)
            }
        }
    };
}

object_wrapper!(WebFilterPolicy);
object_wrapper!(UserActivity);
payload_wrapper!(
    WebFilterPolicyCreate,
    WebFilterPolicyUpdate,
    "web filter policy name"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserActivityCreate {
    inner: ObjectFields,
}

impl UserActivityCreate {
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: ObjectFields::new("user activity name", name)?,
        })
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn with_field(mut self, field: impl AsRef<str>, value: impl Into<Value>) -> Result<Self> {
        self.inner = self.inner.with_field(field, value)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WebFilterApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn webfilter(&self) -> WebFilterApi<'_, T> {
        WebFilterApi { client: self }
    }
}

impl<T> WebFilterApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_policies(&self) -> Result<Vec<WebFilterPolicy>> {
        list_objects(
            self.client,
            WEB_FILTER_POLICY_RESOURCE,
            NAME_KEY,
            "web filter policy name",
            WebFilterPolicy::new,
        )
    }

    pub fn get_policy(&self, name: impl AsRef<str>) -> Result<Option<WebFilterPolicy>> {
        get_object(
            self.client,
            WEB_FILTER_POLICY_RESOURCE,
            NAME_KEY,
            "web filter policy name",
            name,
            WebFilterPolicy::new,
        )
    }

    pub fn create_policy(&self, policy: WebFilterPolicyCreate) -> Result<ResourceResponse> {
        create_object(
            self.client,
            WEB_FILTER_POLICY_RESOURCE,
            NAME_KEY,
            policy.inner,
        )
    }

    pub fn update_policy(&self, policy: WebFilterPolicyUpdate) -> Result<ResourceResponse> {
        let (name, fields) = policy.inner.into_parts();
        let existing = self.get_policy(&name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("web filter policy '{name}' does not exist"))
        })?;
        update_object(
            self.client,
            WEB_FILTER_POLICY_RESOURCE,
            NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_policy(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("web filter policy name", name.as_ref())?;
        if self.get_policy(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "web filter policy '{name}' does not exist"
            )));
        }
        delete_object(self.client, WEB_FILTER_POLICY_RESOURCE, NAME_KEY, &name)
    }

    pub fn list_user_activities(&self) -> Result<Vec<UserActivity>> {
        list_objects(
            self.client,
            USER_ACTIVITY_RESOURCE,
            NAME_KEY,
            "user activity name",
            UserActivity::new,
        )
    }

    pub fn get_user_activity(&self, name: impl AsRef<str>) -> Result<Option<UserActivity>> {
        get_object(
            self.client,
            USER_ACTIVITY_RESOURCE,
            NAME_KEY,
            "user activity name",
            name,
            UserActivity::new,
        )
    }

    pub fn create_user_activity(&self, activity: UserActivityCreate) -> Result<ResourceResponse> {
        create_object(
            self.client,
            USER_ACTIVITY_RESOURCE,
            NAME_KEY,
            activity.inner,
        )
    }

    pub fn delete_user_activity(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("user activity name", name.as_ref())?;
        if self.get_user_activity(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "user activity '{name}' does not exist"
            )));
        }
        delete_object(self.client, USER_ACTIVITY_RESOURCE, NAME_KEY, &name)
    }
}

fn list_objects<T, O>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    label: &str,
    wrap: impl Fn(ApiObject) -> O,
) -> Result<Vec<O>>
where
    T: SophosTransport,
{
    match client.execute(&SophosRequest::read(resource)) {
        Ok(response) => Ok(
            objects_from_response(&response.resources, resource, key, label)?
                .into_iter()
                .map(wrap)
                .collect(),
        ),
        Err(Error::ZeroRecords {
            resource: empty_resource,
        }) if empty_resource == resource => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn get_object<T, O>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    label: &str,
    name: impl AsRef<str>,
    wrap: impl Fn(ApiObject) -> O,
) -> Result<Option<O>>
where
    T: SophosTransport,
{
    let name = normalize_name(label, name.as_ref())?;
    let request = SophosRequest::read(resource)
        .for_object(name.clone())
        .with_object_key(key);

    match client.execute(&request) {
        Ok(response) => Ok(
            objects_from_response(&response.resources, resource, key, label)?
                .into_iter()
                .find(|object| object.name() == name)
                .map(wrap),
        ),
        Err(Error::ZeroRecords {
            resource: empty_resource,
        }) if empty_resource == resource => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    fields: ObjectFields,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    let request = SophosRequest::new(Action::Create, resource)
        .for_object(fields.name())
        .with_object_key(key)
        .with_payload(payload_with_key(key, fields.name(), fields.fields()));
    first_named_resource(client.execute(&request)?.resources, resource)
}

fn update_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    name: &str,
    mut existing: serde_json::Map<String, Value>,
    updates: serde_json::Map<String, Value>,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    merge_fields(&mut existing, updates);
    let request = SophosRequest::new(Action::Update, resource)
        .for_object(name)
        .with_object_key(key)
        .with_payload(payload_with_key(key, name, &existing));
    first_named_resource(client.execute(&request)?.resources, resource)
}

fn delete_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    name: &str,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    let request = SophosRequest::new(Action::Delete, resource)
        .for_object(name)
        .with_object_key(key);
    first_named_resource(client.execute(&request)?.resources, resource)
}
