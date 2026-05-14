use serde_json::Value;

use crate::{Error, ResourceResponse, Result, SophosClient, SophosTransport};

use super::common::{
    ApiObject, FieldMap, ObjectFields, create_object, delete_object, get_object, list_objects,
    normalize_name, update_object, validated_field,
};

const USER_RESOURCE: &str = "User";
const NAME_KEY: &str = "Name";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    inner: ApiObject,
}

impl User {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCreate {
    inner: ObjectFields,
}

impl UserCreate {
    pub fn new(username: impl AsRef<str>) -> Result<Self> {
        let username = normalize_name("username", username.as_ref())?;
        Ok(Self {
            inner: ObjectFields::new("username", &username)?.with_field("Username", username)?,
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
pub struct UsersApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn users(&self) -> UsersApi<'_, T> {
        UsersApi { client: self }
    }
}

impl<T> UsersApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_users(&self) -> Result<Vec<User>> {
        list_objects(self.client, USER_RESOURCE, NAME_KEY, "user", User::new)
    }

    pub fn get_user(&self, username: impl AsRef<str>) -> Result<Option<User>> {
        get_object(
            self.client,
            USER_RESOURCE,
            NAME_KEY,
            "user",
            username,
            User::new,
        )
    }

    pub fn create_user(&self, user: UserCreate) -> Result<ResourceResponse> {
        create_object(self.client, USER_RESOURCE, NAME_KEY, user.inner)
    }

    pub fn update_password(
        &self,
        username: impl AsRef<str>,
        new_password: impl AsRef<str>,
    ) -> Result<ResourceResponse> {
        let username = normalize_name("user", username.as_ref())?;
        let password = normalize_name("password", new_password.as_ref())?;
        let existing = self
            .get_user(&username)?
            .ok_or_else(|| Error::InvalidRequest(format!("user '{username}' does not exist")))?;
        let mut updates = FieldMap::new();
        let (field, value) = validated_field("Password", password)?;
        updates.insert(field, value);
        update_object(
            self.client,
            USER_RESOURCE,
            NAME_KEY,
            &username,
            existing.inner.fields().clone(),
            updates,
        )
    }

    pub fn delete_user(&self, username: impl AsRef<str>) -> Result<ResourceResponse> {
        let username = normalize_name("user", username.as_ref())?;
        if self.get_user(&username)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "user '{username}' does not exist"
            )));
        }
        delete_object(self.client, USER_RESOURCE, NAME_KEY, &username)
    }
}
