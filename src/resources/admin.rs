use serde_json::Value;

use crate::{Error, ResourceResponse, Result, SophosClient, SophosTransport};

use super::common::{
    ApiObject, ObjectFields, create_object, delete_object, get_object, get_singleton, list_objects,
    normalize_name, update_object,
};

const ADMIN_PROFILE_RESOURCE: &str = "AdministrationProfile";
const ADMIN_AUTHENTICATION_RESOURCE: &str = "AdminAuthentication";
const ADMIN_SETTINGS_RESOURCE: &str = "AdminSettings";
const NAME_KEY: &str = "Name";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminProfile {
    inner: ApiObject,
}

impl AdminProfile {
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

macro_rules! singleton_wrapper {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            inner: ApiObject,
        }

        impl $name {
            fn new(inner: ApiObject) -> Self {
                Self { inner }
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

singleton_wrapper!(AdminAuthentication);
singleton_wrapper!(AdminSettings);

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

payload_wrapper!(AdminProfileCreate, AdminProfileUpdate, "admin profile name");

#[derive(Debug, Clone, Copy)]
pub struct AdminApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn admin(&self) -> AdminApi<'_, T> {
        AdminApi { client: self }
    }
}

impl<T> AdminApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_profiles(&self) -> Result<Vec<AdminProfile>> {
        list_objects(
            self.client,
            ADMIN_PROFILE_RESOURCE,
            NAME_KEY,
            "admin profile name",
            AdminProfile::new,
        )
    }

    pub fn get_profile(&self, name: impl AsRef<str>) -> Result<Option<AdminProfile>> {
        get_object(
            self.client,
            ADMIN_PROFILE_RESOURCE,
            NAME_KEY,
            "admin profile name",
            name,
            AdminProfile::new,
        )
    }

    pub fn create_profile(&self, profile: AdminProfileCreate) -> Result<ResourceResponse> {
        create_object(self.client, ADMIN_PROFILE_RESOURCE, NAME_KEY, profile.inner)
    }

    pub fn update_profile(&self, profile: AdminProfileUpdate) -> Result<ResourceResponse> {
        let (name, fields) = profile.inner.into_parts();
        let existing = self.get_profile(&name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("admin profile '{name}' does not exist"))
        })?;
        update_object(
            self.client,
            ADMIN_PROFILE_RESOURCE,
            NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_profile(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("admin profile name", name.as_ref())?;
        if self.get_profile(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "admin profile '{name}' does not exist"
            )));
        }
        delete_object(self.client, ADMIN_PROFILE_RESOURCE, NAME_KEY, &name)
    }

    pub fn get_authentication(&self) -> Result<AdminAuthentication> {
        Ok(AdminAuthentication::new(get_singleton(
            self.client,
            ADMIN_AUTHENTICATION_RESOURCE,
        )?))
    }

    pub fn get_settings(&self) -> Result<AdminSettings> {
        Ok(AdminSettings::new(get_singleton(
            self.client,
            ADMIN_SETTINGS_RESOURCE,
        )?))
    }
}
