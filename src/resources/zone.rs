use serde_json::Value;

use crate::{Error, ResourceResponse, Result, SophosClient, SophosTransport};

use super::common::{
    ApiObject, ObjectFields, create_object, delete_object, get_object, get_singleton, list_objects,
    normalize_name, update_object,
};

const ZONE_RESOURCE: &str = "Zone";
const INTERFACE_RESOURCE: &str = "Interface";
const VLAN_RESOURCE: &str = "VLAN";
const DNS_RESOURCE: &str = "DNS";
const NAME_KEY: &str = "Name";

macro_rules! object_wrapper {
    ($name:ident, $name_method:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            inner: ApiObject,
        }

        impl $name {
            fn new(inner: ApiObject) -> Self {
                Self { inner }
            }

            pub fn $name_method(&self) -> &str {
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

object_wrapper!(Zone, name);
object_wrapper!(Interface, name);
object_wrapper!(Vlan, name);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsForwarders {
    inner: ApiObject,
}

impl DnsForwarders {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCreate {
    inner: ObjectFields,
}

impl ZoneCreate {
    pub fn new(name: impl AsRef<str>, zone_type: impl AsRef<str>) -> Result<Self> {
        let zone_type = normalize_name("zone type", zone_type.as_ref())?;
        Ok(Self {
            inner: ObjectFields::new("zone name", name)?.with_field("Type", zone_type)?,
        })
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn with_field(mut self, field: impl AsRef<str>, value: impl Into<Value>) -> Result<Self> {
        self.inner = self.inner.with_field(field, value)?;
        Ok(self)
    }

    pub fn into_update(self) -> ZoneUpdate {
        ZoneUpdate { inner: self.inner }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneUpdate {
    inner: ObjectFields,
}

impl ZoneUpdate {
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: ObjectFields::new("zone name", name)?,
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
pub struct ZonesApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn zones(&self) -> ZonesApi<'_, T> {
        ZonesApi { client: self }
    }
}

impl<T> ZonesApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        list_objects(self.client, ZONE_RESOURCE, NAME_KEY, "zone name", Zone::new)
    }

    pub fn get_zone(&self, name: impl AsRef<str>) -> Result<Option<Zone>> {
        get_object(
            self.client,
            ZONE_RESOURCE,
            NAME_KEY,
            "zone name",
            name,
            Zone::new,
        )
    }

    pub fn create_zone(&self, zone: ZoneCreate) -> Result<ResourceResponse> {
        create_object(self.client, ZONE_RESOURCE, NAME_KEY, zone.inner)
    }

    pub fn update_zone(&self, zone: ZoneUpdate) -> Result<ResourceResponse> {
        let (name, fields) = zone.inner.into_parts();
        let existing = self
            .get_zone(&name)?
            .ok_or_else(|| Error::InvalidRequest(format!("zone '{name}' does not exist")))?;
        update_object(
            self.client,
            ZONE_RESOURCE,
            NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_zone(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("zone name", name.as_ref())?;
        if self.get_zone(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "zone '{name}' does not exist"
            )));
        }
        delete_object(self.client, ZONE_RESOURCE, NAME_KEY, &name)
    }

    pub fn list_interfaces(&self) -> Result<Vec<Interface>> {
        list_objects(
            self.client,
            INTERFACE_RESOURCE,
            NAME_KEY,
            "interface name",
            Interface::new,
        )
    }

    pub fn get_interface(&self, name: impl AsRef<str>) -> Result<Option<Interface>> {
        get_object(
            self.client,
            INTERFACE_RESOURCE,
            NAME_KEY,
            "interface name",
            name,
            Interface::new,
        )
    }

    pub fn list_vlans(&self) -> Result<Vec<Vlan>> {
        list_objects(self.client, VLAN_RESOURCE, NAME_KEY, "VLAN name", Vlan::new)
    }

    pub fn get_vlan(&self, name: impl AsRef<str>) -> Result<Option<Vlan>> {
        get_object(
            self.client,
            VLAN_RESOURCE,
            NAME_KEY,
            "VLAN name",
            name,
            Vlan::new,
        )
    }

    pub fn get_dns_forwarders(&self) -> Result<DnsForwarders> {
        Ok(DnsForwarders::new(get_singleton(
            self.client,
            DNS_RESOURCE,
        )?))
    }
}
