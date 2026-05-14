use serde_json::Value;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

use super::common::{
    ApiObject, ObjectFields, first_named_resource, merge_fields, normalize_name,
    objects_from_response, payload_with_key,
};

const FIREWALL_RULE_RESOURCE: &str = "FirewallRule";
const FIREWALL_RULE_GROUP_RESOURCE: &str = "FirewallRuleGroup";
const LOCAL_SERVICE_ACL_RESOURCE: &str = "LocalServiceACL";
const NAME_KEY: &str = "Name";
const RULE_NAME_KEY: &str = "RuleName";

macro_rules! object_wrapper {
    ($name:ident, $label:literal, $name_method:ident) => {
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

object_wrapper!(FirewallRule, "firewall rule name", name);
object_wrapper!(FirewallRuleGroup, "firewall rule group name", name);
object_wrapper!(LocalServiceAcl, "ACL rule name", rule_name);
payload_wrapper!(FirewallRuleCreate, FirewallRuleUpdate, "firewall rule name");
payload_wrapper!(
    FirewallRuleGroupCreate,
    FirewallRuleGroupUpdate,
    "firewall rule group name"
);
payload_wrapper!(
    LocalServiceAclCreate,
    LocalServiceAclUpdate,
    "ACL rule name"
);

impl FirewallRule {
    pub fn status(&self) -> Option<&str> {
        self.field("Status")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FirewallApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn firewall(&self) -> FirewallApi<'_, T> {
        FirewallApi { client: self }
    }
}

impl<T> FirewallApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        list_objects(
            self.client,
            FIREWALL_RULE_RESOURCE,
            NAME_KEY,
            "firewall rule name",
            FirewallRule::new,
        )
    }

    pub fn get_rule(&self, name: impl AsRef<str>) -> Result<Option<FirewallRule>> {
        get_object(
            self.client,
            FIREWALL_RULE_RESOURCE,
            NAME_KEY,
            "firewall rule name",
            name,
            FirewallRule::new,
        )
    }

    pub fn create_rule(&self, rule: FirewallRuleCreate) -> Result<ResourceResponse> {
        create_object(self.client, FIREWALL_RULE_RESOURCE, NAME_KEY, rule.inner)
    }

    pub fn update_rule(&self, rule: FirewallRuleUpdate) -> Result<ResourceResponse> {
        let (name, fields) = rule.inner.into_parts();
        let existing = self.get_rule(&name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("firewall rule '{name}' does not exist"))
        })?;
        update_object(
            self.client,
            FIREWALL_RULE_RESOURCE,
            NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_rule(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("firewall rule name", name.as_ref())?;
        if self.get_rule(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "firewall rule '{name}' does not exist"
            )));
        }
        delete_object(self.client, FIREWALL_RULE_RESOURCE, NAME_KEY, &name)
    }

    pub fn list_rule_groups(&self) -> Result<Vec<FirewallRuleGroup>> {
        list_objects(
            self.client,
            FIREWALL_RULE_GROUP_RESOURCE,
            NAME_KEY,
            "firewall rule group name",
            FirewallRuleGroup::new,
        )
    }

    pub fn get_rule_group(&self, name: impl AsRef<str>) -> Result<Option<FirewallRuleGroup>> {
        get_object(
            self.client,
            FIREWALL_RULE_GROUP_RESOURCE,
            NAME_KEY,
            "firewall rule group name",
            name,
            FirewallRuleGroup::new,
        )
    }

    pub fn create_rule_group(&self, group: FirewallRuleGroupCreate) -> Result<ResourceResponse> {
        create_object(
            self.client,
            FIREWALL_RULE_GROUP_RESOURCE,
            NAME_KEY,
            group.inner,
        )
    }

    pub fn update_rule_group(&self, group: FirewallRuleGroupUpdate) -> Result<ResourceResponse> {
        let (name, fields) = group.inner.into_parts();
        let existing = self.get_rule_group(&name)?.ok_or_else(|| {
            Error::InvalidRequest(format!("firewall rule group '{name}' does not exist"))
        })?;
        update_object(
            self.client,
            FIREWALL_RULE_GROUP_RESOURCE,
            NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_rule_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("firewall rule group name", name.as_ref())?;
        if self.get_rule_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "firewall rule group '{name}' does not exist"
            )));
        }
        delete_object(self.client, FIREWALL_RULE_GROUP_RESOURCE, NAME_KEY, &name)
    }

    pub fn list_acl_rules(&self) -> Result<Vec<LocalServiceAcl>> {
        list_objects(
            self.client,
            LOCAL_SERVICE_ACL_RESOURCE,
            RULE_NAME_KEY,
            "ACL rule name",
            LocalServiceAcl::new,
        )
    }

    pub fn get_acl_rule(&self, name: impl AsRef<str>) -> Result<Option<LocalServiceAcl>> {
        get_object(
            self.client,
            LOCAL_SERVICE_ACL_RESOURCE,
            RULE_NAME_KEY,
            "ACL rule name",
            name,
            LocalServiceAcl::new,
        )
    }

    pub fn create_acl_rule(&self, acl: LocalServiceAclCreate) -> Result<ResourceResponse> {
        create_object(
            self.client,
            LOCAL_SERVICE_ACL_RESOURCE,
            RULE_NAME_KEY,
            acl.inner,
        )
    }

    pub fn update_acl_rule(&self, acl: LocalServiceAclUpdate) -> Result<ResourceResponse> {
        let (name, fields) = acl.inner.into_parts();
        let existing = self
            .get_acl_rule(&name)?
            .ok_or_else(|| Error::InvalidRequest(format!("ACL rule '{name}' does not exist")))?;
        update_object(
            self.client,
            LOCAL_SERVICE_ACL_RESOURCE,
            RULE_NAME_KEY,
            &name,
            existing.inner.fields().clone(),
            fields,
        )
    }

    pub fn delete_acl_rule(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_name("ACL rule name", name.as_ref())?;
        if self.get_acl_rule(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "ACL rule '{name}' does not exist"
            )));
        }
        delete_object(
            self.client,
            LOCAL_SERVICE_ACL_RESOURCE,
            RULE_NAME_KEY,
            &name,
        )
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
