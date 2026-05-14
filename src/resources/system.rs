use serde_json::Value;

use crate::{ResourceResponse, Result, SophosClient, SophosTransport};

use super::common::{
    ApiObject, FieldMap, get_object, get_singleton, list_objects, update_singleton, validated_field,
};

const BACKUP_RESOURCE: &str = "BackupRestore";
const NOTIFICATION_RESOURCE: &str = "Notification";
const NOTIFICATION_LIST_RESOURCE: &str = "NotificationList";
const REPORTS_RETENTION_RESOURCE: &str = "DataManagement";
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

singleton_wrapper!(BackupSettings);
singleton_wrapper!(ReportsRetention);
object_wrapper!(Notification, name);
object_wrapper!(NotificationListItem, name);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackupUpdate {
    fields: FieldMap,
}

impl BackupUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_schedule_field(
        mut self,
        field: impl AsRef<str>,
        value: impl Into<Value>,
    ) -> Result<Self> {
        let (field, value) = validated_field(field, value)?;
        let schedule = self
            .fields
            .entry("ScheduleBackup".to_string())
            .or_insert_with(|| Value::Object(FieldMap::new()));
        match schedule {
            Value::Object(map) => {
                map.insert(field, value);
            }
            _ => unreachable!("ScheduleBackup is only created as an object"),
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn system(&self) -> SystemApi<'_, T> {
        SystemApi { client: self }
    }
}

impl<T> SystemApi<'_, T>
where
    T: SophosTransport,
{
    pub fn get_backup(&self) -> Result<BackupSettings> {
        Ok(BackupSettings::new(get_singleton(
            self.client,
            BACKUP_RESOURCE,
        )?))
    }

    pub fn update_backup(&self, update: BackupUpdate) -> Result<ResourceResponse> {
        let existing = self.get_backup()?;
        update_singleton(
            self.client,
            BACKUP_RESOURCE,
            existing.inner.fields().clone(),
            update.fields,
        )
    }

    pub fn list_notifications(&self) -> Result<Vec<Notification>> {
        list_objects(
            self.client,
            NOTIFICATION_RESOURCE,
            NAME_KEY,
            "notification name",
            Notification::new,
        )
    }

    pub fn get_notification(&self, name: impl AsRef<str>) -> Result<Option<Notification>> {
        get_object(
            self.client,
            NOTIFICATION_RESOURCE,
            NAME_KEY,
            "notification name",
            name,
            Notification::new,
        )
    }

    pub fn list_notification_items(&self) -> Result<Vec<NotificationListItem>> {
        list_objects(
            self.client,
            NOTIFICATION_LIST_RESOURCE,
            NAME_KEY,
            "notification list item name",
            NotificationListItem::new,
        )
    }

    pub fn get_notification_item(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Option<NotificationListItem>> {
        get_object(
            self.client,
            NOTIFICATION_LIST_RESOURCE,
            NAME_KEY,
            "notification list item name",
            name,
            NotificationListItem::new,
        )
    }

    pub fn get_reports_retention(&self) -> Result<ReportsRetention> {
        Ok(ReportsRetention::new(get_singleton(
            self.client,
            REPORTS_RETENTION_RESOURCE,
        )?))
    }
}
