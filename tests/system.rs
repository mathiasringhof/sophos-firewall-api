use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall::{BackupUpdate, Error, SophosClient, SophosConnection, SophosTransport};

#[derive(Clone)]
struct QueueTransport {
    requests: Rc<RefCell<Vec<String>>>,
    responses: Rc<RefCell<VecDeque<String>>>,
}

impl QueueTransport {
    fn new(responses: impl IntoIterator<Item = String>) -> Self {
        Self {
            requests: Rc::new(RefCell::new(Vec::new())),
            responses: Rc::new(RefCell::new(responses.into_iter().collect())),
        }
    }

    fn captured_requests(&self) -> Vec<String> {
        self.requests.borrow().clone()
    }
}

impl SophosTransport for QueueTransport {
    fn send_xml(&self, _api_url: &str, request_xml: &str) -> sophos_firewall::Result<String> {
        self.requests.borrow_mut().push(request_xml.to_string());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| Error::Transport("no queued fake response".to_string()))
    }
}

fn connection() -> SophosConnection {
    SophosConnection::new("firewall.example", "api-user", "secret")
}

fn client_with(
    responses: impl IntoIterator<Item = String>,
) -> (SophosClient<QueueTransport>, QueueTransport) {
    let transport = QueueTransport::new(responses);
    (
        SophosClient::new(connection(), transport.clone()),
        transport,
    )
}

fn response(body: impl AsRef<str>) -> String {
    format!("<Response>{}</Response>", body.as_ref())
}

fn success_response(resource: &str) -> String {
    response(format!(
        "<{resource}><Status code=\"200\">Configuration applied successfully.</Status></{resource}>"
    ))
}

fn zero_records_response(resource: &str) -> String {
    response(format!(
        "<{resource}><Status>Number of records Zero.</Status></{resource}>"
    ))
}

fn backup_xml(prefix: &str, frequency: &str) -> String {
    format!(
        "<BackupRestore><ScheduleBackup><BackupMode>FTP</BackupMode><BackupPrefix>{prefix}</BackupPrefix><FTPServer>192.0.2.10</FTPServer><BackupFrequency>{frequency}</BackupFrequency></ScheduleBackup></BackupRestore>"
    )
}

fn notification_xml(name: &str, status: &str) -> String {
    format!("<Notification><Name>{name}</Name><Status>{status}</Status></Notification>")
}

fn notification_list_xml(name: &str, address: &str) -> String {
    format!(
        "<NotificationList><Name>{name}</Name><EmailAddress>{address}</EmailAddress></NotificationList>"
    )
}

#[test]
fn system_backup_get_update_uses_backuprestore_and_preserves_escaped_fields() {
    let (client, transport) = client_with([
        response(backup_xml("fw1", "Daily")),
        response(backup_xml("fw1", "Daily")),
        success_response("BackupRestore"),
    ]);

    let backup = client.system().get_backup().expect("backup parses");
    assert_eq!(backup.field("ScheduleBackup.BackupPrefix"), Some("fw1"));

    client
        .system()
        .update_backup(
            BackupUpdate::new()
                .with_schedule_field("BackupPrefix", "fw & lab")
                .expect("valid field"),
        )
        .expect("backup updated");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("<Get><BackupRestore/>"));
    assert!(requests[2].contains("<Set operation=\"update\"><BackupRestore>"));
    assert!(requests[2].contains("<BackupMode>FTP</BackupMode>"));
    assert!(requests[2].contains("<FTPServer>192.0.2.10</FTPServer>"));
    assert!(requests[2].contains("<BackupFrequency>Daily</BackupFrequency>"));
    assert!(requests[2].contains("<BackupPrefix>fw &amp; lab</BackupPrefix>"));
}

#[test]
fn system_notification_and_notification_list_list_get_work() {
    let (client, transport) = client_with([
        response(format!(
            "{}{}",
            notification_xml("ATP", "Enable"),
            notification_xml("VPN", "Disable")
        )),
        response(notification_xml("ATP", "Enable")),
        response(notification_list_xml("admin", "admin@example.test")),
        response(notification_list_xml("admin", "admin@example.test")),
    ]);

    let notifications = client
        .system()
        .list_notifications()
        .expect("notifications parse");
    assert_eq!(
        notifications
            .iter()
            .map(|item| (item.name(), item.field("Status")))
            .collect::<Vec<_>>(),
        vec![("ATP", Some("Enable")), ("VPN", Some("Disable"))]
    );

    let notification = client
        .system()
        .get_notification("ATP")
        .expect("notification get works")
        .expect("exists");
    assert_eq!(notification.name(), "ATP");

    let items = client
        .system()
        .list_notification_items()
        .expect("notification list parses");
    assert_eq!(items[0].field("EmailAddress"), Some("admin@example.test"));

    let item = client
        .system()
        .get_notification_item("admin")
        .expect("notification item get works")
        .expect("exists");
    assert_eq!(item.name(), "admin");

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<Get><Notification/>"));
    assert!(requests[1].contains("<Get><Notification>"));
    assert!(requests[2].contains("<Get><NotificationList/>"));
    assert!(requests[3].contains("<Get><NotificationList>"));
}

#[test]
fn system_notification_get_zero_records_returns_none_and_reports_retention_get_uses_data_management()
 {
    let (client, transport) = client_with([
        zero_records_response("Notification"),
        response(
            "<DataManagement><ReportRetentionPeriod>90</ReportRetentionPeriod></DataManagement>",
        ),
    ]);

    let missing = client
        .system()
        .get_notification("missing")
        .expect("zero maps to None");
    assert_eq!(missing, None);

    let retention = client
        .system()
        .get_reports_retention()
        .expect("retention parses");
    assert_eq!(retention.field("ReportRetentionPeriod"), Some("90"));

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<Get><Notification>"));
    assert!(requests[1].contains("<Get><DataManagement/>"));
}

#[test]
fn backup_update_rejects_invalid_schedule_field_tags() {
    let error = BackupUpdate::new()
        .with_schedule_field("Bad<Tag", "value")
        .expect_err("invalid field rejected");

    assert!(error.to_string().contains("invalid XML tag"));
}
