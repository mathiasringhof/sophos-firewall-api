use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use serde_json::json;
use sophos_firewall::{
    AdminProfileCreate, AdminProfileUpdate, Error, SophosClient, SophosConnection, SophosTransport,
};

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

fn profile_xml(name: &str, dashboard: &str, backup: &str) -> String {
    format!(
        "<AdministrationProfile><Name>{name}</Name><Dashboard>{dashboard}</Dashboard><System><Backup>{backup}</Backup><Restore>Read-Only</Restore></System></AdministrationProfile>"
    )
}

#[test]
fn admin_profile_create_update_delete_use_administration_profile_resource() {
    let (client, transport) = client_with([
        success_response("AdministrationProfile"),
        response(profile_xml("auditor", "Read-Only", "None")),
        success_response("AdministrationProfile"),
        response(profile_xml("auditor", "Read-Only", "Read-Write")),
        success_response("AdministrationProfile"),
    ]);

    client
        .admin()
        .create_profile(
            AdminProfileCreate::new("auditor")
                .expect("valid profile")
                .with_field("Dashboard", "Read-Only")
                .expect("valid field")
                .with_field("System", json!({ "Backup": "None" }))
                .expect("valid nested field"),
        )
        .expect("profile created");

    client
        .admin()
        .update_profile(
            AdminProfileUpdate::new("auditor")
                .expect("valid profile")
                .with_field("System", json!({ "Backup": "Read-Write" }))
                .expect("valid nested field"),
        )
        .expect("profile updated");

    client
        .admin()
        .delete_profile("auditor")
        .expect("profile deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].contains("<Set operation=\"add\"><AdministrationProfile>"));
    assert!(requests[0].contains("<Name>auditor</Name>"));
    assert!(requests[2].contains("<Set operation=\"update\"><AdministrationProfile>"));
    assert!(requests[2].contains("<Backup>Read-Write</Backup>"));
    assert!(requests[2].contains("<Restore>Read-Only</Restore>"));
    assert!(requests[4].contains("<Remove><AdministrationProfile><Name>auditor</Name>"));
}

#[test]
fn missing_admin_profile_delete_does_not_send_remove() {
    let (client, transport) = client_with([zero_records_response("AdministrationProfile")]);

    let error = client
        .admin()
        .delete_profile("missing")
        .expect_err("missing rejected");

    assert!(
        error
            .to_string()
            .contains("admin profile 'missing' does not exist")
    );
    assert_eq!(transport.captured_requests().len(), 1);
    assert!(!transport.captured_requests()[0].contains("<Remove>"));
}

#[test]
fn admin_authentication_and_settings_get_use_confirmed_resources() {
    let (client, transport) = client_with([
        response(
            "<AdminAuthentication><AuthenticationServer>Local</AuthenticationServer></AdminAuthentication>",
        ),
        response(
            "<AdminSettings><HostnameSettings><Hostname>fw1</Hostname></HostnameSettings></AdminSettings>",
        ),
    ]);

    let auth = client.admin().get_authentication().expect("auth parses");
    assert_eq!(auth.field("AuthenticationServer"), Some("Local"));

    let settings = client.admin().get_settings().expect("settings parses");
    assert_eq!(settings.field("HostnameSettings.Hostname"), Some("fw1"));

    let requests = transport.captured_requests();
    assert!(requests[0].contains("<Get><AdminAuthentication/>"));
    assert!(requests[1].contains("<Get><AdminSettings/>"));
}
