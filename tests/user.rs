use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use pretty_assertions::assert_eq;
use sophos_firewall::{Error, SophosClient, SophosConnection, SophosTransport, UserCreate};

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

fn user_xml(username: &str, name: &str, group: &str, password: &str) -> String {
    format!(
        "<User><Username>{username}</Username><Name>{name}</Name><Description>existing</Description><Password>{password}</Password><UserType>User</UserType><Group>{group}</Group><EmailList><EmailID>{username}@example.test</EmailID></EmailList></User>"
    )
}

#[test]
fn user_list_get_create_delete_use_user_resource_and_name_key() {
    let (client, transport) = client_with([
        response(format!(
            "{}{}",
            user_xml("alice", "alice", "Open Group", "old-dummy"),
            user_xml("bob", "bob", "Open Group", "old-dummy")
        )),
        response(user_xml("alice", "alice", "Open Group", "old-dummy")),
        success_response("User"),
        response(user_xml("alice", "alice", "Open Group", "old-dummy")),
        success_response("User"),
    ]);

    let users = client.users().list_users().expect("users parse");
    assert_eq!(
        users.iter().map(|user| user.name()).collect::<Vec<_>>(),
        vec!["alice", "bob"]
    );
    assert_eq!(users[0].field("Username"), Some("alice"));

    let user = client
        .users()
        .get_user("alice")
        .expect("get works")
        .expect("exists");
    assert_eq!(user.name(), "alice");

    client
        .users()
        .create_user(
            UserCreate::new("alice")
                .expect("valid user")
                .with_field("UserType", "User")
                .expect("valid field")
                .with_field("Group", "Open Group")
                .expect("valid field")
                .with_field("Password", "dummy-create-password")
                .expect("valid field"),
        )
        .expect("user created");

    client.users().delete_user("alice").expect("user deleted");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[1].contains("<key name=\"Name\" criteria=\"=\">alice</key>"));
    assert!(requests[2].contains("<Set operation=\"add\"><User>"));
    assert!(requests[2].contains("<Username>alice</Username>"));
    assert!(requests[2].contains("<Name>alice</Name>"));
    assert!(requests[4].contains("<Remove><User><Name>alice</Name>"));
}

#[test]
fn user_password_update_fetches_existing_preserves_fields_and_updates_password() {
    let (client, transport) = client_with([
        response(user_xml("alice", "alice", "Open Group", "old-dummy")),
        success_response("User"),
    ]);

    client
        .users()
        .update_password("alice", "dummy-new-password")
        .expect("password updated");

    let requests = transport.captured_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<Get><User>"));
    assert!(requests[0].contains("<key name=\"Name\" criteria=\"=\">alice</key>"));
    assert!(requests[1].contains("<Set operation=\"update\"><User>"));
    assert!(requests[1].contains("<Username>alice</Username>"));
    assert!(requests[1].contains("<Description>existing</Description>"));
    assert!(requests[1].contains("<Group>Open Group</Group>"));
    assert!(requests[1].contains("<Password>dummy-new-password</Password>"));
    assert!(!requests[1].contains("old-dummy"));
}

#[test]
fn missing_user_password_update_and_delete_do_not_send_write() {
    let (password_client, password_transport) = client_with([zero_records_response("User")]);
    let error = password_client
        .users()
        .update_password("missing", "dummy-new-password")
        .expect_err("missing update rejected");
    assert!(error.to_string().contains("user 'missing' does not exist"));
    assert_eq!(password_transport.captured_requests().len(), 1);
    assert!(!password_transport.captured_requests()[0].contains("<Set"));

    let (delete_client, delete_transport) = client_with([zero_records_response("User")]);
    let error = delete_client
        .users()
        .delete_user("missing")
        .expect_err("missing delete rejected");
    assert!(error.to_string().contains("user 'missing' does not exist"));
    assert_eq!(delete_transport.captured_requests().len(), 1);
    assert!(!delete_transport.captured_requests()[0].contains("<Remove>"));
}
