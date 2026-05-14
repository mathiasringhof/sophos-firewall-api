# sophos-firewall

Library-only Rust crate for Sophos Firewall API access primitives.

This repo deliberately contains no CLI and no web server. Those should live in
separate repos/binaries and consume this crate, so API behavior and authorization
rules do not drift.

## Current slice

Implemented with red/green TDD:

- `SophosRequest` and `SophosConnection` primitives
- object-scoped `AuthorizationPolicy`
- safe XML request builder for structured read/create/update/delete operations
- `SophosTransport` plus `SophosClient<T>` so tests can prove authorization happens before XML generation/transport
- optional blocking HTTP transport behind the `blocking-http` feature
- XML response parsing into resource status/body, including structured zero-record and non-2xx API errors
- hard denial of raw XML in authorization and safe XML builder

The first security use case is restricting an agent to change exactly one object,
for example one `WebFilterPolicy`.

## Usage

Custom transports stay simple for tests and embedding code:

```rust
use sophos_firewall::{Result, SophosTransport};

#[derive(Clone)]
struct FakeTransport;

impl SophosTransport for FakeTransport {
    fn send_xml(&self, _api_url: &str, request_xml: &str) -> Result<String> {
        assert!(request_xml.contains("<Request>"));
        Ok("<Response/>".to_string())
    }
}
```

Enable the real blocking HTTP transport when you want the crate to post to a
Sophos Firewall API endpoint:

```toml
[dependencies]
sophos-firewall = { version = "0.1", features = ["blocking-http"] }
```

```rust,no_run
use sophos_firewall::{
    Action, AuthorizationPolicy, AuthorizationRule, HttpTransport, ObjectScope, SophosClient,
    SophosConnection, WebFilterPolicyUpdate,
};

# fn main() -> sophos_firewall::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let policy = AuthorizationPolicy::new(vec![AuthorizationRule::allow(
    "agent:webfilter-bot",
    "WebFilterPolicy",
    ObjectScope::named(["Default Policy"]),
    [Action::Update],
)]);
let client = SophosClient::new(connection, transport).with_authorization("agent:webfilter-bot", policy);

client
    .webfilter()
    .update_policy(WebFilterPolicyUpdate::new("Default Policy")?)?;
# Ok(())
# }
```

`HttpTransport` posts form data as `reqxml=<request_xml>` to the connection's
`/webconsole/APIController` URL with `Accept: application/xml`. It uses a 30s
default timeout and follows `SophosConnection::verify_tls`; setting
`verify_tls = false` accepts invalid certificates for lab/self-signed firewalls.

Transport errors intentionally avoid including request XML or response bodies, so
credentials generated into the XML are not echoed into logs by this crate. Keep
using structured request builders plus `SophosClient` authorization: denied
requests fail before XML generation or transport, and raw XML remains blocked by
both authorization and the safe XML builder.

## Red/green proof

The initial tests for each slice were written before implementation and failed
with unresolved public API imports. Implementation was then added until the
tests passed.

## Verify

```bash
cargo fmt --all --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --features blocking-http
cargo clippy --all-targets --features blocking-http -- -D warnings
```

## Python reference

Reference left outside this repo at:

```text
../../refs/sophos-cli
```

Upstream: <https://github.com/mathiasringhof/sophos-cli>
