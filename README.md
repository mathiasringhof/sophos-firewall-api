# sophos-firewall-api

Library-only Rust crate for typed Sophos Firewall XML API access.

The root crate stays library-only. Companion frontends live as separate
workspace members and consume this crate, so Sophos API behavior stays
centralized.

## Current coverage

Implemented with red/green TDD:

- `SophosRequest` and `SophosConnection` primitives
- safe XML request builder for structured read/create/update/delete operations
- `SophosTransport` plus `SophosClient<T>` so tests can capture generated XML without live firewall calls
- optional blocking HTTP transport behind the `blocking-http` feature
- XML response parsing into resource status/body, including structured zero-record and non-2xx API errors
- typed helpers for DNS host entries, URL groups, services/service groups, IP/FQDN network objects, firewall rules/rule groups/local service ACLs, web filter policies/user activities, zones/interfaces/VLANs/DNS forwarders, admins, users, backup/notification/report settings
- `sophos-firewall-web`, a thin agent-facing HTTP API wrapper for DNS, URL groups, firewall rules, and firewall rule groups

## Usage

Custom transports stay simple for tests and embedding code:

```rust
use sophos_firewall_api::{Result, SophosTransport};

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
sophos-firewall-api = { version = "0.1", features = ["blocking-http"] }
```

```rust,no_run
use sophos_firewall_api::{
    HttpTransport, SophosClient, SophosConnection, WebFilterPolicyUpdate,
};

# fn main() -> sophos_firewall_api::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let client = SophosClient::new(connection, transport);

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
credentials generated into the XML are not echoed into logs by this crate.

## DNS examples

Create a manual A record:

```rust,no_run
use sophos_firewall_api::{
    DnsHostAddress, DnsHostEntryCreate, EntryType, HttpTransport, IpFamily, SophosClient,
    SophosConnection,
};

# fn main() -> sophos_firewall_api::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let client = SophosClient::new(connection, transport);

let address = DnsHostAddress::new(EntryType::Manual, IpFamily::IPv4, "10.0.40.32")?;
let entry = DnsHostEntryCreate::new("homeassistant.local.ringhof.io", vec![address])?;

// force = false means: fail if the hostname already exists.
client.dns().add_entry(entry, false)?;
# Ok(())
# }
```

Create or replace the same DNS host entry idempotently:

```rust,no_run
use sophos_firewall_api::{
    DnsHostAddress, DnsHostEntryCreate, EntryType, HttpTransport, IpFamily, SophosClient,
    SophosConnection,
};

# fn main() -> sophos_firewall_api::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let client = SophosClient::new(connection, transport);

let entry = DnsHostEntryCreate::new(
    "grafana.local.ringhof.io",
    vec![DnsHostAddress::new(
        EntryType::Manual,
        IpFamily::IPv4,
        "10.0.30.19",
    )?],
)?;

// force = true updates the existing host entry instead of failing.
let outcome = client.dns().add_entry(entry, true)?;
println!("DNS mutation: {:?}", outcome.action);
# Ok(())
# }
```

Update only the address while preserving the existing reverse-DNS setting:

```rust,no_run
use sophos_firewall_api::{
    DnsHostAddress, DnsHostEntryUpdate, EntryType, HttpTransport, IpFamily, SophosClient,
    SophosConnection,
};

# fn main() -> sophos_firewall_api::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let client = SophosClient::new(connection, transport);

let update = DnsHostEntryUpdate::new("grafana.local.ringhof.io")?.with_addresses(vec![
    DnsHostAddress::new(EntryType::Manual, IpFamily::IPv4, "10.0.30.20")?,
])?;

client.dns().update_entry(update)?;
# Ok(())
# }
```

Bulk-add a small set and collect per-host errors without stopping at the first
failure:

```rust,no_run
use sophos_firewall_api::{
    DnsHostAddress, DnsHostEntryCreate, EntryType, HttpTransport, IpFamily, SophosClient,
    SophosConnection,
};

# fn main() -> sophos_firewall_api::Result<()> {
let connection = SophosConnection::new("firewall.example", "api-user", "secret");
let transport = HttpTransport::from_connection(&connection)?;
let client = SophosClient::new(connection, transport);

let host = |name, ip| -> sophos_firewall_api::Result<DnsHostEntryCreate> {
    Ok(DnsHostEntryCreate::new(
        name,
        vec![DnsHostAddress::new(EntryType::Manual, IpFamily::IPv4, ip)?],
    )?)
};

let result = client.dns().add_many(
    vec![
        host("app-1.local.ringhof.io", "10.0.30.41")?,
        host("app-2.local.ringhof.io", "10.0.30.42")?,
    ],
    true, // force existing records to update
    true, // continue collecting errors after a failed host
);

println!(
    "total={} created={} updated={} failed={}",
    result.total, result.created, result.updated, result.failed
);
for error in result.errors {
    eprintln!("{error}");
}
# Ok(())
# }
```

## Red/green proof

The initial tests for each slice were written before implementation and failed
with unresolved public API imports. Implementation was then added until the
tests passed.

## Verify

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

## Python reference

Reference left outside this repo at:

```text
../../refs/sophos-cli
```

Upstream: <https://github.com/mathiasringhof/sophos-cli>
