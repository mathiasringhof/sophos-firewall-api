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
- XML response parsing into resource status/body, including structured zero-record and non-2xx API errors
- hard denial of raw XML in authorization and safe XML builder

The first security use case is restricting an agent to change exactly one object,
for example one `WebFilterPolicy`.

## Red/green proof

The initial tests for each slice were written before implementation and failed
with unresolved public API imports. Implementation was then added until the
tests passed.

## Verify

```bash
cargo fmt --all --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Python reference

Reference left outside this repo at:

```text
../../refs/sophos-cli
```

Upstream: <https://github.com/mathiasringhof/sophos-cli>
