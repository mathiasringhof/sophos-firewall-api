# sophos-firewall-web

Agent-facing HTTP API for Sophos Firewall automation.

This crate is deliberately thin: it accepts JSON, validates DTOs through
`sophos-firewall-api`, calls the typed client, and returns JSON. Authentication
and object-scope restrictions are intentionally not part of this first slice.

## Configuration

Set these environment variables before starting the server:

```sh
export SOPHOS_FIREWALL_HOST=firewall.example
export SOPHOS_FIREWALL_USERNAME=api-user
export SOPHOS_FIREWALL_PASSWORD=secret
export SOPHOS_FIREWALL_WEB_BIND=127.0.0.1:8080
```

Optional:

```sh
export SOPHOS_FIREWALL_PORT=4444
export SOPHOS_FIREWALL_VERIFY_TLS=true
```

Run:

```sh
cargo run -p sophos-firewall-web
```

## Endpoints

Health:

- `GET /health`

DNS host entries:

- `GET /v1/dns/host-entries`
- `GET /v1/dns/host-entries/{host_name}`
- `POST /v1/dns/host-entries?force=false`
- `PUT /v1/dns/host-entries/{host_name}`
- `PATCH /v1/dns/host-entries/{host_name}`
- `DELETE /v1/dns/host-entries/{host_name}`

URL groups:

- `GET /v1/url-groups`
- `GET /v1/url-groups/{name}`
- `POST /v1/url-groups`
- `PATCH /v1/url-groups/{name}/domains`
- `DELETE /v1/url-groups/{name}`

Firewall rules and rule groups:

- `GET /v1/firewall/rules`
- `GET /v1/firewall/rules/{name}`
- `POST /v1/firewall/rules`
- `PATCH /v1/firewall/rules/{name}`
- `DELETE /v1/firewall/rules/{name}`
- `GET /v1/firewall/rule-groups`
- `GET /v1/firewall/rule-groups/{name}`
- `POST /v1/firewall/rule-groups`
- `PATCH /v1/firewall/rule-groups/{name}`
- `DELETE /v1/firewall/rule-groups/{name}`

Firewall objects use a raw `fields` object because the underlying crate has not
yet codified full Sophos firewall-rule semantics. DNS and URL groups use typed
request DTOs.

## Examples

Create or replace a DNS host entry:

```sh
curl -X PUT http://127.0.0.1:8080/v1/dns/host-entries/app.local -H 'content-type: application/json' -d '{"addresses":[{"ip_family":"IPv4","ip_address":"10.0.0.20"}],"add_reverse_dns_lookup":false}'
```

Add domains to a URL group:

```sh
curl -X PATCH http://127.0.0.1:8080/v1/url-groups/kids/domains -H 'content-type: application/json' -d '{"action":"add","domains":["example.com"]}'
```

Patch a firewall rule:

```sh
curl -X PATCH http://127.0.0.1:8080/v1/firewall/rules/allow-web -H 'content-type: application/json' -d '{"fields":{"Status":"Disable"}}'
```
