# enterprise-api

**Language:** Go · **Author:** Ciprian Ștefan Pleșca

The SaaS/monetization layer: a REST API in front of the open-source core,
with authentication, role-based access control, and usage-based billing
metering.

## Layout

```
cmd/server/main.go        # HTTP server entry point, route wiring
internal/auth/auth.go     # HMAC-SHA256 token issuer/verifier + RBAC
internal/handlers/handlers.go  # commitment ingest/list, billing, health
```

## Running locally

```bash
go build ./... && go run ./cmd/server
```

On boot in non-production mode, the server prints a 24-hour admin token to
the log so you can immediately call authenticated endpoints:

```bash
export TOKEN="<paste the printed dev token>"

curl http://localhost:8080/healthz

curl -X POST http://localhost:8080/v1/commitments/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"commitment": "123456789", "node_id": "local-node-1"}'

curl http://localhost:8080/v1/commitments \
  -H "Authorization: Bearer $TOKEN"

curl http://localhost:8080/v1/billing/summary \
  -H "Authorization: Bearer $TOKEN"
```

## Testing

```bash
go vet ./...
go test ./... -v
```

## Roles

| Role | Can do |
|---|---|
| `viewer` | `GET /v1/commitments` |
| `analyst` | everything `viewer` can, plus `POST /v1/commitments/ingest` |
| `admin` | everything `analyst` can, plus `GET /v1/billing/summary` |

## Production notes

- Set `ZKT_JWT_SECRET` to a strong, randomly generated secret — the
  built-in default is for local development only and the server will warn
  loudly if it's not set.
- Set `ZKT_ENV=production` to disable the automatic dev-token minting on
  boot.
- Replace the HMAC token issuer with a real IdP integration (OIDC/SAML)
  before onboarding real customers — see
  [`../docs/enterprise_integration.md`](../docs/enterprise_integration.md).
