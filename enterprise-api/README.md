# enterprise-api

**Language:** Go · **Author:** Ciprian Ștefan Pleșca

The SaaS/monetization layer: a REST API in front of the open-source core,
with authentication, role-based access control, usage-based billing
metering, and PostgreSQL-backed persistence.

## Layout

```
cmd/server/main.go              # HTTP server entry point, route wiring, DB connection
internal/auth/auth.go           # HMAC-SHA256 token issuer/verifier + RBAC
internal/handlers/handlers.go   # commitment ingest/list, billing, health
internal/store/store.go         # PostgreSQL persistence + schema migration
```

## Running locally

You need a Postgres instance. The fastest way to get one:

```bash
docker run --rm -d --name zk-postgres \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=zkthreat \
  -p 5432:5432 postgres:16-alpine
```

Then:

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/zkthreat?sslmode=disable"
go build ./... && go run ./cmd/server
```

The schema (commitments + billing tables) is created automatically on
startup if it doesn't already exist — no separate migration step needed.

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

Restart the server and repeat the `GET /v1/commitments` call — the
commitment from before is still there. That's the whole point of this
module's persistence layer.

## Testing

Requires `DATABASE_URL` pointing at a real Postgres (see above). Tests
`t.Skip()` cleanly if it's not set, so `go test ./...` won't fail in an
environment without Postgres — it'll just skip the store/handlers tests
that need one.

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/zkthreat?sslmode=disable"
go vet ./...
go test ./... -v
```

CI runs these against a real Postgres service container — see
[`../.github/workflows/go-tests.yml`](../.github/workflows/go-tests.yml).

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
- Set `DATABASE_URL` to your production Postgres connection string. There
  is no automatic fallback in production mode — the server will fail to
  start if it can't connect, which is the correct behavior for a service
  that must not silently run without its persistence layer.
- Replace the HMAC token issuer with a real IdP integration (OIDC/SAML)
  before onboarding real customers — see
  [`../docs/enterprise_integration.md`](../docs/enterprise_integration.md).
- Default `database/sql` connection pool settings are in effect
  (unconfigured) — tune `SetMaxOpenConns`/`SetMaxIdleConns` before serving
  real production load; see `docs/ROADMAP.md` Phase 3.
