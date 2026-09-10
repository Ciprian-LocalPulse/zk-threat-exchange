# deployments

**Author:** Ciprian Ștefan Pleșca

Zero-cost, local-first deployment tooling for the full stack.

## Layout

```
core-node.Dockerfile
enterprise-api.Dockerfile
heuristics-engine.Dockerfile
docker-compose.yml
make_templates/
└── soc_phishing_alert_webhook.json   # Make.com blueprint for SOC alerting
```

## Quickstart

From the repository root:

```bash
docker-compose -f deployments/docker-compose.yml up -d
```

This builds and starts four containers:

| Service | Image | Notes |
|---|---|---|
| `postgres` | `postgres:16-alpine` | Persistent store for `enterprise-api`; gates its startup via healthcheck |
| `zk-threat-node` | `core-node.Dockerfile` | Rust P2P node, runs continuously, SQLite pool file in a named volume |
| `heuristics-engine` | `heuristics-engine.Dockerfile` | Julia, runs its test/inference batch once by default |
| `enterprise-api` | `enterprise-api.Dockerfile` | Go REST API, exposed on `localhost:8080` |

State in both `postgres` and `zk-threat-node`'s SQLite file is kept in named
Docker volumes (`zk-postgres-data`, `zk-core-node-data`) — a plain
`docker-compose down` / `up` cycle does **not** lose data. Use
`docker-compose down -v` if you actually want to wipe everything and start
fresh.

Check logs for the auto-generated dev admin token:

```bash
docker logs zk-enterprise-api | grep "Dev admin token"
```

## Importing the Make.com blueprint

1. Log into [Make.com](https://www.make.com) (free tier works for
   low-volume alerting).
2. **Scenarios → Create a new scenario → Import Blueprint**.
3. Select `make_templates/soc_phishing_alert_webhook.json`.
4. Point the webhook module at your `enterprise-api` instance's outbound
   webhook configuration (see
   [`../docs/enterprise_integration.md`](../docs/enterprise_integration.md)).

## Going beyond local Docker Compose

`docker-compose.yml` is intentionally a single-host starting point. For a
real multi-organization deployment you'll still want:

- Wide-area peer discovery beyond mDNS for `core-node`'s gossip layer (see
  `docs/ROADMAP.md` Phase 2 — mDNS only works within one network segment).
- Managed Postgres (RDS, Cloud SQL, etc.) instead of the single
  `postgres:16-alpine` container here, plus connection-pool tuning under
  real load (see `docs/ROADMAP.md` Phase 3).
- Backup/restore automation for both Postgres and the SQLite pool files —
  currently neither is backed up.
- A container orchestrator (Kubernetes, Nomad) once you're running more
  than a handful of nodes.
