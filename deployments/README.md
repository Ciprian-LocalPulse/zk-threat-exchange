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

This builds and starts three containers:

| Service | Image | Notes |
|---|---|---|
| `zk-threat-node` | `core-node.Dockerfile` | Rust P2P node, runs continuously |
| `heuristics-engine` | `heuristics-engine.Dockerfile` | Julia, runs its test/inference batch once by default |
| `enterprise-api` | `enterprise-api.Dockerfile` | Go REST API, exposed on `localhost:8080` |

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

`docker-compose.yml` is intentionally a single-host, zero-cost starting
point. For a real multi-organization deployment you'll want:

- A real network transport for `core-node`'s gossip layer (see
  `CHANGELOG.md`'s "Planned" section).
- Persistent storage instead of in-memory state for both `core-node` and
  `enterprise-api`.
- A container orchestrator (Kubernetes, Nomad) once you're running more
  than a handful of nodes.
