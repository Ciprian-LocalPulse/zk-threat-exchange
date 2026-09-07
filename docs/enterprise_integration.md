# Enterprise Integration Guide

**Author: Ciprian Ștefan Pleșca**

## Open Core model

| | Open source (MIT) | Enterprise |
|---|---|---|
| `core-node` (Rust P2P + ZKP) | ✅ | ✅ (same binary) |
| `heuristics-engine` (Julia) | ✅ | ✅ (same binary) |
| `rule-mutator` (Scheme) | ✅ | ✅ (same binary) |
| `enterprise-api` dashboard | Local-only, no auth needed for local dev | Hosted, SSO, RBAC, metering |
| SOC connectors (Splunk, CrowdStrike, Sentinel) | — | ✅ |
| SLA-backed support | — | ✅ 24/7 |
| Billing | — | Usage-based (see below) |

The core protocol is open forever. This is not a "rug-pull open core" — it's
the mechanism by which the network gets adopted widely enough to be useful at
all (a threat-intelligence network with 12 members isn't worth much).

## Authentication

`enterprise-api` issues short-lived HMAC-signed tokens (see
`internal/auth/auth.go`) with three roles:

- `viewer` — read-only access to the commitments dashboard.
- `analyst` — can ingest new commitments from a connected `core-node`.
- `admin` — can additionally view billing summaries and manage the org.

In production, replace the built-in HMAC issuer with a real identity
provider (SAML/OIDC via Okta, Azure AD, Auth0, or Keycloak) — the built-in
issuer is intentionally dependency-free for local development, not a
production auth system.

## Billing dimensions

Two metered dimensions, tracked by `handlers.BillingMeter`:

1. **Verifications total** — every accepted `POST /v1/commitments/ingest`
   call, i.e. every zero-knowledge proof the platform verified on the
   customer's behalf.
2. **Connected nodes** — distinct `node_id`s that have ever submitted a
   commitment, i.e. how many of the customer's hosts/services are
   participating.

`GET /v1/billing/summary` (admin-only) exposes both counters for invoicing.

## SOC connector pattern

Rather than building bespoke Splunk/CrowdStrike/Sentinel integrations up
front, the fastest path to "integrated with your SOC" is a webhook +
Make.com blueprint (see `deployments/make_templates/`): `enterprise-api` fires
a webhook on every high-corroboration commitment, and the Make.com scenario
fans it out to Slack, email, or a SOC ticketing system — all on Make.com's
free tier for low alert volumes.

## Minimal integration checklist for a new enterprise customer

1. Deploy `core-node` on each host/service that should participate (Docker
   image in `deployments/core-node.Dockerfile`).
2. Point each `core-node` instance's outbound webhook at your
   `enterprise-api` `/v1/commitments/ingest` endpoint with an `analyst`-role
   token.
3. Import the Make.com blueprint(s) in `deployments/make_templates/` for
   alerting.
4. Review `docs/zero_knowledge_math.md`'s "known limitations" section with
   your security team before treating this as a production control — the
   demo cryptographic parameters are not production-sized.
