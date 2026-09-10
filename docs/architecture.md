# Architecture

**Author: Ciprian Ștefan Pleșca**

## Data flow, end to end

```
   [ compromised host / SOC log ]
                │
                ▼
   core-node (Rust)  ──── Witness::from_incident_logs()
                │
                ▼
   ZKP proof (Schnorr/Fiat-Shamir)  ──── prove(witness)
                │
                ▼
   Gossip broadcast (real libp2p: TCP+Noise+Yamux,
   gossipsub pub-sub, mDNS discovery)  ──── GossipNode::publish()
                │
        ┌───────┴────────┐
        ▼                ▼
  peer core-nodes    enterprise-api (Go)
  memory_pool::ingest()   /v1/commitments/ingest
        │                │
        ▼                ▼
 heuristics-engine   Enterprise dashboard
 (Julia) scores          + billing meter
 event vs archetypes     + SOC webhook (Make.com)
        │
        ▼
 rule-mutator (Scheme)
 mutates detection rule
 if drift is significant
        │
        ▼
 Sandbox backtest (eval_sandbox.scm)
 accept-mutation? gate
        │
        ▼
 New rule generation gossiped
 to the whole network
```

## Component responsibilities

### core-node (Rust)
- Owns the only code path that ever touches raw incident data (`Witness`).
- Produces a `ThreatProof` that a peer can verify against a public
  `commitment` without learning `w`.
- Runs the gossip layer (`p2p::GossipNode`) and the local `memory_pool`,
  which only ever stores public commitments + proofs + corroboration counts,
  persisted to an embedded SQLite database (survives restarts as of v0.4.0).

### heuristics-engine (Julia)
- Consumes locally observed event features (entropy, timing, destination
  rarity, payload similarity) — **not** the ZK witness itself — and scores
  them against a library of attack archetypes via cosine similarity.
- Combines that local score with network corroboration counts (from
  `memory_pool`) into a posterior risk estimate (`posterior_risk`).

### rule-mutator (Scheme)
- Represents every detection rule as an s-expression (data, not compiled
  bytecode), so "the rule changes itself" is literally "a new list is
  produced" (`mutate-rule` / `mutate-threshold`).
- Every mutation must pass `eval_sandbox.scm`'s backtest gate
  (`accept-mutation?`) against a labeled sample set before it is allowed to
  propagate — this is the safety valve against auto-mutating into a rule
  that starts flagging legitimate traffic.

### enterprise-api (Go)
- The only component that talks to paying customers directly.
- Wraps the open-source core in gRPC/REST, adds JWT-based auth and
  role-based access control (`viewer` / `analyst` / `admin`), and meters
  usage for invoicing.
- Persists commitments, dashboard data, and billing counters to PostgreSQL
  (`internal/store`) as of v0.4.0 — state survives restarts and supports
  running multiple API replicas against the same database.

## Trust boundaries

| Boundary | What crosses it | What never crosses it |
|---|---|---|
| Host → core-node | Raw logs (local only, in-process) | — |
| core-node → gossip network | `ThreatProof` + public `commitment` | The witness `w`, raw logs |
| core-node → heuristics-engine | Statistical feature vector (`AttackVector`) | Raw logs, witness |
| Any component → enterprise-api | Commitments, corroboration counts, billing events | Raw logs, witness, private keys |

## Known limitations (be honest with yourself before a real deployment)

1. ~~The ZKP module ships a Schnorr sigma-protocol over a small prime.~~
   **Resolved in v0.2.0** — now runs over Ristretto255 (~128-bit security).
   The remaining crypto item is the SNARK migration for compound predicates
   — see `docs/snark_migration_spike.md`.
2. `enterprise-api`'s JWT implementation is a minimal HMAC-SHA256 scheme for
   demonstration; swap in a vetted library or a real IdP (Auth0, Okta,
   Keycloak) before handling real customer credentials.
3. ~~The gossip layer is an in-process `tokio::broadcast` channel.~~
   **Resolved in v0.3.0** — `core-node/src/p2p/` now runs real `libp2p`
   networking (TCP + Noise + Yamux transport, `gossipsub` pub-sub, `mDNS`
   discovery). This is newly implemented and has not yet had field time or
   independent review — treat it as "real transport, not yet battle-tested,"
   not as "production-hardened."
