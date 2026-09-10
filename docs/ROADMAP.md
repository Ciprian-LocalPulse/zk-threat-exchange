# Roadmap

**Author:** Ciprian Ștefan Pleșca

This roadmap tracks the path from the current `0.1.0` scaffold toward a
production-viable system. See [`CHANGELOG.md`](../CHANGELOG.md) for what has
already shipped.

## Phase 1 — Cryptographic hardening (pre-1.0 blocker)

- [x] Replace the demo-sized Schnorr group with a production-sized group —
      shipped in `v0.2.0` using Ristretto255 via `curve25519-dalek`.
- [x] Design (not yet implement) the migration to a general-purpose
      zk-SNARK — see [`docs/snark_migration_spike.md`](./snark_migration_spike.md)
      for the chosen proving system, circuit sketch, and effort estimate.
- [ ] Implement the SNARK migration once compound-predicate requirements are
      confirmed (see the spike doc's "Decision point" section).
- [ ] Independent security review of `core-node/src/zkp/`.

## Phase 2 — Real network transport

- [x] Replace the in-process `tokio::broadcast` gossip channel with
      `libp2p` — shipped in `v0.3.0` (TCP + Noise + Yamux transport,
      `gossipsub` pub-sub, matching the pattern used by Ethereum 2.0/IPFS).
- [x] Add peer discovery — mDNS shipped in `v0.3.0` for local-network
      discovery (LAN / Docker Compose network).
- [ ] Add a bootstrap-node list / DHT-based discovery for wide-area
      deployment (mDNS alone doesn't cross network boundaries).
- [ ] Add message signing at the transport layer (distinct from the ZKP
      itself) to prevent gossip-layer spoofing/DoS. Note: `gossipsub` with
      `MessageAuthenticity::Signed` (already configured) does sign messages
      with the libp2p identity key — evaluate whether this alone is
      sufficient or whether an additional application-layer signature is
      warranted.
- [ ] Load-test gossipsub mesh behavior beyond 2-node test coverage —
      current test suite validates 2-node direct-dial delivery only.
- [ ] Independent review of the new networking code (like the ZKP module,
      "compiles and passes 2-node tests" is not the same bar as "reviewed
      and field-tested").

## Phase 3 — Persistence & scale

- [x] Persistent storage for `core-node::memory_pool` — shipped in `v0.4.0`
      using embedded SQLite (`rusqlite`), namespaced per `NODE_ID`.
- [x] Persistent storage for `enterprise-api` — shipped in `v0.4.0` using
      PostgreSQL (`internal/store`), with a CI-verified integration test
      suite (16 tests against a real Postgres service container).
- [ ] Load testing and horizontal scaling story for `enterprise-api`. Note:
      the store layer is already safe for multiple `enterprise-api`
      replicas against one database (no in-process state), but this hasn't
      been load-tested.
- [ ] Database connection pooling tuning (`database/sql`'s default pool
      settings are used as-is; revisit under real load).
- [ ] Backup/restore story for both the SQLite pool files and the Postgres
      database — currently neither is backed up automatically.

## Phase 4 — Enterprise readiness

- [ ] Real OIDC/SAML SSO integration (replacing the built-in HMAC JWT
      issuer) — see `docs/enterprise_integration.md`.
- [ ] Native SOC connectors (Splunk, CrowdStrike, Microsoft Sentinel) beyond
      the current Make.com webhook bridge.
- [ ] Usage-based billing integration with a real payment processor.
- [ ] SLA monitoring and status page.

## Phase 5 — Detection intelligence

- [ ] Train `heuristics-engine`'s `ArchetypeLibrary` on real labeled
      incident data (with appropriate privacy safeguards) instead of the
      current illustrative starter set.
- [ ] Expand `rule-mutator`'s predicate vocabulary beyond
      `gt`/`lt`/`and`/`or`/`not`.
- [ ] Formal evaluation metrics (precision/recall over time) for the
      self-mutation feedback loop, published as a `docs/evaluation.md`.

## Contributing to the roadmap

Have a proposal for something not listed here? Open an issue using the
[feature request template](../.github/ISSUE_TEMPLATE/feature_request.md).
