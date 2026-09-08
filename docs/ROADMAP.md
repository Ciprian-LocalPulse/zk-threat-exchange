# Roadmap

**Author:** Ciprian Ștefan Pleșca

This roadmap tracks the path from the current `0.1.0` scaffold toward a
production-viable system. See [`CHANGELOG.md`](../CHANGELOG.md) for what has
already shipped.

## Phase 1 — Cryptographic hardening (pre-1.0 blocker)

- [ ] Replace the demo-sized Schnorr group with a production-sized safe
      prime or an elliptic-curve group (Curve25519 / BLS12-381).
- [ ] Evaluate and prototype a migration to a general-purpose zk-SNARK
      (Groth16 or PLONK via `arkworks`) for richer statement predicates
      beyond "I know a discrete log."
- [ ] Independent security review of `core-node/src/zkp/`.

## Phase 2 — Real network transport

- [ ] Replace the in-process `tokio::broadcast` gossip channel with
      `libp2p` (or a raw QUIC transport) for genuine multi-host gossip.
- [ ] Add peer discovery (mDNS for local networks, a bootstrap-node list
      for wide-area deployment).
- [ ] Add message signing at the transport layer (distinct from the ZKP
      itself) to prevent gossip-layer spoofing/DoS.

## Phase 3 — Persistence & scale

- [ ] Persistent storage for `core-node::memory_pool` (currently in-memory
      only; state is lost on restart).
- [ ] Persistent storage for `enterprise-api` (Postgres or similar) in place
      of the current in-memory map.
- [ ] Load testing and horizontal scaling story for `enterprise-api`.

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
