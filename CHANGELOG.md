# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once
it reaches `1.0.0`. Before `1.0.0`, minor version bumps (`0.x.0`) may include
breaking changes.

## [Unreleased]

### Planned
- Replace the demo Schnorr group (`P = 2^31 - 1`) with a production-sized
  safe prime or an elliptic-curve group (Curve25519 / BLS12-381).
- Evaluate migrating `core-node/src/zkp/` to a general-purpose zk-SNARK
  (Groth16 or PLONK via `arkworks`) to support richer statement predicates.
- Replace the in-process `tokio::broadcast` gossip transport with a real
  network layer (`libp2p` or a raw QUIC transport) for genuine multi-host
  deployment.
- Replace the built-in HMAC JWT issuer in `enterprise-api` with real
  OIDC/SAML SSO support.
- Persistent storage for `core-node::memory_pool` and `enterprise-api`
  (currently both in-memory only; state is lost on restart).

## [0.1.0] — 2026-09-07

Initial public scaffold. Author: **Ciprian Ștefan Pleșca**.

### Added
- **core-node (Rust):**
  - Zero-knowledge proof module (`zkp/`) implementing a non-interactive
    Schnorr proof of knowledge (Fiat-Shamir transform), with a full test
    suite verifying completeness, soundness against a wrong commitment, and
    that the witness never appears in serialized proof bytes.
  - P2P gossip module (`p2p/`) using a `tokio::broadcast` channel to model
    TTL-bounded fan-out propagation of threat proofs.
  - In-memory proof pool (`memory_pool/`) that verifies every incoming
    commitment before accepting it, with corroboration counting for
    duplicate observations.
  - Binary entry point demonstrating the full local flow: detect → prove →
    ingest → gossip.
- **heuristics-engine (Julia):**
  - `tensor_models.jl`: `AttackVector` feature representation, cosine
    similarity, Shannon entropy of byte sequences, L2 normalization.
  - `threat_inference.jl`: a starter `ArchetypeLibrary` of known attack
    patterns and a `posterior_risk` function combining local similarity
    score with network corroboration count.
  - Full `Test`-based test suite (`test/runtests.jl`).
- **rule-mutator (Scheme):**
  - `macros.scm`: rules represented as s-expressions; predicate evaluation
    (`gt`/`lt`/`and`/`or`/`not` combinators); `mutate-rule` /
    `mutate-threshold` for runtime AST rewriting of detection thresholds.
  - `eval_sandbox.scm`: a backtest harness (`backtest`) and an
    `accept-mutation?` gate that only allows a mutated rule to propagate if
    it does not regress accuracy or introduce new false positives beyond
    tolerance.
  - Guile test suite (`test/run_tests.scm`) demonstrating an end-to-end
    scenario: an evolved attack evades the original rule, is caught by the
    mutated rule, and the mutation passes the sandbox gate.
- **enterprise-api (Go):**
  - Dependency-free HMAC-SHA256 JWT-style token issuer/verifier
    (`internal/auth/`) with three roles (`viewer`, `analyst`, `admin`) and
    role-hierarchy enforcement.
  - REST handlers (`internal/handlers/`) for commitment ingestion, dashboard
    listing, billing summary, and an unauthenticated health check.
  - Usage-based `BillingMeter` tracking total verifications and distinct
    connected nodes.
  - Full `go test` suite covering auth issuance/verification/tampering and
    handler-level RBAC enforcement.
- **Deployments:**
  - `Dockerfile`s for all three services and a `docker-compose.yml` for a
    zero-cost local stack.
  - A Make.com blueprint for relaying high-corroboration alerts to a SOC
    channel/inbox.
- **CI:** GitHub Actions workflows for Rust, Go, Julia, and Scheme test
  suites, plus a Docker build-verification workflow.
- **Documentation:** `README.md` (project pitch), `docs/architecture.md`,
  `docs/zero_knowledge_math.md` (including an explicit "known limitations"
  section), `docs/enterprise_integration.md`, `CONTRIBUTING.md`,
  `SECURITY.md`.

### Known Limitations (tracked, not hidden)
- ZKP group size is demo-scale, not production-scale (see
  `docs/zero_knowledge_math.md`).
- Gossip transport is in-process only, not a real network layer yet.
- JWT issuer is a development stand-in, not a vetted auth library or IdP.
