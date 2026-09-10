# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once
it reaches `1.0.0`. Before `1.0.0`, minor version bumps (`0.x.0`) may include
breaking changes.

## [Unreleased]

### Planned
- Implement the SNARK migration described in
  `docs/snark_migration_spike.md` once compound-predicate requirements are
  confirmed from real deployment needs.
- Bootstrap-node list / DHT-based peer discovery for wide-area deployment
  (current mDNS discovery only works on a local network segment).
- Replace the built-in HMAC JWT issuer in `enterprise-api` with real
  OIDC/SAML SSO support.
- Load testing and connection-pool tuning for `enterprise-api`'s Postgres
  store under real traffic.
- Backup/restore tooling for both the SQLite pool files and Postgres.

## [0.4.0] — 2026-09-10

**Persistence (Roadmap Phase 3, partial).**

> **Verification note:** unlike v0.3.0, this release's Go changes
> (`enterprise-api`) were fully compiled and tested locally against a real
> PostgreSQL 16 instance — 16/16 tests passing, `gofmt`/`go vet`/`go build`
> all clean. The Rust changes (`core-node`) could not be locally compiled
> for the same reason as v0.3.0 (the `libp2p` dependency tree added in
> v0.3.0 requires a newer Rust toolchain than this project's authoring
> sandbox has access to) — verify via this project's CI or a local
> `rustup`-managed toolchain before treating as field-tested.

### Changed
- **BREAKING:** `core-node::memory_pool::MemoryPool` no longer holds state
  in a `HashMap`. It now persists to an embedded SQLite database via
  `rusqlite`, opened with `MemoryPool::open(path)` (or
  `MemoryPool::open_in_memory()` for tests) instead of `MemoryPool::new()`.
  `get_proof` now returns an owned `Option<ThreatProof>` instead of
  `Option<&ThreatProof>`, since the proof is deserialized fresh from disk on
  each call rather than referenced from an in-process map.
- **BREAKING:** `enterprise-api`'s `handlers.Server` no longer holds an
  in-memory map + mutex. `handlers.NewServer` now takes a `*store.Store`
  (PostgreSQL-backed, `internal/store/store.go`) as a required parameter.
- `enterprise-api`'s `HandleListCommitments` response shape is unchanged
  (still a JSON array of commitment objects), but is now backed by a real
  `SELECT ... ORDER BY received_at DESC` query instead of an unordered map
  iteration — list order is now deterministic (most recent first).

### Added
- `core-node`: `MemoryPool` state now survives a process restart —
  verified by a new test that closes and reopens the same SQLite file and
  confirms the data is still there.
- `enterprise-api`: new `internal/store` package (PostgreSQL persistence,
  idempotent schema migration on startup, `Reset()` for test isolation).
- `enterprise-api`: 5 new integration tests in `internal/store/store_test.go`
  and 2 new tests in `internal/handlers/handlers_test.go` (including a
  restart-simulation test — ingest via one `Server`/`Store` instance, then
  confirm visibility from a brand new instance backed by the same database).
- `deployments/docker-compose.yml`: new `postgres` service (with a
  healthcheck gating `enterprise-api`'s startup) and named volumes for both
  Postgres data and `core-node`'s SQLite file, so `docker-compose down` /
  `up` cycles no longer silently wipe all state.
- `.github/workflows/go-tests.yml`: added a Postgres service container so
  the new store-layer tests run in CI, plus an explicit `gofmt -l` check
  (previously formatting was only fixed manually, never enforced by CI).

### Fixed
- `deployments/enterprise-api.Dockerfile` was missing `COPY
  enterprise-api/go.sum` — harmless while the project had zero external Go
  dependencies, but would have broken the Docker build the moment a real
  dependency (like this release's `lib/pq`) was added, since Go 1.16+
  defaults to `-mod=readonly` and refuses to build without a matching
  `go.sum`. Fixed before it could bite.
- `deployments/core-node.Dockerfile` was missing a C compiler
  (`build-essential`), needed because `rusqlite`'s `bundled` feature
  compiles SQLite from its C source at build time.

## [0.3.0] — 2026-09-09

**Real network transport (Roadmap Phase 2, partial).**

> **Verification note:** this release's networking code was developed and
> reviewed against the documented `libp2p` 0.53 API, but could not be
> compiled in the authoring environment (outdated local Rust toolchain
> unable to build the current `libp2p` dependency tree). It is verified via
> this project's CI (which runs a current Rust toolchain), not via local
> `cargo test` by the author at authoring time. Treat accordingly until CI
> is confirmed green and the code has had real field exposure.

### Changed
- **BREAKING:** `core-node/src/p2p/` no longer uses an in-process
  `tokio::broadcast` channel to simulate gossip. It now runs a real
  `libp2p` Swarm: TCP transport, Noise encryption, Yamux multiplexing,
  `gossipsub` pub-sub (the same protocol family used by Ethereum 2.0, IPFS,
  and Filecoin), and `mDNS` for automatic local-network peer discovery.
- **BREAKING:** `GossipNode::new` replaced by `GossipNode::spawn` (async,
  returns a `Result` and a `GossipHandle` bundling the node handle, an
  inbound message channel, and the resolved listen address).
- **BREAKING:** `GossipNode::publish` is now `async` and returns a
  `Result`, reflecting that publishing now involves real network I/O
  instead of an infallible in-process channel send.
- `main.rs` updated to the new async API: spawns the node, waits briefly
  for mDNS discovery, publishes a demo threat proof, then listens for
  inbound gossip for a bounded demo window.

### Added
- `GossipNode::dial` — explicit peer dialing, used by the test suite to
  validate message delivery deterministically without depending on mDNS
  (which requires UDP multicast support that isn't guaranteed in every CI
  environment).
- Two new `core-node` integration tests: a 2-node direct-dial gossip
  delivery test (publishes on node A, asserts receipt on node B over a real
  encrypted TCP connection) and a distinct-peer-ID sanity test.
- `docs/architecture.md` and `docs/ROADMAP.md` updated to reflect the real
  transport.

### Security
- Malformed/undeserializable gossip payloads from a peer are logged and
  dropped, never causing a panic — consistent with the same defensive
  posture already applied to `zkp::verify`.
- `gossipsub` is configured with `MessageAuthenticity::Signed`, meaning
  messages are cryptographically signed with the libp2p identity key at the
  transport layer, on top of the ZKP proof already carried in the payload.

## [0.2.0] — 2026-09-08

**Cryptographic hardening (Roadmap Phase 1, partial).**

### Changed
- **BREAKING:** `core-node/src/zkp/` now runs over **Ristretto255** (via
  `curve25519-dalek`) instead of the v0.1.0 toy 31-bit Mersenne-prime
  multiplicative group. `Witness::public_commitment()` and
  `ThreatProof`'s fields now return/store `[u8; 32]` canonical byte
  encodings instead of `u128` integers.
- **BREAKING:** `memory_pool::MemoryPool` and `p2p::GossipMessage` updated
  to use the new `memory_pool::Commitment` (`[u8; 32]`) type in place of
  `u128` throughout.
- `verify()` now rejects malformed/non-canonical input bytes gracefully
  (returns `false`) instead of assuming well-formed peer input.
- Witness derivation and the Fiat-Shamir challenge now use SHA-512 wide
  reduction (`Scalar::from_bytes_mod_order_wide`) instead of a 32-byte
  reduction, avoiding modulo bias relative to the group order.

### Added
- Three new `core-node` tests: malformed-commitment rejection, tampered-proof
  rejection, and distinct-witness-distinct-commitment.
- `memory_pool::MemoryPool::get_proof` / `first_seen` accessors (also fixes
  a `cargo clippy` dead-code lint from the fields being write-only).
- `docs/snark_migration_spike.md` — a concrete design document (chosen
  proving system, circuit sketch, effort estimate) for the future SNARK
  migration.

### Security
- The v0.1.0 demo-scale ZKP group (documented as insecure from initial
  release) has been fully replaced. See
  `docs/zero_knowledge_math.md`'s "Change history" section.

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
