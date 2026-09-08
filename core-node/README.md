# core-node

**Language:** Rust · **Author:** Ciprian Ștefan Pleșca

The P2P networking and zero-knowledge cryptography core of
zk-threat-exchange. This is the only component that ever touches raw
incident data — everything it emits to the rest of the system is a public
commitment plus a zero-knowledge proof.

## Layout

```
src/
├── main.rs          # binary entry point: detect → prove → ingest → gossip
├── zkp/mod.rs        # Schnorr/Fiat-Shamir non-interactive ZK proof of knowledge
├── p2p/mod.rs         # gossip broadcast layer (tokio::broadcast, TTL-bounded)
└── memory_pool/mod.rs # verified, deduplicated in-memory commitment store
```

## Running locally

```bash
cargo run
```

## Testing

```bash
cargo fmt -- --check   # formatting
cargo clippy --all-targets -- -D warnings   # lints
cargo test              # unit tests (6 tests across zkp, p2p, memory_pool)
```

## Key types

- `zkp::Witness` — the secret, derived from raw incident data. Never
  serialized, never transmitted.
- `zkp::ThreatProof` — the public, transmittable proof. Verifiable via
  `zkp::verify` without learning the witness.
- `p2p::GossipNode` — publishes/relays `GossipMessage`s (commitment + proof)
  to subscribers.
- `memory_pool::MemoryPool` — verifies every incoming commitment before
  accepting it; tracks corroboration counts for repeated observations.

See [`../docs/zero_knowledge_math.md`](../docs/zero_knowledge_math.md) for
the cryptographic details and known limitations of the current scheme.
