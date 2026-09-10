# core-node

**Language:** Rust · **Author:** Ciprian Ștefan Pleșca

The P2P networking and zero-knowledge cryptography core of
zk-threat-exchange. This is the only component that ever touches raw
incident data — everything it emits to the rest of the system is a public
commitment plus a zero-knowledge proof.

## Layout

```
src/
├── main.rs             # binary entry point: detect → prove → ingest → gossip
├── zkp/mod.rs           # Schnorr/Fiat-Shamir ZK proof of knowledge over Ristretto255
├── p2p/mod.rs            # real libp2p networking: TCP+Noise+Yamux, gossipsub, mDNS
└── memory_pool/mod.rs    # verified commitment store, persisted to SQLite
```

## Running locally

```bash
cargo run
```

This creates a `./data/<node-id>.sqlite3` file on first run — your accepted
commitments survive across restarts. Override the directory with `DB_DIR`.

To see real peer-to-peer gossip between two nodes on the same machine:

```bash
NODE_ID=node-a cargo run &
NODE_ID=node-b cargo run
```

They'll discover each other via mDNS on the local network and exchange
gossip messages over a real (encrypted) TCP connection. Each gets its own
`./data/node-a.sqlite3` / `./data/node-b.sqlite3` file.

## Testing

```bash
cargo fmt -- --check   # formatting
cargo clippy --all-targets -- -D warnings   # lints
cargo test              # unit + integration tests (uses in-memory SQLite, no files touched)
```

## Key types

- `zkp::Witness` — the secret, derived from raw incident data. Never
  serialized, never transmitted.
- `zkp::ThreatProof` — the public, transmittable proof (Ristretto255
  Schnorr/Fiat-Shamir). Verifiable via `zkp::verify` without learning the
  witness.
- `p2p::GossipNode` — a handle to a running libp2p node. `spawn()` starts
  the node (TCP+Noise+Yamux transport, gossipsub pub-sub, mDNS discovery);
  `publish()` broadcasts a threat proof to the network; `dial()` connects
  to a specific peer address explicitly (used for wide-area bootstrap and
  for deterministic tests that don't rely on mDNS).
- `memory_pool::MemoryPool` — verifies every incoming commitment before
  accepting it and persists it to SQLite; `open(path)` for a real file,
  `open_in_memory()` for tests. Tracks corroboration counts for repeated
  observations.

See [`../docs/zero_knowledge_math.md`](../docs/zero_knowledge_math.md) for
the cryptographic details and [`../docs/architecture.md`](../docs/architecture.md)
for how the networking and persistence layers fit into the overall data flow.
