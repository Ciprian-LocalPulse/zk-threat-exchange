# The Zero-Knowledge Math

**Author: Ciprian Ștefan Pleșca**

> **Status: v0.2.0.** This document describes the current, production-grade
> Ristretto255 implementation. The v0.1.0 toy implementation (a 31-bit
> Mersenne-prime multiplicative group) has been fully replaced — see
> `CHANGELOG.md` for the migration record. For the roadmap toward a
> general-circuit zk-SNARK, see
> [`docs/snark_migration_spike.md`](./snark_migration_spike.md).

## The problem, stated precisely

A node has observed evidence `w` (log excerpts, a compromised process's
behavior, a suspicious connection record) that a particular threat signature
was present on its infrastructure. It wants to publish that fact to a shared
network so other organizations can defend against the same attacker, **without
revealing `w`** — because `w` itself often contains exactly the sensitive
detail (internal hostnames, IP ranges, employee data) that made the breach
worth keeping quiet about in the first place.

Formally: given a public one-way relation `y = g^w mod p`, the node wants to
convince any verifier that it knows `w`, without revealing `w`, and without
any interaction beyond a single message (non-interactive).

## The protocol implemented in `core-node/src/zkp/mod.rs`

This is the classic **Schnorr identification protocol**, made non-interactive
via the **Fiat-Shamir heuristic**, running over **Ristretto255** — a
prime-order group built on Curve25519 via the `curve25519-dalek` crate. This
is the same primitive family underlying Signal, WireGuard, and Ed25519, and
gives ~128-bit security against the discrete-log problem. It has three
properties that make it a genuine zero-knowledge proof of knowledge:

1. **Completeness** — an honest prover who really knows `w` always convinces
   the verifier.
2. **Soundness** — a prover who does *not* know `w` can only produce a valid
   proof with negligible probability (bounded by the hardness of the
   discrete-log problem in Ristretto255).
3. **Zero-knowledge** — the proof transcript `(t, c, s)` reveals nothing about
   `w` beyond the fact that the prover knows it. This follows from the
   simulatability of Schnorr transcripts: a simulator who does *not* know `w`
   can produce transcripts indistinguishable from real ones by picking `s`
   and `c` first and computing `t = s·G - c·y`.

### Why Ristretto255, specifically

Raw Curve25519 points have a cofactor of 8: multiple distinct byte encodings
can represent group elements that differ only by a small-order component,
which is a classic source of protocol bugs (implicit signature malleability,
small-subgroup confinement attacks) when a protocol assumes prime order.
**Ristretto255** is a construction that produces a clean prime-order group
on top of Curve25519's fast, well-studied arithmetic — eliminating the
cofactor pitfall entirely while keeping the performance and implementation
maturity of Curve25519. It is the standard choice today for exactly this
kind of Schnorr-style discrete-log proof (it's what `ristretto255`-based
VRFs, ring signatures, and Signal's X3DH-adjacent primitives use).

### Step by step

**Setup (public):** the Ristretto255 base point `G` (a fixed constant,
`RISTRETTO_BASEPOINT_POINT`).

**Witness derivation:** `w = H_wide(raw_logs) mod ℓ`, where `H_wide` is
SHA-512 reduced via `Scalar::from_bytes_mod_order_wide` — a 64-byte wide
reduction, which avoids the modulo bias a naive 32-byte reduction would
introduce relative to the group order `ℓ`. The raw logs never leave the
node; only `w` (still secret) is derived from them, and only in memory.

**Public commitment:** `y = w · G`. This is what's published to the network
as the "threat indicator" — a compressed Ristretto point, 32 bytes.
Recovering `w` from `y` requires solving a discrete logarithm — believed
computationally infeasible for Ristretto255 at the ~128-bit security level.

**Proof generation (`prove`):**
1. Pick a random nonce `r` (sampled with 64 bytes of OS randomness, reduced
   via wide reduction for uniformity).
2. Compute `t = r · G` (the commitment).
3. Compute the challenge `c = H(G, y, t)` (Fiat-Shamir: a wide SHA-512 hash
   of the domain-separated transcript, reduced mod `ℓ`).
4. Compute the response `s = r + c·w mod ℓ` (scalar field arithmetic,
   handled by `curve25519-dalek`'s `Scalar` type).
5. Output `(t, c, s)`, each serialized as canonical 32-byte encodings. Note
   `w` and `r` never appear in the output — verified explicitly by
   `witness_never_appears_in_proof_bytes` in the test suite.

**Verification (`verify`):**
1. Reject immediately if `y` or `t` do not decompress to valid Ristretto
   points, or if `c`/`s` are not canonical scalar encodings (malformed input
   from an untrusted peer must never panic the node).
2. Recompute `c' = H(G, y, t)` and check `c' == c` (binds the proof to this
   specific `y`, preventing reuse against a different commitment).
3. Check `s·G ≡ t + c·y`.

If both checks pass, the verifier is convinced the prover knows `w`, and has
learned nothing else. See `core-node/src/zkp/mod.rs`'s test module for six
tests covering completeness, soundness against a wrong commitment,
witness-non-leakage, malformed-input rejection, and tamper-detection.

## What would be needed for a full zk-SNARK

The README describes this system as "Zero-Knowledge Threat Intelligence,"
and Schnorr proofs are honestly zero-knowledge — but they can only prove
knowledge of a discrete logarithm, a narrow statement. A production system
that wants to prove richer statements (e.g. "this event matches attack
signature pattern X AND was observed within the last 24 hours AND the
reporting node has degree ≥ 3 in the trust graph") needs a general-purpose
proof system over arithmetic circuits:

- **Groth16** (via `arkworks` or `bellman` in Rust) — smallest proofs, but
  requires a per-circuit trusted setup ceremony.
- **PLONK** / **Halo2** — universal or updatable setup, more flexible circuit
  design, larger proofs than Groth16.
- **Bulletproofs** — no trusted setup at all, good for range proofs, larger
  proof sizes and slower verification than SNARKs.

Migrating from the Schnorr scaffold here to a SNARK means: (1) expressing the
detection predicate as an arithmetic circuit, (2) running a setup ceremony
(trusted or transparent depending on the scheme), and (3) replacing
`prove`/`verify` with the corresponding circuit-prover/circuit-verifier calls.
The public interface (`ThreatProof`, `memory_pool::ingest`) is designed to be
swappable without touching the gossip or Go API layers.

**A concrete design for this migration — chosen proving system, circuit
sketch, dependency plan, and a working minimal Groth16 spike — is in
[`docs/snark_migration_spike.md`](./snark_migration_spike.md).**

## Change history

| Version | Group | Notes |
|---|---|---|
| v0.1.0 | Multiplicative group mod a 31-bit Mersenne prime | Toy parameters for pedagogical clarity; **not secure**, documented as such from the start. |
| v0.2.0 (current) | Ristretto255 (via `curve25519-dalek`) | Production-grade prime-order group, ~128-bit security, same primitive family as Signal/WireGuard/Ed25519. |
