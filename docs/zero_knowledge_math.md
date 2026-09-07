# The Zero-Knowledge Math

**Author: Ciprian Ștefan Pleșca**

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
via the **Fiat-Shamir heuristic** (replacing the verifier's random challenge
with a hash of the transcript so far). It has three properties that make it
a genuine zero-knowledge proof of knowledge:

1. **Completeness** — an honest prover who really knows `w` always convinces
   the verifier.
2. **Soundness** — a prover who does *not* know `w` can only produce a valid
   proof with negligible probability (bounded by the hardness of the
   discrete-log problem in the chosen group).
3. **Zero-knowledge** — the proof transcript `(t, c, s)` reveals nothing about
   `w` beyond the fact that the prover knows it. This follows from the
   simulatability of Schnorr transcripts: a simulator who does *not* know `w`
   can produce transcripts indistinguishable from real ones by picking `s`
   and `c` first and computing `t = g^s · y^(-c) mod p`.

### Step by step

**Setup (public):** a group generator `g` and modulus `p` (in the repo:
`G = 7`, `P = 2^31 - 1`, a Mersenne prime — chosen for a fast, dependency-free
demo; see the limitations note below).

**Witness derivation:** `w = SHA256(raw_logs) mod (p-1)`. The raw logs never
leave the node; only `w` (still secret) is derived from them, and only in
memory.

**Public commitment:** `y = g^w mod p`. This is what's published to the
network as the "threat indicator." Recovering `w` from `y` requires solving
a discrete logarithm — believed computationally infeasible for a
correctly-sized group.

**Proof generation (`prove`):**
1. Pick a random nonce `r`.
2. Compute `t = g^r mod p` (the commitment).
3. Compute the challenge `c = H(g, y, t)` (Fiat-Shamir: hash stands in for an
   interactive verifier's random challenge).
4. Compute the response `s = r + c·w mod (p-1)`.
5. Output `(t, c, s)`. Note `w` and `r` never appear in the output.

**Verification (`verify`):**
1. Recompute `c' = H(g, y, t)` and check `c' == c` (binds the proof to this
   specific `y`, preventing reuse against a different commitment).
2. Check `g^s ≡ t · y^c (mod p)`.

If both checks pass, the verifier is convinced the prover knows `w`, and has
learned nothing else.

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
