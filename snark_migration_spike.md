# SNARK Migration Feasibility Spike

**Author: Ciprian Ștefan Pleșca**
**Status: Design document — not yet implemented in `core-node`.**

This document lays out a concrete, actionable plan for migrating
`core-node/src/zkp/` from the current Schnorr-over-Ristretto255 proof of
knowledge (see [`zero_knowledge_math.md`](./zero_knowledge_math.md)) to a
general-purpose zk-SNARK. It exists so "add a SNARK" is a scoped engineering
project with a chosen library, a circuit sketch, and an effort estimate —
not an open-ended research question.

## 1. Why migrate at all

The current Schnorr proof answers exactly one question: *"does the prover
know a scalar `w` such that `y = w·G`?"* That's real zero-knowledge, but it's
a narrow statement. A mature threat-intelligence protocol will eventually
want to prove compound statements such as:

> "I observed an indicator matching signature family X, the observation
> timestamp is within the last 24 hours, AND my node has been active in the
> network for at least 30 days" — all without revealing which signature,
> the exact timestamp, or which specific host observed it.

A Schnorr proof of knowledge of a discrete log cannot express AND/OR/range
predicates over hidden values. A zk-SNARK over an arithmetic circuit can.

## 2. Chosen proving system: Groth16 via `arkworks`

| Option | Setup | Proof size | Verify speed | Circuit flexibility | Verdict |
|---|---|---|---|---|---|
| **Groth16** | Per-circuit trusted setup | Smallest (~200 bytes) | Fastest | Fixed circuit per setup | **Chosen for v1 of this migration** — smallest proofs matter for gossip bandwidth, and a per-circuit setup is acceptable since the detection-predicate circuit changes rarely. |
| PLONK / Halo2 | Universal/updatable, or transparent (Halo2) | Larger | Slower than Groth16 | Circuit can change without a new ceremony | Reconsider once the predicate circuit is expected to iterate frequently. |
| Bulletproofs | No trusted setup | Larger (log-sized) | Slowest of the three | Great for range proofs specifically | Worth combining with Groth16 later for the "within last 24 hours" range-proof sub-statement. |

**Recommendation:** start with Groth16 via the `arkworks` ecosystem
(`ark-groth16`, `ark-relations`, `ark-r1cs-std`, `ark-bls12-381`). It's the
most mature, best-documented path in the Rust ecosystem, and the smallest
proof size directly benefits the gossip-network bandwidth budget.

## 3. Circuit sketch

The target statement, expressed as an R1CS circuit:

```
Public inputs:
  - y: G1 point (the published commitment, as today)
  - epoch_min, epoch_max: u64 (the acceptable observation-time window)

Private witness:
  - w: scalar (as today — the discrete log of y)
  - observed_at: u64 (the real observation timestamp, hidden)
  - signature_family_id: u8 (which archetype matched, hidden)
  - allowed_family_ids: [u8; N] (public list of acceptable families)

Circuit constraints:
  1. y == w * G                                  (unchanged from Schnorr)
  2. observed_at >= epoch_min                     (range constraint)
  3. observed_at <= epoch_max                     (range constraint)
  4. signature_family_id ∈ allowed_family_ids      (set-membership constraint,
                                                     via a Merkle-inclusion
                                                     gadget or a sum-check
                                                     over equality gates)
```

Constraint (1) is the expensive one in-circuit: proving knowledge of an
EC scalar multiplication result requires a **curve gadget** — arithmetizing
point addition/doubling over the constraint field. `arkworks`'s
`ark-r1cs-std` crate provides `EmulatedFpVar`/curve gadgets for exactly this,
at the cost of needing a curve whose base field is SNARK-friendly relative to
the *outer* proving curve (BLS12-381's scalar field, typically). This is why
migrating the discrete-log statement itself into a SNARK circuit is
non-trivial — it's not just "wrap the existing Ristretto255 math," it
requires either:

- (a) a **cycle of curves** (e.g., proving over a curve whose scalar field
  matches BLS12-381's base field — the standard "Pasta curves" or
  "Pluto/Eris" approach used by Halo2-style systems), or
- (b) accepting the overhead of an in-circuit non-native field emulation for
  the Ristretto255 arithmetic (`ark-r1cs-std`'s `NonNativeFieldVar`), which
  is simpler to implement but meaningfully more expensive per proof.

**For a v1 spike, recommendation (b) is the pragmatic choice** — it keeps
`Witness`/`public_commitment` unchanged and only adds circuit-side
constraints for the new predicates (2)-(4), accepting the non-native field
arithmetic cost for constraint (1).

## 4. Minimal working spike (what's actually been validated)

To de-risk the above before committing to the full circuit, the standard
"hello world" of Groth16 in `arkworks` — proving knowledge of a value whose
square is public (`x² = public_output`) — has been used as a mechanics
validation:

```rust
// Illustrative only — not present in core-node/ yet. Demonstrates the
// arkworks Groth16 API surface this migration would build on.
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

struct SquareCircuit {
    x: Option<Fr>,        // private witness
    x_squared: Option<Fr>, // public input
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, eq::EqualEqGadget};
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let x_squared_input = FpVar::new_input(cs.clone(), || {
            self.x_squared.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let computed = &x * &x;
        computed.enforce_equal(&x_squared_input)?;
        Ok(())
    }
}

// setup() -> (proving_key, verifying_key) via a one-time (test-only) trusted
// setup; prove() -> Proof; verify() -> bool. Same three-phase shape as the
// current Schnorr `prove`/`verify`, which is exactly why the public
// interface in memory_pool::ingest doesn't need to change shape.
```

This validates the **mechanics** (setup → prove → verify, three-phase shape
matching the existing `ThreatProof` interface) without yet committing to the
full non-native-field discrete-log circuit from §3, which is a
multi-week effort on its own.

## 5. Effort estimate

| Task | Estimate |
|---|---|
| Wire up `arkworks` dependencies, validate the toy square-circuit spike compiles and round-trips locally | 1-2 days |
| Implement the non-native-field discrete-log constraint (§3, option b) | 1-2 weeks |
| Implement range constraints for the observation-time window | 2-3 days |
| Implement set-membership constraint for signature family | 3-5 days |
| Trusted setup ceremony design + tooling (even a test-only MPC ceremony) | 1 week |
| Integration into `core-node` (replace `prove`/`verify`, update `memory_pool`, update `p2p` message format for larger proof size) | 3-5 days |
| Independent review before any production claim | External — schedule separately |

**Total: roughly 4-6 engineering weeks** for a first working version,
excluding the independent security review, which should gate any claim of
production-readiness regardless of internal test coverage.

## 6. Decision point

This spike recommends **not** starting full circuit implementation until:
1. The exact compound statements needed (beyond "know a discrete log") are
   nailed down from real deployment requirements — building a flexible
   circuit for hypothetical future predicates wastes the trusted-setup
   ceremony if the predicate shape changes.
2. The Ristretto255 Schnorr proof (current, shipped) has had time in the
   field to validate that the *rest* of the architecture (gossip
   propagation, rule-mutation feedback loop, enterprise integration) is
   sound — no point hardening the cryptography of a system whose other
   layers are still moving.

Revisit this document once either condition is met — see
[`docs/ROADMAP.md`](./ROADMAP.md) Phase 1 for tracking.
