//! zk-threat-exchange :: core-node :: zkp
//! Author: Ciprian Ștefan Pleșca
//!
//! Non-interactive zero-knowledge proof of knowledge (Schnorr protocol +
//! Fiat-Shamir heuristic) that a node knows a secret witness `w` (derived
//! from its private incident data) corresponding to a public
//! threat-indicator commitment `y`, WITHOUT revealing `w`.
//!
//! ## v0.2.0 cryptographic upgrade
//!
//! This module now runs over **Ristretto255**, a prime-order group built on
//! Curve25519 via the `curve25519-dalek` crate — the same primitive family
//! used by Signal, WireGuard, and Ed25519. This replaces the v0.1.0 toy
//! implementation, which ran the identical Schnorr math over a 31-bit
//! Mersenne-prime multiplicative group for pedagogical clarity only.
//!
//! Ristretto255 gives us, for free:
//! - A prime-order group with no cofactor pitfalls (unlike raw Curve25519
//!   points, which have a cofactor of 8 and require careful handling to
//!   avoid small-subgroup attacks).
//! - ~128-bit security against the discrete-log problem, matching the
//!   security level assumed by every other primitive in this stack
//!   (SHA-256, AES-128-equivalent).
//! - Constant-time scalar/point arithmetic from a widely reviewed,
//!   production-grade library, instead of a hand-rolled `mod_pow`.
//!
//! This is still a Schnorr proof of knowledge — it proves "I know a
//! discrete log," not an arbitrary circuit predicate. See
//! `docs/zero_knowledge_math.md` for the full writeup and the SNARK
//! migration design (`docs/snark_migration_spike.md`) for what a
//! general-circuit upgrade (Groth16/PLONK) would require.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};

/// The secret witness: never transmitted, never logged, never leaves the
/// node's process memory.
pub struct Witness {
    w: Scalar,
}

impl Witness {
    /// Derive a witness deterministically from raw incident data (e.g. a
    /// compromised host's log excerpt) without ever exposing the raw data
    /// itself on the wire. Uses a wide (64-byte) hash reduction so the
    /// resulting scalar is uniformly distributed over the group order,
    /// avoiding the modulo bias a naive 32-byte reduction could introduce.
    pub fn from_incident_logs(raw_logs: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"zk-threat-exchange/witness-derivation/v1");
        hasher.update(raw_logs);
        let digest = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Witness {
            w: Scalar::from_bytes_mod_order_wide(&wide),
        }
    }

    /// The public commitment `y = w * G`. This is what gets published to
    /// the gossip network as the "threat indicator." Recovering `w` from
    /// `y` requires solving the Ristretto255 discrete-log problem —
    /// computationally infeasible at the ~128-bit security level.
    pub fn public_commitment(&self) -> [u8; 32] {
        (self.w * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
    }
}

/// A non-interactive zero-knowledge proof (Fiat-Shamir transformed Schnorr
/// proof) that the prover knows `w` such that `y = w * G`. All fields are
/// serialized as raw compressed/scalar bytes so `ThreatProof` can cross the
/// gossip network and the enterprise API without depending on
/// `curve25519-dalek`'s (optional) serde feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatProof {
    /// Compressed Ristretto point `t = r * G`.
    pub commitment: [u8; 32],
    /// Fiat-Shamir challenge scalar `c = H(G, y, t)`, as canonical bytes.
    pub challenge: [u8; 32],
    /// Response scalar `s = r + c*w`, as canonical bytes.
    pub response: [u8; 32],
}

/// Generate a proof of knowledge of `witness.w` for the public value
/// `witness.public_commitment()`, without revealing `witness.w`.
pub fn prove(witness: &Witness) -> ThreatProof {
    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 64];
    rng.fill_bytes(&mut nonce_bytes);
    let r = Scalar::from_bytes_mod_order_wide(&nonce_bytes);

    let t_point = r * RISTRETTO_BASEPOINT_POINT;
    let t = t_point.compress().to_bytes();
    let y = witness.public_commitment();

    let c = fiat_shamir_challenge(&y, &t);
    let s = r + c * witness.w;

    ThreatProof {
        commitment: t,
        challenge: c.to_bytes(),
        response: s.to_bytes(),
    }
}

/// Verify a proof against the publicly known threat-indicator commitment
/// `y`. Returns `false` (never panics) on any malformed input — a peer
/// sending garbage bytes should be rejected, not crash the node.
pub fn verify(y: [u8; 32], proof: &ThreatProof) -> bool {
    let (Some(y_point), Some(t_point)) = (
        CompressedRistretto(y).decompress(),
        CompressedRistretto(proof.commitment).decompress(),
    ) else {
        return false;
    };

    let c = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.challenge)) {
        Some(c) => c,
        None => return false,
    };
    let s = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.response)) {
        Some(s) => s,
        None => return false,
    };

    let recomputed_c = fiat_shamir_challenge(&y, &proof.commitment);
    if recomputed_c != c {
        return false;
    }

    // Check: s*G == t + c*y
    let lhs = s * RISTRETTO_BASEPOINT_POINT;
    let rhs = t_point + c * y_point;
    lhs == rhs
}

fn fiat_shamir_challenge(y: &[u8; 32], t: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"zk-threat-exchange/fiat-shamir/v1");
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().to_bytes());
    hasher.update(y);
    hasher.update(t);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verifies_for_honest_prover() {
        let witness = Witness::from_incident_logs(b"suspicious-connection-to-185.220.101.7");
        let y = witness.public_commitment();
        let proof = prove(&witness);
        assert!(verify(y, &proof));
    }

    #[test]
    fn proof_fails_for_wrong_commitment() {
        let witness = Witness::from_incident_logs(b"real-incident-data");
        let other = Witness::from_incident_logs(b"unrelated-data");
        let proof = prove(&witness);
        assert!(!verify(other.public_commitment(), &proof));
    }

    #[test]
    fn witness_never_appears_in_proof_bytes() {
        let witness = Witness::from_incident_logs(b"top-secret-server-credentials-12345");
        let proof = prove(&witness);
        let serialized = serde_json::to_string(&proof).unwrap();
        // The witness scalar's canonical byte encoding must not appear
        // anywhere in the serialized proof.
        let witness_hex = hex::encode(witness.w.to_bytes());
        assert!(!serialized.contains(&witness_hex));
    }

    #[test]
    fn verify_rejects_malformed_commitment_bytes() {
        // All-0xFF is not a valid compressed Ristretto point encoding.
        let bogus_y = [0xFFu8; 32];
        let witness = Witness::from_incident_logs(b"data");
        let proof = prove(&witness);
        assert!(!verify(bogus_y, &proof));
    }

    #[test]
    fn verify_rejects_tampered_response() {
        let witness = Witness::from_incident_logs(b"data");
        let y = witness.public_commitment();
        let mut proof = prove(&witness);
        // Flip a byte in the response scalar — proof must no longer verify.
        proof.response[0] ^= 0x01;
        assert!(!verify(y, &proof));
    }

    #[test]
    fn different_witnesses_produce_different_commitments() {
        let a = Witness::from_incident_logs(b"incident-a");
        let b = Witness::from_incident_logs(b"incident-b");
        assert_ne!(a.public_commitment(), b.public_commitment());
    }
}
