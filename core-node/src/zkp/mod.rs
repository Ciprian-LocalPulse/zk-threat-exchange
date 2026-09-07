//! zk-threat-exchange :: core-node :: zkp
//! Author: Ciprian Ștefan Pleșca
//!
//! This module implements a **real, working, non-interactive zero-knowledge
//! proof of knowledge** (Schnorr protocol + Fiat-Shamir heuristic) that a node
//! knows a secret witness `w` (derived from its private incident data)
//! corresponding to a public threat-indicator commitment `y`, WITHOUT
//! revealing `w`.
//!
//! Honesty note: this is a Schnorr sigma-protocol over a small prime-order
//! group, chosen because it is a well-understood, provably zero-knowledge
//! primitive that can be implemented correctly without a circuit compiler.
//! It is *not* a general-purpose zk-SNARK (arithmetic circuit) system — see
//! `docs/zero_knowledge_math.md` for the full discussion, including what
//! would be required to upgrade this to a SNARK (e.g. Groth16 via `arkworks`)
//! for arbitrary statement circuits. The parameters here (small prime) are
//! for demonstration/testing; production deployment requires a
//! cryptographically-sized safe prime (2048+ bit) or an elliptic-curve group.

use rand::Rng;
use sha2::{Digest, Sha256};

/// A small, fixed cyclic group (Z_p*, generator g) used for the demo Schnorr
/// proof. Replace with a properly-sized safe prime or an EC group (e.g.
/// curve25519-dalek's Ristretto) before any production use.
pub const P: u128 = 2_147_483_647; // Mersenne prime 2^31 - 1
pub const G: u128 = 7; // generator (verified to have large order mod P for demo use)

fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}

/// The secret witness: never transmitted, never logged, never leaves the node.
pub struct Witness {
    pub w: u128,
}

impl Witness {
    /// Derive a witness deterministically from raw incident data (e.g. the
    /// compromised host's log excerpt) without ever exposing the raw data
    /// itself on the wire.
    pub fn from_incident_logs(raw_logs: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(raw_logs);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[0..16]);
        let w = u128::from_be_bytes(bytes) % (P - 1);
        Witness { w: if w == 0 { 1 } else { w } }
    }

    /// The public commitment y = g^w mod p. This is what gets published to
    /// the gossip network as the "threat indicator" — it reveals nothing
    /// about `w` (discrete-log hardness) but lets any peer verify a proof
    /// against it.
    pub fn public_commitment(&self) -> u128 {
        mod_pow(G, self.w, P)
    }
}

/// A non-interactive zero-knowledge proof (Fiat-Shamir transformed Schnorr
/// proof) that the prover knows `w` such that `y = g^w mod p`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatProof {
    pub commitment: u128, // t = g^r mod p
    pub challenge: u128,  // c = H(g, y, t)
    pub response: u128,   // s = r + c*w mod (p-1)
}

/// Generate a proof of knowledge of `witness.w` for the public value
/// `witness.public_commitment()`, without revealing `witness.w`.
pub fn prove(witness: &Witness) -> ThreatProof {
    let mut rng = rand::thread_rng();
    let r: u128 = rng.gen_range(1..P - 1);
    let t = mod_pow(G, r, P);
    let y = witness.public_commitment();

    let c = fiat_shamir_challenge(G, y, t);
    // s = r + c*w mod (p-1)
    let s = (r + (c % (P - 1)) * (witness.w % (P - 1))) % (P - 1);

    ThreatProof { commitment: t, challenge: c, response: s }
}

/// Verify a proof against the publicly known threat-indicator commitment `y`.
/// Returns true iff the prover knows the witness `w` behind `y`, without the
/// verifier ever learning `w`.
pub fn verify(y: u128, proof: &ThreatProof) -> bool {
    let lhs = mod_pow(G, proof.response, P);
    let rhs = (proof.commitment * mod_pow(y, proof.challenge, P)) % P;
    let recomputed_c = fiat_shamir_challenge(G, y, proof.commitment);
    recomputed_c == proof.challenge && lhs == rhs
}

fn fiat_shamir_challenge(g: u128, y: u128, t: u128) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(g.to_be_bytes());
    hasher.update(y.to_be_bytes());
    hasher.update(t.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[0..16]);
    u128::from_be_bytes(bytes) % (P - 1)
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
        assert!(!serialized.contains(&witness.w.to_string()));
    }
}
