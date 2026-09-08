//! zk-threat-exchange :: core-node :: memory_pool
//! Author: Ciprian Ștefan Pleșca
//!
//! An in-memory, deduplicated pool of verified threat-indicator commitments.
//! Every accepted entry has already passed `zkp::verify` — the pool never
//! stores raw witnesses, only public commitments and their proofs.

use crate::zkp::{verify, ThreatProof};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub proof: ThreatProof,
    pub first_seen_unix: u64,
    pub seen_count: u32,
}

#[derive(Default)]
pub struct MemoryPool {
    entries: HashMap<u128, PoolEntry>,
}

impl MemoryPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Verify and, if valid, insert a new threat commitment. Returns true if
    /// the entry was newly accepted, false if invalid or already known.
    pub fn ingest(&mut self, commitment: u128, proof: ThreatProof) -> bool {
        if !verify(commitment, &proof) {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match self.entries.get_mut(&commitment) {
            Some(existing) => {
                existing.seen_count += 1;
                false // already known, just corroborated
            }
            None => {
                self.entries.insert(
                    commitment,
                    PoolEntry {
                        proof,
                        first_seen_unix: now,
                        seen_count: 1,
                    },
                );
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn corroboration_count(&self, commitment: u128) -> u32 {
        self.entries
            .get(&commitment)
            .map(|e| e.seen_count)
            .unwrap_or(0)
    }

    /// Retrieve the accepted proof for a commitment, e.g. so `enterprise-api`
    /// or a dashboard can re-display the raw proof bytes for audit purposes.
    pub fn get_proof(&self, commitment: u128) -> Option<&ThreatProof> {
        self.entries.get(&commitment).map(|e| &e.proof)
    }

    /// Unix timestamp (seconds) at which this commitment was first accepted
    /// into the pool — used for age-based prioritization/expiry policies.
    pub fn first_seen(&self, commitment: u128) -> Option<u64> {
        self.entries.get(&commitment).map(|e| e.first_seen_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::{prove, Witness};

    #[test]
    fn ingest_accepts_valid_proof_once() {
        let mut pool = MemoryPool::new();
        let witness = Witness::from_incident_logs(b"c2-beacon-pattern-observed");
        let commitment = witness.public_commitment();
        let proof = prove(&witness);

        assert!(pool.ingest(commitment, proof.clone()));
        assert_eq!(pool.len(), 1);
        // Second ingest of the same commitment corroborates, doesn't duplicate.
        assert!(!pool.ingest(commitment, proof));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.corroboration_count(commitment), 2);

        // Confirm the stored proof and first-seen timestamp are retrievable.
        assert!(pool.get_proof(commitment).is_some());
        assert!(pool.first_seen(commitment).unwrap() > 0);
    }

    #[test]
    fn get_proof_and_first_seen_return_none_for_unknown_commitment() {
        let pool = MemoryPool::new();
        assert!(pool.get_proof(999).is_none());
        assert!(pool.first_seen(999).is_none());
    }

    #[test]
    fn ingest_rejects_invalid_proof() {
        let mut pool = MemoryPool::new();
        let witness = Witness::from_incident_logs(b"data");
        let bogus_commitment = witness.public_commitment() + 1;
        let proof = prove(&witness);
        assert!(!pool.ingest(bogus_commitment, proof));
        assert!(pool.is_empty());
    }
}
