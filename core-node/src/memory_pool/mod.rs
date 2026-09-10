//! zk-threat-exchange :: core-node :: memory_pool
//! Author: Ciprian Ștefan Pleșca
//!
//! A deduplicated pool of verified threat-indicator commitments, persisted
//! to an embedded SQLite database. Every accepted entry has already passed
//! `zkp::verify` — the pool never stores raw witnesses, only public
//! commitments and their proofs.
//!
//! ## v0.4.0 — persistence upgrade
//!
//! Earlier versions kept this pool in a `HashMap`, meaning every accepted
//! commitment was lost when the process restarted — a real problem for a
//! node meant to run continuously. This version persists to SQLite via
//! `rusqlite`, so the pool survives restarts, crashes, and redeploys.
//!
//! SQLite (embedded, file-backed) was chosen over a client-server database
//! deliberately: `core-node` is meant to run standalone on a single host
//! without requiring external infrastructure. `enterprise-api`, which *is*
//! a multi-tenant service, uses PostgreSQL instead — see
//! `enterprise-api/internal/store/`.
//!
//! Note on concurrency: `rusqlite::Connection` is used synchronously here.
//! `core-node`'s current call pattern only ever touches `MemoryPool` from a
//! single task (see `main.rs`), so this is safe as-is. If a future version
//! calls into the pool from multiple concurrent tasks (e.g. directly from
//! the `p2p` event loop rather than via a channel back to `main`), wrap
//! these calls in `tokio::task::spawn_blocking` to avoid blocking the async
//! runtime on disk I/O.

use crate::zkp::{verify, ThreatProof};
use rusqlite::{params, Connection, OptionalExtension};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Commitment = [u8; 32];

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS commitments (
        commitment      BLOB PRIMARY KEY,
        proof_json      TEXT NOT NULL,
        first_seen_unix INTEGER NOT NULL,
        seen_count      INTEGER NOT NULL
    );
";

pub struct MemoryPool {
    conn: Connection,
}

impl MemoryPool {
    /// Open (creating if necessary) a persistent, file-backed pool at
    /// `path`. The parent directory must already exist.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Open a transient, in-memory pool — used by the test suite so tests
    /// stay fast and fully isolated from the filesystem. Not called from
    /// `main.rs` (production always uses a real file via `open`), but kept
    /// public so external integration tests can use it too.
    #[allow(dead_code)]
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Verify and, if valid, insert a new threat commitment. Returns true if
    /// the entry was newly accepted, false if invalid or already known.
    pub fn ingest(&mut self, commitment: Commitment, proof: ThreatProof) -> bool {
        if !verify(commitment, &proof) {
            return false;
        }

        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT seen_count FROM commitments WHERE commitment = ?1",
                params![&commitment[..]],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);

        match existing {
            Some(count) => {
                let _ = self.conn.execute(
                    "UPDATE commitments SET seen_count = ?1 WHERE commitment = ?2",
                    params![count + 1, &commitment[..]],
                );
                false // already known, just corroborated
            }
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let proof_json = match serde_json::to_string(&proof) {
                    Ok(json) => json,
                    Err(_) => return false, // should never happen; fail closed
                };
                let inserted = self.conn.execute(
                    "INSERT INTO commitments (commitment, proof_json, first_seen_unix, seen_count)
                     VALUES (?1, ?2, ?3, 1)",
                    params![&commitment[..], proof_json, now as i64],
                );
                inserted.is_ok()
            }
        }
    }

    pub fn len(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM commitments", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|n| n as usize)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn corroboration_count(&self, commitment: Commitment) -> u32 {
        self.conn
            .query_row(
                "SELECT seen_count FROM commitments WHERE commitment = ?1",
                params![&commitment[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|n| n as u32)
            .unwrap_or(0)
    }

    /// Retrieve the accepted proof for a commitment, e.g. so `enterprise-api`
    /// or a dashboard can re-display the raw proof bytes for audit purposes.
    /// Returns an owned value (unlike the pre-persistence version, which
    /// could return a `&ThreatProof` directly into the in-memory map) since
    /// the proof now has to be deserialized fresh from disk on each call.
    pub fn get_proof(&self, commitment: Commitment) -> Option<ThreatProof> {
        let proof_json: Option<String> = self
            .conn
            .query_row(
                "SELECT proof_json FROM commitments WHERE commitment = ?1",
                params![&commitment[..]],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();
        proof_json.and_then(|json| serde_json::from_str(&json).ok())
    }

    /// Unix timestamp (seconds) at which this commitment was first accepted
    /// into the pool — used for age-based prioritization/expiry policies.
    pub fn first_seen(&self, commitment: Commitment) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT first_seen_unix FROM commitments WHERE commitment = ?1",
                params![&commitment[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|n| n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::{prove, Witness};

    #[test]
    fn ingest_accepts_valid_proof_once() {
        let mut pool = MemoryPool::open_in_memory().unwrap();
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
        let pool = MemoryPool::open_in_memory().unwrap();
        let unknown: Commitment = [7u8; 32];
        assert!(pool.get_proof(unknown).is_none());
        assert!(pool.first_seen(unknown).is_none());
    }

    #[test]
    fn ingest_rejects_invalid_proof() {
        let mut pool = MemoryPool::open_in_memory().unwrap();
        let witness = Witness::from_incident_logs(b"data");
        let mut bogus_commitment = witness.public_commitment();
        bogus_commitment[0] ^= 0x01; // corrupt one byte -> no longer matches the proof
        let proof = prove(&witness);
        assert!(!pool.ingest(bogus_commitment, proof));
        assert!(pool.is_empty());
    }

    #[test]
    fn state_persists_across_reopening_the_same_file() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "zk-threat-exchange-test-{}",
            std::process::id()
        ));
        
        // Creăm efectiv directorul înainte de a-l folosi
        std::fs::create_dir_all(&tmp_dir).expect("Eșec la crearea directorului temporar");
        
        let db_path = tmp_dir.join("pool.sqlite3");
        let db_path_str = db_path.to_str().unwrap();

        let witness = Witness::from_incident_logs(b"persistence-test-incident");
        let commitment = witness.public_commitment();
        let proof = prove(&witness);

        {
            let mut pool = MemoryPool::open(db_path_str).unwrap();
            assert!(pool.ingest(commitment, proof));
            assert_eq!(pool.len(), 1);
        } // pool (and its Connection) dropped here, simulating a restart

        {
            let reopened = MemoryPool::open(db_path_str).unwrap();
            assert_eq!(
                reopened.len(),
                1,
                "commitment should still be present after reopening the same DB file"
            );
            assert!(reopened.get_proof(commitment).is_some());
        }

        // Curățăm directorul la final
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}