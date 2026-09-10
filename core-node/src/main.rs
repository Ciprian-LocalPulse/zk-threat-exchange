//! zk-threat-exchange :: core-node
//! Author: Ciprian Ștefan Pleșca
//!
//! Entry point for the P2P zero-knowledge threat intelligence node.

mod memory_pool;
mod p2p;
mod zkp;

use memory_pool::MemoryPool;
use p2p::GossipNode;
use std::time::Duration;
use zkp::{prove, Witness};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("=== zk-threat-exchange core-node ===");
    println!("Author: Ciprian Ștefan Pleșca");

    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-local".to_string());

    // Persistent state: defaults to a per-node file in ./data/, overridable
    // via DB_DIR (e.g. for a custom volume mount in a container). Always
    // namespaced by node_id so multiple nodes can safely share one DB_DIR
    // (e.g. a single mounted volume in docker-compose) without clashing.
    let db_dir = std::env::var("DB_DIR").unwrap_or_else(|_| "./data".to_string());
    std::fs::create_dir_all(&db_dir).ok();
    let db_path = format!("{db_dir}/{node_id}.sqlite3");
    let mut pool = MemoryPool::open(&db_path)?;
    println!("[{node_id}] persistent pool state: {db_path}");

    let handle = GossipNode::spawn(&node_id).await?;
    let node = handle.node;
    let mut inbound = handle.inbound;

    println!(
        "[{node_id}] node online (peer id {}), listening on {}.",
        node.peer_id(),
        handle.listen_addr
    );

    // Explicit bootstrap peer support: mDNS only discovers peers on the
    // same local network segment (see docs/ROADMAP.md Phase 2). Setting
    // BOOTSTRAP_PEER to a known peer's multiaddr (e.g.
    // "/ip4/203.0.113.5/tcp/4001") lets this node dial it directly,
    // which is how a wide-area deployment bridges separate network
    // segments until a proper DHT/bootstrap-list mechanism lands.
    if let Ok(bootstrap_addr) = std::env::var("BOOTSTRAP_PEER") {
        match bootstrap_addr.parse() {
            Ok(addr) => {
                println!("[{node_id}] dialing configured bootstrap peer {bootstrap_addr}...");
                if let Err(e) = node.dial(addr).await {
                    println!("[{node_id}] failed to dial bootstrap peer: {e}");
                }
            }
            Err(e) => {
                println!("[{node_id}] BOOTSTRAP_PEER is not a valid multiaddr: {e}");
            }
        }
    }

    println!(
        "[{node_id}] waiting a moment for mDNS to discover any peers on this network..."
    );
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Demo: simulate detecting a threat locally, proving it in zero
    // knowledge, and gossiping the proof to the real P2P network.
    let witness = Witness::from_incident_logs(b"anomalous-outbound-tls-to-known-c2-range");
    let commitment = witness.public_commitment();
    let proof = prove(&witness);

    pool.ingest(commitment, proof.clone());
    node.publish(commitment, proof, 8).await?;

    println!(
        "[{node_id}] published threat commitment {} without revealing the witness.",
        hex::encode(commitment)
    );
    println!(
        "[{node_id}] local pool size: {} (empty: {})",
        pool.len(),
        pool.is_empty()
    );
    println!(
        "[{node_id}] corroboration count for this commitment: {}",
        pool.corroboration_count(commitment)
    );
    if let Some(first_seen) = pool.first_seen(commitment) {
        println!("[{node_id}] this commitment was first accepted at unix time {first_seen}.");
    }
    if pool.get_proof(commitment).is_some() {
        println!("[{node_id}] stored proof is retrievable for audit purposes.");
    }

    println!("[{node_id}] listening for gossip from peers for 10 seconds...");
    let listen_deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(listen_deadline);
    loop {
        tokio::select! {
            Some(msg) = inbound.recv() => {
                let accepted = pool.ingest(msg.commitment, msg.proof);
                println!(
                    "[{node_id}] received gossip from '{}' (ttl={}) — newly accepted: {accepted}",
                    msg.node_id, msg.ttl
                );
            }
            _ = &mut listen_deadline => {
                break;
            }
        }
    }

    println!("[{node_id}] demo window complete. In a real deployment this node keeps running (Ctrl+C to stop).");
    Ok(())
}
