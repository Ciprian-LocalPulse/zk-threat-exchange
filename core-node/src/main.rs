//! zk-threat-exchange :: core-node
//! Author: Ciprian Ștefan Pleșca
//!
//! Entry point for the P2P zero-knowledge threat intelligence node.

mod memory_pool;
mod p2p;
mod zkp;

use memory_pool::MemoryPool;
use p2p::GossipNode;
use zkp::{prove, Witness};

#[tokio::main]
async fn main() {
    println!("=== zk-threat-exchange core-node ===");
    println!("Author: Ciprian Ștefan Pleșca");

    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-local".to_string());
    let (node, mut rx) = GossipNode::new(&node_id, 256);
    let mut pool = MemoryPool::new();

    println!("[{node_id}] node online, subscribed to gossip channel.");

    // Demo: simulate detecting a threat locally, proving it in zero
    // knowledge, and gossiping the proof to the network.
    let witness = Witness::from_incident_logs(b"anomalous-outbound-tls-to-known-c2-range");
    let commitment = witness.public_commitment();
    let proof = prove(&witness);

    pool.ingest(commitment, proof.clone());
    node.publish(commitment, proof, 8);

    println!(
        "[{node_id}] published threat commitment {commitment} without revealing the witness."
    );
    println!("[{node_id}] local pool size: {}", pool.len());

    if let Ok(msg) = rx.try_recv() {
        println!(
            "[{node_id}] observed gossip message from '{}' (ttl={})",
            msg.node_id, msg.ttl
        );
    }

    println!("[{node_id}] node running. (Ctrl+C to stop in a real deployment.)");
}
