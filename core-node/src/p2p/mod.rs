//! zk-threat-exchange :: core-node :: p2p
//! Author: Ciprian Ștefan Pleșca
//!
//! A minimal gossip-protocol layer for propagating verified threat proofs
//! across the network. This is an in-process simulation (tokio broadcast
//! channel) that models the real gossip fan-out logic; swapping the
//! transport for libp2p or a raw TCP/QUIC socket layer is a drop-in
//! replacement for `broadcast_raw` / `receive_raw` below.

use crate::zkp::ThreatProof;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub node_id: String,
    pub commitment: u128,
    pub proof: ThreatProof,
    pub ttl: u8,
}

pub struct GossipNode {
    pub node_id: String,
    tx: broadcast::Sender<GossipMessage>,
}

impl GossipNode {
    pub fn new(node_id: &str, capacity: usize) -> (Self, broadcast::Receiver<GossipMessage>) {
        let (tx, rx) = broadcast::channel(capacity);
        (
            GossipNode { node_id: node_id.to_string(), tx },
            rx,
        )
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GossipMessage> {
        self.tx.subscribe()
    }

    /// Publish a threat proof to all connected peers. TTL-based propagation
    /// prevents unbounded rebroadcast loops in a real multi-hop mesh.
    pub fn publish(&self, commitment: u128, proof: ThreatProof, ttl: u8) {
        let msg = GossipMessage {
            node_id: self.node_id.clone(),
            commitment,
            proof,
            ttl,
        };
        // Ignore send errors (no active subscribers is a valid state).
        let _ = self.tx.send(msg);
    }

    /// Re-broadcast a message received from a peer, decrementing TTL.
    pub fn relay(&self, mut msg: GossipMessage) {
        if msg.ttl == 0 {
            return;
        }
        msg.ttl -= 1;
        let _ = self.tx.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::{prove, Witness};

    #[tokio::test]
    async fn gossip_delivers_proof_to_subscriber() {
        let (node, mut rx) = GossipNode::new("node-a", 16);
        let witness = Witness::from_incident_logs(b"test-log-entry");
        let commitment = witness.public_commitment();
        let proof = prove(&witness);

        node.publish(commitment, proof.clone(), 4);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.node_id, "node-a");
        assert_eq!(received.commitment, commitment);
    }
}
