//! zk-threat-exchange :: core-node :: p2p
//! Author: Ciprian Ștefan Pleșca
//!
//! Real P2P networking for propagating verified threat proofs across the
//! network, built on `libp2p`:
//!
//! - **Transport:** TCP + Noise (encrypted, authenticated channels) + Yamux
//!   (stream multiplexing) — libp2p's standard, production transport stack.
//! - **Pub-sub:** `gossipsub`, the same pub-sub protocol used by Ethereum
//!   2.0, IPFS, and Filecoin for exactly this kind of "broadcast a signed
//!   message to everyone subscribed to a topic" pattern.
//! - **Discovery:** `mDNS`, for automatic peer discovery on a local network
//!   (LAN/Docker Compose network) without a bootstrap node list. A
//!   wide-area deployment would add a DHT-based or bootstrap-list discovery
//!   mechanism alongside this — see `docs/ROADMAP.md` Phase 2.
//!
//! ## v0.3.0 — replaces the v0.2.0 in-process simulation
//!
//! Earlier versions of this module used an in-process `tokio::broadcast`
//! channel to model gossip fan-out without a real transport. This version
//! is a genuine P2P network: two `core-node` processes on the same LAN (or
//! the same Docker Compose network) will discover each other via mDNS and
//! exchange `GossipMessage`s over real, encrypted TCP connections.
//!
//! The Swarm itself is not `Send`-shared across the application; instead,
//! this module spawns a single background task that owns the `Swarm` and
//! drives its event loop, exposing a small command/event channel API
//! (`GossipNode::publish`, `GossipNode::dial`, and an inbound
//! `mpsc::Receiver<GossipMessage>`) to the rest of the application — the
//! standard pattern for using libp2p from an application that also needs to
//! do other work concurrently.

use crate::memory_pool::Commitment;
use crate::zkp::ThreatProof;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// The gossipsub topic all `core-node` instances publish/subscribe to.
/// Versioned so a future incompatible message-format change can run
/// alongside the old topic during a rollout instead of silently breaking.
pub const COMMITMENT_TOPIC: &str = "zk-threat-exchange/commitments/v1";

/// The message payload gossiped over the network — unchanged in shape from
/// the v0.2.0 in-process version, just now serialized over a real wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub node_id: String,
    pub commitment: Commitment,
    pub proof: ThreatProof,
    pub ttl: u8,
}

#[derive(NetworkBehaviour)]
struct ZkBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

enum Command {
    Publish(GossipMessage),
    Dial(Multiaddr),
}

/// A handle to a running P2P node. Cheap to clone-by-reference (holds a
/// channel sender); the actual `Swarm` lives in a spawned background task.
pub struct GossipNode {
    node_id: String,
    peer_id: PeerId,
    command_tx: mpsc::Sender<Command>,
}

/// Everything returned by spawning a new node: the handle to control it,
/// the channel on which validated inbound gossip messages arrive, and the
/// address it ended up listening on (useful for tests and for out-of-band
/// bootstrap/dial in a wide-area deployment).
pub struct GossipHandle {
    pub node: GossipNode,
    pub inbound: mpsc::Receiver<GossipMessage>,
    pub listen_addr: Multiaddr,
}

impl GossipNode {
    /// Build a libp2p Swarm (TCP + Noise + Yamux transport, gossipsub +
    /// mDNS behaviour), bind it to an OS-assigned local TCP port, subscribe
    /// to `COMMITMENT_TOPIC`, and spawn a background task to drive it.
    pub async fn spawn(
        node_id: &str,
    ) -> Result<GossipHandle, Box<dyn Error + Send + Sync + 'static>> {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(5))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(std::io::Error::other)?;

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

                Ok(ZkBehaviour { gossipsub, mdns })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let peer_id = *swarm.local_peer_id();
        let topic = gossipsub::IdentTopic::new(COMMITMENT_TOPIC);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let (command_tx, command_rx) = mpsc::channel::<Command>(64);
        let (inbound_tx, inbound_rx) = mpsc::channel::<GossipMessage>(64);
        let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

        let node_id_owned = node_id.to_string();
        tokio::spawn(run_event_loop(
            swarm,
            topic,
            command_rx,
            inbound_tx,
            Some(addr_tx),
            node_id_owned,
        ));

        let listen_addr = addr_rx
            .await
            .map_err(|_| "swarm task ended before it started listening")?;

        Ok(GossipHandle {
            node: GossipNode {
                node_id: node_id.to_string(),
                peer_id,
                command_tx,
            },
            inbound: inbound_rx,
            listen_addr,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Public API for callers (or future components) that need the node's
    /// own label rather than its cryptographic PeerId — e.g. for log
    /// correlation. Not yet called from `main.rs`'s single-node demo.
    #[allow(dead_code)]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Publish a threat proof to the gossip network. Returns an error only
    /// if the background swarm task has already shut down.
    pub async fn publish(
        &self,
        commitment: Commitment,
        proof: ThreatProof,
        ttl: u8,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let msg = GossipMessage {
            node_id: self.node_id.clone(),
            commitment,
            proof,
            ttl,
        };
        self.command_tx
            .send(Command::Publish(msg))
            .await
            .map_err(|_| "gossip event loop has shut down")?;
        Ok(())
    }

    /// Explicitly dial a known peer address. Not needed when mDNS discovery
    /// is available (LAN / Docker Compose network), but useful for
    /// wide-area bootstrap peers and for deterministic tests.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.command_tx
            .send(Command::Dial(addr))
            .await
            .map_err(|_| "gossip event loop has shut down")?;
        Ok(())
    }
}

/// The background task that owns the `Swarm` and drives its event loop.
/// Handles mDNS peer discovery/expiry, inbound gossipsub messages, and
/// outbound commands (publish/dial) from the application.
async fn run_event_loop(
    mut swarm: libp2p::Swarm<ZkBehaviour>,
    topic: gossipsub::IdentTopic,
    mut command_rx: mpsc::Receiver<Command>,
    inbound_tx: mpsc::Sender<GossipMessage>,
    mut addr_tx: Option<oneshot::Sender<Multiaddr>>,
    node_id: String,
) {
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[{node_id}] listening on {address}");
                        if let Some(tx) = addr_tx.take() {
                            let _ = tx.send(address);
                        }
                    }
                    SwarmEvent::Behaviour(ZkBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                        for (peer_id, addr) in peers {
                            println!("[{node_id}] discovered peer {peer_id} at {addr} via mDNS");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(ZkBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                        for (peer_id, _addr) in peers {
                            println!("[{node_id}] mDNS peer expired: {peer_id}");
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(ZkBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        match serde_json::from_slice::<GossipMessage>(&message.data) {
                            Ok(gossip_msg) => {
                                let _ = inbound_tx.send(gossip_msg).await;
                            }
                            Err(e) => {
                                // A peer sent malformed data — log and drop,
                                // never let untrusted input crash the node.
                                println!(
                                    "[{node_id}] dropped malformed gossip message from {propagation_source}: {e}"
                                );
                            }
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[{node_id}] connection established with {peer_id}");
                    }
                    _ => {}
                }
            }
            command = command_rx.recv() => {
                match command {
                    Some(Command::Publish(msg)) => {
                        match serde_json::to_vec(&msg) {
                            Ok(bytes) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                    println!("[{node_id}] publish failed (no peers yet?): {e}");
                                }
                            }
                            Err(e) => println!("[{node_id}] failed to serialize outbound message: {e}"),
                        }
                    }
                    Some(Command::Dial(addr)) => {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            println!("[{node_id}] dial {addr} failed: {e}");
                        }
                    }
                    None => {
                        // Command channel closed — the GossipNode handle was
                        // dropped, so shut the event loop down cleanly.
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::{prove, Witness};
    use std::time::Duration as StdDuration;

    /// End-to-end test that does NOT rely on mDNS (which needs UDP
    /// multicast support that may not be available in a CI sandbox).
    /// Instead, node B dials node A's listen address directly, and we
    /// assert a published message actually arrives over the real
    /// encrypted TCP transport.
    #[tokio::test]
    async fn two_nodes_exchange_a_gossip_message_via_direct_dial() {
        let handle_a = GossipNode::spawn("node-a")
            .await
            .expect("node A failed to start");
        let handle_b = GossipNode::spawn("node-b")
            .await
            .expect("node B failed to start");

        let mut inbound_b = handle_b.inbound;

        // B dials A directly, bypassing mDNS discovery for test determinism.
        handle_b
            .node
            .dial(handle_a.listen_addr.clone())
            .await
            .expect("dial should succeed");

        // Give the connection + gossipsub mesh a moment to establish.
        tokio::time::sleep(StdDuration::from_secs(2)).await;

        let witness = Witness::from_incident_logs(b"integration-test-incident");
        let commitment = witness.public_commitment();
        let proof = prove(&witness);

        handle_a
            .node
            .publish(commitment, proof, 8)
            .await
            .expect("publish should succeed");

        let received = tokio::time::timeout(StdDuration::from_secs(10), inbound_b.recv())
            .await
            .expect("timed out waiting for gossip message")
            .expect("channel closed unexpectedly");

        assert_eq!(received.node_id, "node-a");
        assert_eq!(received.commitment, commitment);
    }

    #[tokio::test]
    async fn node_reports_a_distinct_peer_id() {
        let handle_a = GossipNode::spawn("node-a").await.unwrap();
        let handle_b = GossipNode::spawn("node-b").await.unwrap();
        assert_ne!(handle_a.node.peer_id(), handle_b.node.peer_id());
    }
}
