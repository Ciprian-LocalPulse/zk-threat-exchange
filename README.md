# zk-threat-exchange
**Zero-Knowledge Polymorphic Threat Intelligence**

![zk-threat-exchange banner](./assets/zk-threat-exchange%20banner.png)

Author & Maintainer: **Ciprian Ștefan Pleșca**  
License: MIT (core) — see [LICENSE](./LICENSE)

---

## 1. The Vision

Threat intelligence sharing is broken at its foundation: to report an attack, an
organization must expose exactly the data it can least afford to expose — internal
logs, infrastructure topology, and often the fingerprints of its own defensive
gaps. That single fact is why threat-sharing consortia stay small, slow, and full
of stale or sanitized-to-uselessness data.

**zk-threat-exchange** removes the trade-off. Using zero-knowledge proofs
(zk-SNARKs), a node can prove *"I observed an indicator of compromise consistent
with signature X"* without revealing the witness — the raw logs, the compromised
host, or the internal topology that produced that observation. The network gets a
verifiable signal. The organization keeps its data.

## 2. Why This Stack?

Every language in this repository was chosen for a property the problem actually
needs, not for novelty:

| Layer | Language | Why |
|---|---|---|
| P2P networking + ZKP proof generation | **Rust** | Memory safety without a garbage collector, fearless concurrency for gossip propagation, and a mature `arkworks`/`bellman`-class cryptography ecosystem. |
| Tensor analysis & threat inference | **Julia** | C-like numerical performance with math-native syntax, ideal for scoring attack vectors as tensors and running probabilistic inference at line rate. |
| Polymorphic detection rules | **Scheme** | Code-as-data (homoiconicity) lets detection rules rewrite themselves at runtime via macro/AST manipulation when a malware mutation is observed — something a static YARA-rule engine structurally cannot do. |
| Enterprise API / monetization | **Go** | Boring, fast, easy to operate gRPC/REST surface for paying customers, with a mature SSO/JWT/RBAC ecosystem. |

## 3. The Moat

The defensible core isn't any single component — it's the intersection: a
gossip network that only propagates *verified-without-disclosure* proofs, feeding
a rule engine that can mutate its own detection logic as those proofs arrive. That
combination of applied cryptography, metaprogramming, and real-time tensor
inference is not something a competitor bolts on in a sprint.

## 4. Repository Layout

```
zk-threat-exchange/
├── core-node/          # Rust: P2P gossip + ZKP circuits + in-memory proof pool
├── heuristics-engine/  # Julia: tensor models + probabilistic threat inference
├── rule-mutator/       # Scheme: self-rewriting detection rules (macros + AST)
├── enterprise-api/     # Go: gRPC/REST SaaS layer, auth, billing hooks
├── deployments/        # docker-compose + Make.com automation blueprints
├── docs/               # Architecture, ZK math, enterprise integration
└── .github/workflows/  # CI: rust tests, julia tests, docker build
```

## 5. Quickstart (Zero Cost, Local Only)

Requires only Docker and Docker Compose — no cloud account needed.

```bash
git clone https://github.com/<your-username>/zk-threat-exchange.git
cd zk-threat-exchange
docker-compose -f deployments/docker-compose.yml up -d
```

This brings up three containers: the Rust P2P node, the Julia heuristics
engine, and the Go enterprise API gateway (running in open-source/local mode,
no license key required).

## 6. Enterprise Edition (Open Core)

The core protocol (`core-node`, `heuristics-engine`, `rule-mutator`) is open
source under MIT, forever — that's what earns community trust and, more
practically, community-contributed threat data.

The **Enterprise Edition** (`enterprise-api` in hosted form) adds:
- SOC integration connectors (Splunk, CrowdStrike, Sentinel)
- Corporate SSO (SAML/OIDC) and RBAC
- SLA-backed 24/7 support
- Usage-based billing on decrypted-verification volume / connected nodes

See [`docs/enterprise_integration.md`](./docs/enterprise_integration.md).

## 7. Project Status

This is an early-stage research/engineering project. The ZKP circuit, tensor
models, and rule-mutation engine in this repository are **working scaffolds**
demonstrating the architecture end-to-end — not yet audited, production-grade
cryptography. Do not use in a real SOC pipeline without a proper security audit
and a real trusted-setup ceremony for the SNARK parameters.

## Author

**Ciprian Ștefan Pleșca**
Project lead, architecture, and initial implementation.
## 💖 Support & Funding
If you find `zk-threat-exchange` valuable, read our [DONATE.md](./DONATE.md) to see how voluntary support funds independent security audits, production-grade cryptographic parameters, and ongoing maintenance.
