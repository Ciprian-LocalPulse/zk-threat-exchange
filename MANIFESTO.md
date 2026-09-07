# Zero-Knowledge Polymorphic Threat Intelligence
## A Privacy-Preserving Protocol for Decentralized Threat Verification and Self-Mutating Detection Logic

**Author:** Ciprian Ștefan Pleșca
**Repository:** [github.com/Ciprian-LocalPulse/zk-threat-exchange](https://github.com/Ciprian-LocalPulse/zk-threat-exchange)
**Status:** Working research scaffold (pre-audit, pre-production)
**License:** MIT
**Version:** 1.0.0 — September 2026

---

## Abstract

Collective threat intelligence is bottlenecked by what this paper calls the
**Telemetry Exposure Dilemma**: an organization that wants to report an
observed attack must, under the conventional model, hand over exactly the
data it can least afford to expose — raw logs, internal IP ranges, host
identities, and by implication the shape of its own defensive blind spots.
Sharing consortia built on this model stay small, slow, and populated with
data that has been sanitized past the point of usefulness.

**zk-threat-exchange** removes that trade-off at the protocol level. A node
proves *"I observed evidence consistent with a given threat commitment"*
without revealing the evidence itself, using a non-interactive
zero-knowledge proof of knowledge. The proof propagates over a gossip
network; a companion inference layer scores it against known attack
patterns; a self-mutating rule engine updates local detection logic when the
inferred threat landscape shifts; and a commercial API layer turns verified,
privacy-preserving signal into an integratable enterprise product. This
document describes the mathematical construction actually implemented in
the repository, states plainly where that construction is a scaffold rather
than a production cryptosystem, and lays out the path from one to the other.

---

## 1. The Telemetry Exposure Dilemma

Centralized Threat Intelligence Platforms (TIPs) aggregate raw telemetry —
PCAP captures, Sysmon events, NetFlow records, EDR alerts — from every
participating organization. That architecture produces three structural
failure modes that no amount of process discipline fully resolves:

1. **Information leakage.** Raw logs routinely carry personally identifiable
   information, internal hostnames, and network topology that a legal or
   compliance team cannot approve for external sharing without a review
   cycle measured in weeks.
2. **Adversarial reconnaissance.** An attacker who can read a shared feed —
   directly, through a compromised member, or through a leak — learns which
   defenses a target has deployed simply by observing what that target
   reports.
3. **Data stagnation.** Because sanitization is slow and legally sensitive,
   organizations delay sharing until an indicator is safe to publish, by
   which point the attacker has often already rotated infrastructure and the
   indicator's operational value has decayed to near zero.

The dilemma is not a tooling problem; it is a structural mismatch between
what threat-sharing requires (verifiable claims) and what raw-telemetry
sharing provides (verifiable claims *bundled with* everything that makes
those claims sensitive). Zero-knowledge proofs are, definitionally, the
cryptographic primitive that separates the two: they let a verifier accept
a claim as true while learning nothing else about the witness that makes it
true.

---

## 2. Protocol Architecture

The protocol is deliberately partitioned across four components, each
implemented in the language best suited to its constraints, with strict
data-flow boundaries enforced between them:

```
   [ compromised host / SOC log ]
                 │
                 ▼
   core-node (Rust)  ── Witness::from_incident_logs()
                 │
                 ▼
   Zero-knowledge proof (Schnorr / Fiat–Shamir)  ── prove(witness)
                 │
                 ▼
   Gossip broadcast, TTL-bounded  ── GossipNode::publish()
                 │
        ┌────────┴─────────┐
        ▼                  ▼
  peer core-nodes     enterprise-api (Go)
  memory_pool::ingest()   /v1/commitments/ingest
        │                  │
        ▼                  ▼
 heuristics-engine    Enterprise dashboard
 (Julia) — scores         + billing meter
 event vs. archetypes     + SOC webhook
        │
        ▼
 rule-mutator (Scheme)
 mutates detection rule
 when drift is significant
        │
        ▼
 Sandboxed backtest gate (eval_sandbox.scm)
 accept-mutation?
        │
        ▼
 Approved rule mutation re-gossiped to the network
```

| Boundary | What crosses it | What is guaranteed to never cross it |
|---|---|---|
| Host → `core-node` | Raw logs (in-process only) | — |
| `core-node` → gossip network | `ThreatProof` and public `commitment` | The witness, raw logs |
| `core-node` → `heuristics-engine` | A statistical feature vector | Raw logs, witness |
| Any component → `enterprise-api` | Commitments, corroboration counts, billing events | Raw logs, witness, private keys |

Each language was selected for a property the corresponding layer actually
needs:

| Layer | Language | Rationale |
|---|---|---|
| P2P gossip + proof generation | **Rust** | Memory safety without garbage collection, safe concurrency for high-fan-out gossip, and a mature cryptography ecosystem (`arkworks`, `bellman`) to grow into. |
| Tensor-based threat inference | **Julia** | Numerical performance close to C with math-native array syntax, well suited to scoring event vectors against archetype tensors at line rate. |
| Self-mutating detection rules | **Scheme** | Homoiconicity — code is data — makes "the rule rewrites itself" a literal, inspectable transformation of an s-expression rather than a metaphor. |
| Enterprise API / commercialization | **Go** | A boring, fast, operationally simple gRPC/REST surface with a mature SSO/JWT/RBAC ecosystem for paying customers. |

---

## 3. Zero-Knowledge Proof Construction

### 3.1 The problem, stated precisely

A node has observed evidence `w` — a log excerpt, a compromised process's
behavior, a suspicious connection record — indicating that a given threat
signature was present on its infrastructure. It wants to publish that fact
so that other organizations can defend against the same actor, **without
revealing `w`**, because `w` typically contains exactly the sensitive detail
(internal hostnames, IP ranges, employee data) that made the incident worth
keeping quiet about in the first place.

Formally, given a public one-way relation

$$y = g^{w} \bmod p,$$

the node must convince any verifier that it knows `w` without revealing
`w`, and without any interaction beyond a single published message
(non-interactivity is required because the network is asynchronous gossip,
not a live challenge–response channel).

### 3.2 The protocol as implemented

`core-node/src/zkp/mod.rs` implements the classical **Schnorr identification
protocol**, made non-interactive via the **Fiat–Shamir heuristic** — the
verifier's random challenge is replaced with a hash of the transcript
generated so far. This construction satisfies the three properties required
of a genuine zero-knowledge proof of knowledge:

1. **Completeness.** An honest prover who genuinely knows `w` always
   convinces the verifier.
2. **Soundness.** A prover who does not know `w` succeeds only with
   probability negligible in the security parameter, bounded by the
   hardness of the discrete-logarithm problem in the chosen group.
3. **Zero-knowledge.** The transcript `(t, c, s)` reveals nothing about `w`
   beyond the bare fact that the prover knows it. This follows from
   simulatability: a simulator lacking `w` can produce transcripts
   indistinguishable from genuine ones by sampling `s` and `c` first and
   computing `t = g^{s} \cdot y^{-c} \bmod p`.

**Setup (public parameters).** A generator `g` and modulus `p`. In the
repository, `G = 7` and `P = 2^{31} - 1` (a Mersenne prime), chosen so the
reference implementation runs with zero external dependencies and is easy
to test and audit line by line — not for production-grade hardness. See
Section 3.4.

**Witness derivation.** `w = SHA256(raw_logs) \bmod (p-1)`. The raw logs
never leave the node; only the derived, still-secret scalar `w` exists in
memory, and only transiently.

**Public commitment.** `y = g^{w} \bmod p`. This value — not `w` — is what
gets published to the network as the threat indicator. Recovering `w` from
`y` requires solving a discrete logarithm, believed computationally
infeasible for a correctly sized group.

**Proof generation, `prove(w)`:**

1. Sample a random nonce `r`.
2. Compute the commitment `t = g^{r} \bmod p`.
3. Compute the Fiat–Shamir challenge `c = H(g, y, t)`.
4. Compute the response `s = r + c \cdot w \pmod{p-1}`.
5. Output `(t, c, s)`. Neither `w` nor `r` appears in the output.

**Verification, `verify(y, t, c, s)`:**

1. Recompute `c' = H(g, y, t)` and check `c' = c`, which binds the proof to
   this specific commitment `y` and prevents replay against a different one.
2. Check `g^{s} \equiv t \cdot y^{c} \pmod{p}`.

If both checks pass, the verifier is convinced the prover knows `w`
corresponding to the published commitment `y`, and has learned nothing
else about `w`.

### 3.3 From Schnorr proofs to general-purpose SNARKs

The protocol name references zero-knowledge proofs in the general sense,
and the Schnorr/Fiat–Shamir construction above is honestly zero-knowledge —
but it proves a narrow statement: knowledge of a discrete logarithm. A
production system that needs to prove richer, compound statements — for
example, *"this event matches detection pattern X, was observed within the
last 24 hours, and the reporting node has trust-graph degree at least
3"* — needs a general-purpose proof system over arithmetic circuits.
Candidate constructions, each with different trade-offs, include:

- **Groth16** (via `arkworks` or `bellman`) — the smallest proofs, at the
  cost of a per-circuit trusted-setup ceremony.
- **PLONK** / **Halo2** — a universal or updatable setup and more flexible
  circuit design, at the cost of larger proofs than Groth16.
- **Bulletproofs** — no trusted setup at all and strong support for range
  proofs, at the cost of larger proof sizes and slower verification.

The public interface exposed by `core-node` — `ThreatProof` and
`memory_pool::ingest` — is deliberately designed so that swapping the
Schnorr scaffold for a circuit-based SNARK is a matter of replacing
`prove`/`verify` internals, not redesigning the gossip or API layers around
it.

### 3.4 Honest limitations of the current implementation

Academic rigor requires stating plainly what this repository is not yet,
not only what it aspires to be:

1. The reference group (`P = 2^{31} - 1`) is sized for clarity and fast
   test iteration, not cryptographic security. A real deployment requires
   either a 2048-bit safe prime for a classical discrete-log group or an
   elliptic-curve group such as Curve25519 or BLS12-381.
2. `enterprise-api`'s authentication layer is a minimal HMAC-SHA256 token
   issuer for demonstration purposes; production use requires a vetted
   identity provider (Auth0, Okta, Keycloak) or a well-audited JWT library.
3. The gossip layer is currently an in-process `tokio::broadcast` channel
   that models fan-out logic correctly but is not yet a real network
   transport. Integrating `libp2p`, or a raw QUIC/TCP layer, is the next
   step toward a genuine multi-host deployment.
4. No trusted-setup or transparent-setup ceremony has been run, because the
   current construction does not require one. Migrating to Groth16 or
   PLONK will introduce that requirement and the operational complexity
   that comes with it.

These are scoped, known gaps between a working architectural demonstration
and an audited production cryptosystem — not open questions about whether
the underlying approach is sound.

---

## 4. Tensor-Based Threat Inference

Accepting a proof establishes that *a* commitment is authentic; it says
nothing about how significant or how novel the underlying event is. That
judgment is delegated to `heuristics-engine`, written in Julia for its
numerical performance and math-native syntax.

Locally observed event features — entropy, timing characteristics,
destination rarity, payload similarity to known families — are assembled
into a feature vector and compared against a library of attack archetypes
by cosine similarity. This local score is then combined with the network's
corroboration count for the same commitment (how many independent nodes
have published a proof against it) into a posterior risk estimate:

$$\mathbf{S}_{t+1} = \sigma\!\left(\mathbf{W} \cdot \mathbf{T}_t + \mathbf{b}\right) \odot \exp(-\lambda \, \Delta t)$$

where `T_t` is the current archetype-similarity tensor, `σ` is a bounded
non-linearity mapping raw similarity into a systemic-risk scalar, and the
exponential term applies temporal decay so that stale, uncorroborated
commitments stop influencing the network's posterior risk over time.
Critically, this scoring layer never sees the zero-knowledge witness — only
the public commitment and locally derived statistical features, preserving
the same trust boundary that the proof layer establishes.

---

## 5. Homoiconic Detection-Rule Mutation

Static detection rules — YARA signatures, Sigma rules — are brittle against
polymorphic malware that alters byte sequences or control flow between
observations while preserving behavior. `rule-mutator`, written in Scheme,
addresses this by representing every detection rule as an s-expression:
data, not compiled bytecode. "The rule rewrites itself" is therefore not a
metaphor — it is literally a new list produced by evaluating a
transformation over the old one.

```scheme
;; Illustrative mutation macro (see rule-mutator/src/macros.scm for the
;; full implementation)
(define-syntax mutate-detection-rule
  (syntax-rules ()
    ((_ base-pattern entropy-threshold)
     (lambda (incoming-stream)
       (if (> (calculate-entropy incoming-stream) entropy-threshold)
           (eval-ast-rewrite base-pattern)
           #f)))))
```

When `heuristics-engine` detects a significant entropy shift in
corroborated commitments, `rule-mutator` proposes a rewritten rule. That
proposal does not propagate automatically: it must first pass
`eval_sandbox.scm`'s backtest gate (`accept-mutation?`), which evaluates
the candidate rule against a labeled sample set before allowing it to
gossip to the rest of the network. This gate exists specifically to prevent
the failure mode inherent to any self-modifying system — a mutation drifting
toward flagging legitimate traffic — from ever reaching production
detection logic unsupervised.

---

## 6. Enterprise API and Open-Core Economics

`core-node`, `heuristics-engine`, and `rule-mutator` are published under MIT
and remain open source permanently. This is a deliberate economic choice,
not a placeholder: a threat-intelligence network with a handful of members
has little value regardless of its cryptographic properties, and unrestricted
openness is the only credible path to the participation density the
protocol needs to be useful at all.

`enterprise-api`, written in Go for its operational simplicity and mature
service ecosystem, wraps the open core in a commercial layer:

- **gRPC/REST ingestion** for `POST /v1/commitments/ingest`, the endpoint
  through which a customer's `core-node` instances submit verified
  commitments.
- **Role-based access control** with three roles — `viewer`, `analyst`,
  `admin` — backed today by a minimal HMAC token issuer intended for local
  development, and by a real identity provider (SAML/OIDC via Okta, Azure
  AD, or Keycloak) in production.
- **Usage-based billing**, metering two dimensions: total verifications
  accepted, and the count of distinct connected nodes, both exposed via
  `GET /v1/billing/summary`.
- **SOC integration** via outbound webhooks, with reference automation
  blueprints for fanning alerts out to Slack, email, or a ticketing system
  on high-corroboration commitments.

Every open-core component ships in the same binary in both the open-source
and enterprise deployments; the commercial product is the hosted,
authenticated, metered wrapper around identical cryptographic and inference
logic, not a functionally crippled variant of it.

---

## 7. Security and Trust Assumptions

1. **Cryptographic hardness.** The current construction's security reduces
   to the discrete-logarithm problem in the reference group. A production
   deployment must move to a cryptographically sized group or an
   elliptic-curve construction, as described in Section 3.4.
2. **Sybil resistance.** The gossip network as currently implemented does
   not yet enforce staking or proof-of-work/stake admission control;
   production deployment requires a Sybil-resistance mechanism so that
   proof corroboration counts cannot be cheaply inflated by a single
   adversary running many nodes.
3. **Setup ceremony.** Migrating to a circuit-based SNARK (Section 3.3)
   will require a multi-party computation ceremony to generate proving and
   verification keys without toxic-waste leakage; the current Schnorr
   construction has no such requirement because it needs no structured
   reference string.
4. **Auth and identity.** Enterprise deployments must replace the built-in
   HMAC token issuer with a vetted identity provider before handling real
   customer credentials, as described in Section 6.

This project should not be treated as a production security control until
an independent audit has reviewed the cryptographic implementation, the
group parameters have been upgraded to production size, and a real network
transport has replaced the current in-process gossip channel.

---

## 8. Related Work

The Telemetry Exposure Dilemma is not a new observation — it is the
standing justification for TLP (Traffic Light Protocol) markings and for
sanitization pipelines in existing sharing communities such as ISACs and
MISP-based consortia. What those approaches lack is a cryptographic
guarantee: sanitization is a best-effort, manual process, whereas a
zero-knowledge proof gives a mathematical guarantee that nothing beyond the
stated claim was disclosed. Homomorphic and secure multi-party computation
approaches to private threat sharing exist in the research literature, but
typically address either aggregate statistics or single-organization
computation; this protocol targets a different point in the design space —
per-event, publishable, independently verifiable proofs propagated over an
open gossip network — traded against the narrower expressiveness of the
Schnorr construction relative to a full SNARK circuit, pending the
migration path described in Section 3.3.

---

## 9. Conclusion and Future Work

`zk-threat-exchange` demonstrates, end to end, that zero-knowledge proofs
can replace raw-telemetry disclosure as the basis for collective threat
intelligence, and that a self-mutating rule engine can be built safely when
every mutation is gated by an explicit, auditable backtest. The current
repository is a working scaffold that proves the architecture — not yet a
production security system. The concrete path from here to there is:
migrate the proof system from Schnorr to a circuit-based SNARK for richer
statements; replace the reference group with a cryptographically sized one;
replace the in-process gossip channel with a real P2P transport; and
subject the whole system to an independent security audit before any
production SOC pipeline relies on it.

---

## Citation

If you use this protocol, codebase, or mathematical framework in academic
work, please cite it as follows (see also `CITATION.cff`):

```bibtex
@software{Plesca_zk_threat_exchange_2026,
  author  = {Ple{\c{s}}ca, Ciprian {\c{S}}tefan},
  title   = {{zk-threat-exchange: Zero-Knowledge Polymorphic Threat Intelligence Network}},
  year    = {2026},
  url     = {https://github.com/Ciprian-LocalPulse/zk-threat-exchange},
  license = {MIT}
}
```

## Author

**Ciprian Ștefan Pleșca** — project lead, architecture, and initial
implementation.
