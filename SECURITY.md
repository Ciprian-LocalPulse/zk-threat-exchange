# Security Policy

## Project status

`zk-threat-exchange` is a research and engineering scaffold. The
zero-knowledge proof module, the tensor inference engine, and the
rule-mutation engine demonstrate the protocol's architecture end to end,
but they have **not been independently audited** and are **not yet backed
by production-grade cryptographic parameters**. Do not deploy this project
in a real SOC pipeline, and do not rely on it to protect real customer
data, without first commissioning an audit and reviewing the limitations
documented in `docs/zero_knowledge_math.md` and `docs/architecture.md`.

That status makes responsible disclosure especially important: this is
exactly the stage where a well-reported vulnerability has the most value
and the least cost to fix.

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | ✅ |
| Tagged pre-1.0 releases | Best effort |

There is no long-term support branch yet. Security fixes land on `main`
and are back-ported to a tagged release only if a maintainer judges the
release to still be in active use.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead:

1. Use GitHub's private vulnerability reporting feature on this repository
   (**Security → Report a vulnerability**), or contact the maintainer
   directly through the contact details on the maintainer's GitHub profile
   if private reporting is unavailable.
2. Include, where possible:
   - A description of the vulnerability and its potential impact.
   - Steps to reproduce, or a proof-of-concept.
   - The component affected (`core-node`, `heuristics-engine`,
     `rule-mutator`, or `enterprise-api`).
   - Whether the issue affects the cryptographic construction itself, the
     implementation, or the surrounding infrastructure (auth, gossip
     transport, API).

You should expect an initial response within **5 business days**. We'll
work with you to confirm the issue, assess severity, and agree on a
disclosure timeline before any public write-up.

## Scope

In scope:

- The Schnorr/Fiat–Shamir proof implementation in `core-node/src/zkp`,
  including soundness, completeness, and zero-knowledge property
  violations.
- Flaws in `memory_pool` or the gossip layer that would let an attacker
  forge, replay, or suppress commitments.
- Authentication and authorization flaws in `enterprise-api`, including
  the HMAC token issuer and role-based access control.
- Logic in `rule-mutator`'s backtest gate (`eval_sandbox.scm`) that could
  let a malicious or drifting rule mutation bypass `accept-mutation?` and
  propagate to the network.
- Dependency vulnerabilities in `Cargo.lock`, `Project.toml`, or `go.mod`
  with a demonstrable path to exploitation in this codebase.

Explicitly out of scope (already documented, tracked, and known):

- The reference group size (`P = 2^31 - 1`) being too small for
  production use — this is a documented placeholder, not a
  vulnerability report. See Section 3.4 of `MANIFESTO.md`.
- The absence of a real P2P transport (the gossip layer currently runs
  over an in-process `tokio::broadcast` channel).
- The HMAC-based auth issuer being unsuitable for production identity
  management — also documented, and slated for replacement with a real
  identity provider.

If you're unsure whether something is in scope, report it anyway — we'd
rather triage a false positive than miss a real issue.

## Disclosure policy

We follow coordinated disclosure. Once a fix is available, we'll credit
reporters (unless anonymity is requested) in the release notes and, where
relevant, in `CITATION.cff`'s acknowledgments.
