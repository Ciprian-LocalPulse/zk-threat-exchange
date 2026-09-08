# Security Policy

Maintained by **Ciprian Ștefan Pleșca**.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.**
Public issues are indexed and searchable — filing one for a live
vulnerability effectively publishes an exploit advisory before a fix exists.

Instead:

1. Report privately via GitHub's **"Report a vulnerability"** button under
   the repository's **Security** tab (this opens a private advisory visible
   only to the maintainer), **or**
2. Contact the maintainer directly through the contact details on their
   GitHub profile.

Please include, where possible:
- The affected component (`core-node`, `heuristics-engine`, `rule-mutator`,
  or `enterprise-api`) and version/commit hash.
- Steps to reproduce, or a minimal proof-of-concept.
- The potential impact as you understand it (e.g. "allows recovering the
  ZKP witness," "allows forging a valid proof for an arbitrary commitment,"
  "allows privilege escalation past RBAC checks").

## Disclosure Timeline

- **Acknowledgement:** within 5 business days of the report.
- **Initial assessment:** within 10 business days — confirming reproducibility
  and severity.
- **Fix or mitigation:** timeline depends on severity and complexity; the
  reporter will be kept updated.
- **Public disclosure:** coordinated with the reporter, normally after a fix
  is released. Credit is given to the reporter unless they request
  anonymity.

## Scope

In scope:
- The zero-knowledge proof implementation (`core-node/src/zkp/`) — proof
  soundness, zero-knowledge property violations, witness leakage.
- The gossip/P2P layer (`core-node/src/p2p/`) — message forgery, replay,
  denial-of-service via malformed gossip.
- The rule-mutation engine (`rule-mutator/`) — ability to bypass the
  `eval_sandbox.scm` backtest gate and propagate a malicious/regressive rule.
- The enterprise API (`enterprise-api/`) — authentication bypass, RBAC
  bypass, injection, billing-meter manipulation.

Out of scope (known, already documented):
- The demo-sized cryptographic parameters (`P`, `G` in
  `core-node/src/zkp/mod.rs`) are explicitly called out as non-production-sized
  in `docs/zero_knowledge_math.md`. Reports about the small prime being
  "insecure for production" are already tracked — see
  [`docs/zero_knowledge_math.md`](./docs/zero_knowledge_math.md) and
  [`CHANGELOG.md`](./CHANGELOG.md) for the planned upgrade path. Reports that
  demonstrate a *practical break* of the demo parameters (not just "the
  group is too small in theory") are still welcome.
- The built-in HMAC JWT issuer in `enterprise-api/internal/auth/` is
  documented as a development-only stand-in for a real IdP
  (see `docs/enterprise_integration.md`).

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` (current) | ✅ |

This project is pre-1.0; there is no long-term-support branch yet. Security
fixes land on `main` and are noted in `CHANGELOG.md` under `Security`.
