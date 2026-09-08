## Summary

<!-- What does this PR do, and why? -->

## Component(s) touched

- [ ] `core-node` (Rust)
- [ ] `heuristics-engine` (Julia)
- [ ] `rule-mutator` (Scheme)
- [ ] `enterprise-api` (Go)
- [ ] `deployments` (Docker/Make.com)
- [ ] `docs`
- [ ] CI/CD (`.github/workflows`)

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] No real incident data, credentials, or customer information is
      included anywhere in this PR (code, tests, commit messages).
- [ ] Relevant tests were added or updated, and pass locally:
  - [ ] `cargo test` (if `core-node` changed)
  - [ ] `go test ./...` (if `enterprise-api` changed)
  - [ ] `guile --no-auto-compile run_tests.scm` (if `rule-mutator` changed)
  - [ ] `julia --project=. test/runtests.jl` (if `heuristics-engine` changed)
- [ ] If this changes `core-node/src/zkp/`, I updated
      `docs/zero_knowledge_math.md` to match.
- [ ] If this changes rule-mutation logic, it still passes the
      `eval_sandbox.scm` backtest gate.
- [ ] I updated `CHANGELOG.md` under `[Unreleased]`.

## How was this tested?

<!-- Describe manual or automated testing performed. -->

## Related issues

<!-- Closes #123, relates to #456 -->
