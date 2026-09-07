# Contributing to zk-threat-exchange

Maintained by **Ciprian Ștefan Pleșca**.

Thanks for considering a contribution. A few ground rules to keep the core
protocol trustworthy:

## Ground rules

1. **Never commit real incident data, credentials, or customer information**
   — not even in test fixtures. Use synthetic data (see the existing tests
   in `core-node/src/*/mod.rs`, `heuristics-engine/test/runtests.jl`, and
   `rule-mutator/test/run_tests.scm` for the pattern).
2. **Any change to `core-node/src/zkp/` requires a corresponding update to
   `docs/zero_knowledge_math.md`** explaining the cryptographic reasoning.
   Cryptography PRs without a written justification will not be merged.
3. **Any change to `rule-mutator/src/macros.scm`'s mutation logic must pass
   through `eval_sandbox.scm`'s backtest gate** — no rule mutation should
   ever ship without regression testing against the labeled sample set.
4. Run the full test matrix locally before opening a PR:

   ```bash
   # Rust
   cd core-node && cargo test

   # Go
   cd enterprise-api && go test ./...

   # Scheme
   cd rule-mutator/test && guile --no-auto-compile run_tests.scm

   # Julia
   cd heuristics-engine && julia --project=. test/runtests.jl
   ```

## Reporting a security issue

Do not open a public issue for a security vulnerability. Contact the
maintainer directly (see the GitHub profile for contact details) so a fix
can be prepared before public disclosure.

## Code style

- Rust: `cargo fmt` + `cargo clippy -- -D warnings` must pass clean.
- Go: `go vet ./...` must pass clean.
- Julia / Scheme: no enforced formatter yet — match the existing style in
  the file you're editing.
