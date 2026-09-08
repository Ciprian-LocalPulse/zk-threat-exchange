# rule-mutator

**Language:** Scheme (GNU Guile) · **Author:** Ciprian Ștefan Pleșca

Detection rules represented as data (s-expressions), able to rewrite their
own predicate logic at runtime when `heuristics-engine` reports a
significant behavioral drift — gated by a mandatory backtest before any
mutation is allowed to propagate.

## Layout

```
src/
├── macros.scm       # rule representation, predicate evaluation, mutate-rule
└── eval_sandbox.scm  # backtest harness + accept-mutation? propagation gate
test/
└── run_tests.scm     # end-to-end demo: evolved attack, mutation, sandbox gate
```

## Running locally

```bash
cd test
guile --no-auto-compile run_tests.scm
```

## How a mutation happens

1. A rule is defined as `(rule <name> <predicate> <severity>)`, where
   `<predicate>` is built from `(gt field value)`, `(lt field value)`,
   `(and ...)`, `(or ...)`, `(not ...)`.
2. When `heuristics-engine` (or an operator) observes that a threshold no
   longer separates malicious from benign traffic, `mutate-rule` produces a
   **new** rule generation with the updated threshold — the original rule
   object is never mutated in place, so every generation is diffable and
   auditable.
3. Before the new rule can be gossiped to the network, `accept-mutation?`
   backtests it against a labeled sample set and only approves it if
   accuracy does not regress and false positives stay within tolerance.

This conservative gate exists specifically to prevent an automated mutation
from silently degrading into a rule that flags legitimate traffic across
every connected enterprise node.
