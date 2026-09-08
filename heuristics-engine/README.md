# heuristics-engine

**Language:** Julia · **Author:** Ciprian Ștefan Pleșca

Statistical/tensor analysis of observed events, scoring them against known
attack archetypes and combining the result with network corroboration counts
from `core-node`.

## Layout

```
src/
├── tensor_models.jl     # AttackVector representation, cosine similarity, entropy
└── threat_inference.jl   # archetype library + posterior_risk scoring
test/
└── runtests.jl           # Test-based test suite
```

## Running locally

```bash
julia --project=. -e 'using Pkg; Pkg.instantiate()'
julia --project=. test/runtests.jl
```

## Key functions

- `TensorModels.entropy_of_bytes` — Shannon entropy of a byte sequence,
  used as a phishing/obfuscation signal.
- `TensorModels.cosine_similarity` — similarity between two feature vectors.
- `ThreatInference.score_event` — scores an `AttackVector` against every
  archetype in an `ArchetypeLibrary`.
- `ThreatInference.posterior_risk` — combines a local similarity score with
  a network corroboration count (from `core-node::memory_pool`) into a
  single risk estimate in `[0, 1]`.

## Extending the archetype library

`default_archetypes()` ships four illustrative archetypes
(`c2_beaconing`, `credential_phishing`, `data_exfiltration`, `port_scan`).
In production, this library should be trained/curated from labeled incident
data and refreshed periodically — see `docs/architecture.md` for where this
fits in the overall pipeline.
