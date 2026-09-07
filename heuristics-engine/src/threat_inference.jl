"""
zk-threat-exchange :: heuristics-engine :: threat_inference
Author: Ciprian Ștefan Pleșca

Probabilistic scoring of an `AttackVector` against a library of known-bad
archetype vectors, plus a Bayesian-style risk update that combines the local
tensor score with network corroboration (how many peers independently
produced a valid zero-knowledge proof for the same commitment — supplied by
`core-node::memory_pool`).
"""
module ThreatInference

include("tensor_models.jl")
using .TensorModels
using Statistics

export ArchetypeLibrary, score_event, posterior_risk, default_archetypes

"""
    ArchetypeLibrary

A named collection of reference `AttackVector`s representing known attack
families (e.g. "c2_beaconing", "credential_phishing", "data_exfiltration").
"""
const ArchetypeLibrary = Dict{String, AttackVector}

"""
    default_archetypes() -> ArchetypeLibrary

A small, illustrative starter set. In production this would be trained /
curated from labeled incident data and periodically refreshed by the network.
"""
function default_archetypes()::ArchetypeLibrary
    return ArchetypeLibrary(
        "c2_beaconing"        => AttackVector(3.2, 0.1, 0.02, 0.8, 0.3),
        "credential_phishing" => AttackVector(6.5, 1.8, 4.5, 0.6, 0.9),
        "data_exfiltration"   => AttackVector(7.8, 3.2, 2.1, 0.9, 0.5),
        "port_scan"           => AttackVector(1.1, -0.4, 0.1, 0.95, 0.1),
    )
end

"""
    score_event(event, archetypes) -> Dict{String, Float64}

Cosine-similarity score of `event` against every archetype in the library.
Returns a mapping archetype-name => similarity score.
"""
function score_event(event::AttackVector, archetypes::ArchetypeLibrary)::Dict{String, Float64}
    event_tensor = feature_tensor(event)
    scores = Dict{String, Float64}()
    for (name, archetype) in archetypes
        scores[name] = cosine_similarity(event_tensor, feature_tensor(archetype))
    end
    return scores
end

"""
    posterior_risk(prior_similarity, corroboration_count; k=0.5) -> Float64

Combine the local tensor-similarity score with how many independent network
peers corroborated the same zero-knowledge threat commitment. More
corroboration pushes the posterior risk toward 1.0 even for a moderate local
similarity score — this is the bridge between `heuristics-engine` (local
math) and `core-node::memory_pool` (network consensus).

Uses a simple saturating update: risk = 1 - (1 - prior)*(1 - k)^corroboration
"""
function posterior_risk(prior_similarity::Float64, corroboration_count::Integer; k::Float64=0.5)::Float64
    prior = clamp(prior_similarity, 0.0, 1.0)
    corroboration_count <= 0 && return prior
    return 1.0 - (1.0 - prior) * (1.0 - k)^corroboration_count
end

end # module ThreatInference
