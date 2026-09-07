"""
zk-threat-exchange :: heuristics-engine :: tensor_models
Author: Ciprian Ștefan Pleșca

Represents an observed attack event as a feature tensor and exposes basic
tensor operations used by `threat_inference.jl` to score similarity against
known attack-pattern archetypes.

This module is intentionally self-contained (uses only LinearAlgebra /
Statistics from the standard library) so it runs anywhere Julia runs, with no
external package resolution required for the open-source core.
"""
module TensorModels

using LinearAlgebra
using Statistics

export AttackVector, feature_tensor, cosine_similarity, entropy_of_bytes, normalize_vector

"""
    AttackVector

A structured, fixed-dimension representation of an observed event, built from
cheap-to-compute statistical features so it can be produced at line rate on a
live traffic/log stream.

Fields:
- `byte_entropy`      : Shannon entropy of the payload/header bytes (0..8)
- `packet_size_z`     : z-scored packet/message size relative to a rolling baseline
- `interval_variance`  : variance of inter-event timing (beaconing detector)
- `destination_rarity` : how rarely this destination has been seen historically (0..1)
- `payload_similarity` : max cosine similarity to any known-bad payload template (0..1)
"""
struct AttackVector
    byte_entropy::Float64
    packet_size_z::Float64
    interval_variance::Float64
    destination_rarity::Float64
    payload_similarity::Float64
end

"""
    feature_tensor(v::AttackVector) -> Vector{Float64}

Flatten an `AttackVector` into a dense feature vector suitable for linear
algebra operations (cosine similarity, projections, clustering).
"""
function feature_tensor(v::AttackVector)::Vector{Float64}
    return [
        v.byte_entropy,
        v.packet_size_z,
        v.interval_variance,
        v.destination_rarity,
        v.payload_similarity,
    ]
end

"""
    normalize_vector(x) -> Vector{Float64}

L2-normalize a vector; returns a zero vector unchanged (avoids division by
zero on all-null observations).
"""
function normalize_vector(x::AbstractVector{<:Real})::Vector{Float64}
    n = norm(x)
    return n == 0.0 ? Float64.(x) : Float64.(x) ./ n
end

"""
    cosine_similarity(a, b) -> Float64

Standard cosine similarity in [-1, 1]; used to compare an observed attack
vector against known archetype vectors.
"""
function cosine_similarity(a::AbstractVector{<:Real}, b::AbstractVector{<:Real})::Float64
    na, nb = norm(a), norm(b)
    (na == 0.0 || nb == 0.0) && return 0.0
    return dot(a, b) / (na * nb)
end

"""
    entropy_of_bytes(data::Vector{UInt8}) -> Float64

Shannon entropy (base 2) of a byte sequence, in bits (0..8). High entropy in,
say, an email header field is a classic phishing/obfuscation signal that
feeds directly into `AttackVector.byte_entropy`.
"""
function entropy_of_bytes(data::Vector{UInt8})::Float64
    isempty(data) && return 0.0
    counts = zeros(Int, 256)
    for b in data
        counts[Int(b) + 1] += 1
    end
    n = length(data)
    h = 0.0
    for c in counts
        c == 0 && continue
        p = c / n
        h -= p * log2(p)
    end
    return h
end

end # module TensorModels
