"""
zk-threat-exchange :: heuristics-engine :: tests
Author: Ciprian Ștefan Pleșca
"""

using Test

include("../src/threat_inference.jl")
using .ThreatInference
using .ThreatInference.TensorModels

@testset "TensorModels" begin
    @testset "entropy_of_bytes" begin
        @test entropy_of_bytes(UInt8[]) == 0.0
        @test entropy_of_bytes(fill(UInt8(65), 100)) == 0.0  # all identical bytes -> zero entropy
        random_bytes = UInt8.(0:255)
        @test entropy_of_bytes(random_bytes) ≈ 8.0 atol=1e-9  # uniform over 256 symbols -> 8 bits
    end

    @testset "cosine_similarity" begin
        @test cosine_similarity([1.0, 0.0], [1.0, 0.0]) ≈ 1.0
        @test cosine_similarity([1.0, 0.0], [0.0, 1.0]) ≈ 0.0 atol=1e-9
        @test cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0
    end

    @testset "normalize_vector" begin
        v = normalize_vector([3.0, 4.0])
        @test isapprox(sqrt(sum(v .^ 2)), 1.0)
        @test normalize_vector([0.0, 0.0]) == [0.0, 0.0]
    end
end

@testset "ThreatInference" begin
    archetypes = default_archetypes()

    @testset "score_event matches closest archetype" begin
        # An event that closely mirrors the phishing archetype should score
        # highest against "credential_phishing".
        phishing_like = AttackVector(6.4, 1.7, 4.3, 0.55, 0.88)
        scores = score_event(phishing_like, archetypes)
        best = argmax(scores)
        @test best == "credential_phishing"
    end

    @testset "posterior_risk increases with corroboration" begin
        base = posterior_risk(0.4, 0)
        one_peer = posterior_risk(0.4, 1)
        many_peers = posterior_risk(0.4, 10)
        @test base == 0.4
        @test one_peer > base
        @test many_peers > one_peer
        @test many_peers <= 1.0
    end
end

println("All heuristics-engine tests passed.")
