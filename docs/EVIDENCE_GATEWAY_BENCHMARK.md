# Neutral Head-to-Head Benchmark

The benchmark crosses four declared capture profiles with one clean control and
nine hostile cases, producing 40 rows. Profiles are Agent Receipts daemon, OLP
self-attested capture, OLP daemon capture, and OLP receiver/tool-witness capture.
Hostile cases are agent compromise, operator compromise, event omission, tail
truncation, replay, cross-run splice, signed fabricated outcome, signed
insufficient evidence, and altered evidence with source-chain resealing.

It records native signature/integrity acceptance and gateway status, false
acceptance, detection, abstention, bytes inspected, wall time, CPU time, and
evidence reads separately. Timing is environment-sensitive and excluded from
reproducibility claims. There is no combined score.

A hostile case that cannot be proven false is an abstention, not credited as
detection. This keeps `rejected` distinct from `undecidable`.

Current deterministic gates require zero gateway false acceptances, a verified
fully witnessed clean control, explicit exposure of the integrity-only boundary,
rejection or abstention on every unsafe case, and absence of a combined score.
See `results/evidence_gateway_benchmark.json` and the row-level CSV.

The Agent Receipts profile is generated against the pinned wire format but does
not execute the upstream daemon. The benchmark compares trust surfaces under
synthetic evidence; it is not a comparative production penetration test.
