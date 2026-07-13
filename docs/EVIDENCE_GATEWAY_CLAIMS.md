# Evidence Gateway Claim Boundary

## Supported

In the shipped controlled benchmark, a signed source receipt was evaluated as
one input to separate integrity, provenance, coverage, freshness, evidence,
outcome-witness, and causal-uptake decisions. The gateway produced no verified
false acceptance in the 36 hostile profile/case combinations. The fully
witnessed clean control verified; clean controls lacking required independent
support abstained.

The pinned Agent Receipts v0.5 runtime vector verifies with its published key and
expected RFC 8785 body hash. This establishes adapter compatibility with that
vector, not generic W3C Verifiable Credential interoperability.

## Not supported

This release does not claim OLP receipts are more deployable than Agent Receipts,
signatures prove real-world truth, the current OTel adapter has independent
provenance, the upstream Agent Receipts daemon accepted a fabricated event in
production, or either system supplies regulatory compliance. It makes no
universal false-acceptance, latency, or security claim.

The useful distinction is narrower: a valid action record can be retained as
evidence while a separate verifier decides whether it is sufficiently supported
and safe to use next.
