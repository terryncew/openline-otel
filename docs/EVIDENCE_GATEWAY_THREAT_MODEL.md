# Evidence Gateway Threat Model

## In scope

The release tests compromised source agents or operators, omitted events,
truncated tails, same-receipt replay, cross-run splicing, validly signed
fabricated outcomes, valid signatures with insufficient evidence, and evidence
replacement followed by source-chain resealing. It also rejects malformed JSON,
duplicate JSON keys, source signature changes, witness conflicts, freshness
rollback, and local wallet-chain forks.

The design assumes the verifier holds expected run/session/parent/generation and
challenge state, and that at least one consequential outcome can be observed by
a key outside the source actor's control. The receiver/tool-witness profile is
the only clean benchmark track satisfying every default requirement.

## Trust domains

- Source signer: asserts receipt integrity and statements inside it.
- Capture daemon: can improve process separation but may remain operator
  controlled.
- Receiver/tool/user/outcome witness: independently observes specified facts and
  signs source, binding, manifest, and outcome hashes.
- Gateway: evaluates supplied material under local policy and signs a verdict.
- Later controller: signs an uptake receipt naming the prior verdict it used.

Independence is a deployment property. Different labels or keys controlled by
the same compromised operator are not independent merely because JSON says so.

## Out of scope

The gateway does not prevent an adversary from suppressing all traffic, prove
completeness without a terminal independent observation, protect keys with an
HSM/KMS, authenticate local browser users, enforce production routing, discover
keys through DID resolution, validate arbitrary W3C VC profiles, or establish EU
AI Act compliance. Browser and MCP surfaces are local prototypes. Traffic,
filesystem, host, database, and process security remain deployment concerns.
The MCP forward proxy gates response uptake after tool execution; it is not a
pre-execution authorization firewall and cannot roll back side effects.

The benchmark models declared trust surfaces and verifies the pinned public
Agent Receipts v0.5 conformance vector. It does not run or compromise the
upstream daemon binary, so results are protocol-boundary evidence rather than a
product security ranking.
