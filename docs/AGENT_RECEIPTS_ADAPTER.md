# Agent Receipts v0.5 Adapter

The adapter is pinned to the public `agent-receipts/obsigna` repository at commit
`df6833a39743e17127d5ad4b10cdc8f6734d8e03` and wire profile `0.5.0`. The fixture
in `artifacts/agent-receipts-v050-runtime-receipt.json` is copied from
`cross-sdk-tests/v050_vectors.json` with its published Ed25519 public key and
expected body hash.

The adapter requires the v0.5 contexts, type array, credential subject, chain,
issuer session, and Ed25519Signature2020 proof. It removes `proof`, canonicalizes
the remaining document with RFC 8785, and verifies the multibase-base64url
signature against an out-of-band trusted verification method. It does not modify
submitted bytes.

Agent Receipts chain ID, sequence, previous receipt hash, and issuer session map
to gateway run, generation, parent, and session fields. A challenge nonce and
external coverage/evidence manifest are not authenticated by that v0.5 source
signature. They become usable only when a trusted independent witness signs
their binding hashes. Without that support, the gateway returns `undecidable`;
it does not call the Agent Receipt invalid.

This is an exact receipt adapter, not a daemon reimplementation, DID resolver,
generic VC validator, or endorsement by the upstream project.
