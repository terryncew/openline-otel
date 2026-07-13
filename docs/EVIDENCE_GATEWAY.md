# OLP Evidence Gateway

The Evidence Gateway is a verification layer, not a replacement receipt
envelope. It retains incoming receipt bytes unchanged in the local wallet and
signs a new verdict naming their SHA-256 hash.

## Decision model

The gateway evaluates seven dimensions independently. Integrity checks the
source signature and canonical bytes. Provenance asks whether the signing key is
trusted for a capture role. Coverage checks a terminal event manifest against
policy-required events. Freshness compares authenticated run, session, parent,
generation, and challenge fields with verifier-held state. Evidence sufficiency
recomputes artifact hashes for material claims. Outcome witnessing requires an
independently controlled signer for consequential actions. Causal uptake verifies
that a later controller receipt names the prior gateway verdict that affected
its action.

`rejected` means supplied material contradicts a required rule: bad signature,
hash mismatch, replay, cross-run splice, witness conflict, policy denial, or
malformed supporting data. `undecidable` means a required fact is absent or not
independently established. Missing evidence is not silently promoted to truth or
falsity.

The caller owns `GatewaySession` and advances it only from a `verified` verdict
using `advance_gateway_session`. Verification is pure and never mutates session
state internally.

## Trust store

```json
{
  "agent_receipts_keys": {
    "did:agent:example#key-1": {
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "capture_mode": "agent_daemon",
      "issuer_id": "did:agent-receipts-daemon:example"
    }
  },
  "olp_keys": {
    "64-hex-character-public-key": {"capture_mode": "receiver"}
  },
  "witness_keys": {
    "build-ci": {"public_key": "64-hex-character-public-key"}
  }
}
```

Allowed provenance roles are `agent_daemon` for the Agent Receipts adapter and
`daemon`, `receiver`, or `tool_witness` for OLP. A configured role says what the
verifier trusts that key to represent. Deployment must separately enforce key
custody, process isolation, and routing.

## Session

```json
{
  "expected_run_id": "run-42",
  "expected_session_id": "session-7",
  "expected_parent_hash": "GENESIS",
  "last_generation_index": 0,
  "expected_challenge_nonce": "nonce-from-verifier",
  "seen_source_hashes": []
}
```

Freshness is stateful. A valid signature cannot make a repeated source hash,
wrong run or session, wrong parent, non-advancing generation, or wrong challenge
current. Agent Receipts v0.5 does not carry every field, so missing fields may be
supplied externally only when an independent witness signs the external binding
hash.

## Evidence manifest

```json
{
  "schema": "openline.evidence-manifest.v1",
  "claims": [
    {"id": "claim-1", "material": true, "evidence_ids": ["tool-result"]}
  ],
  "artifacts": [
    {"id": "tool-result", "path": "tool-result", "sha256": "<64 hex>"}
  ],
  "observed_event_ids": ["intent", "tool_call", "tool_result"],
  "terminal": true
}
```

External manifests must be bound by an independent witness. OLP receipts may
embed the manifest inside their signed body. An embedded manifest still cannot
independently witness its own outcome.

## Local surfaces

`openline-evidence verify` is the batch CLI. `openline-evidence mcp` is a local
stdio verification server with verify/list/get tools. `openline-evidence
mcp-proxy` forwards an upstream stdio MCP server one request at a time. For each
tool response it commits exact request and response bytes, emits a receiver
receipt and witness, evaluates them, and forwards the unchanged response only
after a verified verdict. `openline-evidence serve` is a loopback-only browser
front end. The SQLite wallet stores exact source bytes and signed verdicts in a
local parent-hash chain; it rejects invalid verdicts and forks.

The proxy gates whether the result reaches the agent's next decision; it cannot
undo an upstream tool side effect. Its receiver attestation is independent only
when the proxy process and key are controlled separately from the source actor.
These are local prototype surfaces, not a hardened multi-tenant service.
