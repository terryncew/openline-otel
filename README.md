# openline-otel 0.2.0

[![Real SDK Release Gate](https://github.com/terryncew/openline-otel/actions/workflows/real-sdk-release-gate.yml/badge.svg)](https://github.com/terryncew/openline-otel/actions/workflows/real-sdk-release-gate.yml)

`openline-otel` adds portable, signed OpenLine receipts to OpenTelemetry traces.
It runs beside an application's existing span processors, preserving the trace
while OpenLine produces an independently verifiable signed commitment to what
the adapter observed.

Version 0.2.0 adds an Evidence Gateway. It accepts an OLP Canon receipt or the
pinned Agent Receipts v0.5 wire profile as evidence, preserves the submitted
bytes in a local wallet, and emits a separate signed verdict. Signature validity
is one dimension of that verdict, not a synonym for truth.

## Evidence Gateway

Every verdict reports integrity, provenance, coverage, freshness, evidence
sufficiency, independently witnessed outcome, and causal uptake independently.
Each dimension and the overall decision use only `verified`, `rejected`, or
`undecidable`. There is no `valid: true` shortcut and no combined score.

The gateway is intentionally asymmetric. A correctly signed receipt can verify
integrity while the overall result remains undecidable because required evidence,
terminal coverage, freshness binding, or an independent outcome witness is
missing. Consequential actions require a trusted tool, receiver, user wallet, or
outcome service witness under the configured policy.

## Install

```bash
pip install "openline-otel @ git+https://github.com/terryncew/openline-otel.git"
```

Python 3.11 or newer is required.

## Gateway CLI, MCP, browser, and wallet

```bash
# Run the neutral four-profile hostile benchmark.
openline-evidence benchmark --root .

# Evaluate a receipt and append the signed verdict to the local wallet.
openline-evidence --trust trust-store.json verify receipt.json \
  --session session.json --policy policy.json --manifest manifest.json \
  --evidence-dir evidence --binding binding.json --witness tool-witness.json

# Inspect the wallet or open the loopback-only browser verifier.
openline-evidence wallet
openline-evidence serve

# Expose the verifier as a local newline-delimited stdio MCP server.
openline-evidence --trust trust-store.json mcp

# Gate an upstream stdio MCP server's responses before returning them to the agent.
openline-evidence --key ~/.openline/mcp-receiver.key mcp-proxy \
  --run-id run-42 --session-id session-7 --challenge nonce-1 \
  -- python -m upstream_mcp_server
```

The MCP `evidence.verify` tool accepts `receipt_base64` so it can retain exact
incoming bytes. Object-form `receipt` is a convenience mode and necessarily
serializes the object. The browser sends exact pasted receipt text to its
loopback server. Neither surface exposes the wallet signing key.

The forward proxy leaves the upstream request and successful response bytes
unchanged. Before returning a tool response to the agent, it hashes the exact
request and response, creates a receiver receipt and witness, runs the gateway,
and stores the signed verdict. It blocks response uptake if that local gate does
not verify. It cannot undo a side effect the upstream tool already performed.

An independently controlled witness can co-sign an observation:

```bash
openline-evidence --key ~/.openline/tool-witness.key witness receipt.json \
  --outcome outcome.json --manifest manifest.json --binding binding.json \
  --witness-id build-ci --witness-type tool --output witness.json
```

Do not reuse the gateway key for an independent witness. See
[`docs/EVIDENCE_GATEWAY.md`](docs/EVIDENCE_GATEWAY.md) for formats and policy.

## OpenTelemetry capture

Ordinary OpenTelemetry spans produce a provisional `trace_receipt`. Applications
may add explicit `olp.claim`, `olp.evidence`, `olp.relation`, and `olp.signal`
events. Valid typed events upgrade output to a provisional
`coherence_input_receipt` with a committed semantic graph and integer signal
points. Late spans produce ordered signed amendments; queue overflow produces a
signed `capture_loss_amendment`.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from openline_otel import OpenLineReceiptProcessor, ReceiptStore

provider = TracerProvider()
trace.set_tracer_provider(provider)
receipts = ReceiptStore()
provider.add_span_processor(OpenLineReceiptProcessor(
    Ed25519PrivateKey.generate(), receipt_store=receipts,
))
```

Typed events use strict schemas. Duplicate node IDs, broken relations, mixed
signal schemas, signal gaps, floats in COLE input, and malformed hashes are
rejected. Invalid typed input remains a trace receipt with a signed validation
error; the processor does not invent missing semantics.

## Trust boundary

The OTel adapter still emits `attestation: self` and
`capture_status: provisional`. Root closure plus a grace interval is a capture
policy, not proof that no event was omitted. Running the processor in another
process alone does not create an independent trust domain.

The Evidence Gateway does not silently upgrade that boundary. Self-attested OLP
capture remains provenance-undecidable. Agent Receipts daemon keys may be
configured as daemon provenance, but operator resistance still depends on actual
key custody and deployment. Trust-store labels are verifier policy, not proof of
kernel isolation.

The MCP receiver is independent of the source agent only when deployed under
separate control. Running it in the same trust domain is useful instrumentation,
not independent provenance.

## Deterministic commitments

- OLP envelopes use Ed25519 and the `olp-canonical-json-int-v1` profile.
- Trace records use domain-separated RFC 6962-style Merkle hashing.
- OTel floats are committed as exact tagged IEEE-754 binary64 bytes.
- Large OTel integers are committed as tagged canonical decimal strings.
- The Agent Receipts adapter uses complete RFC 8785 canonicalization.

## Verification

```bash
pip install -e .
python -m pytest -q
python scripts/generate_conformance.py
node verify-node.mjs artifacts/conformance-receipt.json
python scripts/release_check.py
```

## Scope and claim boundary

The capture package does not infer semantics from ordinary spans, compute COLE
metrics, set calibrated risk states, or control downstream execution.

The 0.2.0 gateway claim is narrower: under configured keys, policy, session
state, and supplied evidence, it distinguishes receipt integrity from evidential
support and abstains or rejects on the shipped hostile controls. It does not
prove an unwitnessed event happened, prove every event reached the verifier,
execute the upstream Agent Receipts daemon, establish production compromise
resistance, or produce legal compliance.

## License

MIT License. Copyright 2026 Terrynce White.
