# openline-otel

[![Real SDK Release Gate](https://github.com/terryncew/openline-otel/actions/workflows/real-sdk-release-gate.yml/badge.svg)](https://github.com/terryncew/openline-otel/actions/workflows/real-sdk-release-gate.yml)

`openline-otel` adds portable, signed OpenLine receipts to OpenTelemetry traces.
It runs beside an application's existing span processors, so the dashboard keeps
the trace while OpenLine produces independently verifiable proof of what was
captured.

## What It Produces

Ordinary OpenTelemetry spans produce a provisional `trace_receipt`. OpenLine
commits the observed trace structure without guessing what the trace means.

Applications may add explicit `olp.claim`, `olp.evidence`, `olp.relation`, and
`olp.signal` span events. Valid typed events upgrade the output to a provisional
`coherence_input_receipt` containing a committed semantic graph and integer signal
points for downstream COLE measurement.

Late spans do not silently rewrite a receipt. They produce ordered, signed
`amendment_receipt` records. Queue overflow is bound to the affected trace through
a signed `capture_loss_amendment`.

## Install

```bash
pip install "openline-otel @ git+https://github.com/terryncew/openline-otel.git"
```

Python 3.11 or newer is required.

## Attach It to OpenTelemetry

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from openline_otel import OpenLineReceiptProcessor, ReceiptStore

provider = TracerProvider()
trace.set_tracer_provider(provider)

receipts = ReceiptStore()
provider.add_span_processor(
    OpenLineReceiptProcessor(
        Ed25519PrivateKey.generate(),
        receipt_store=receipts,
        grace_interval_seconds=30,
    )
)
```

Other processors can remain attached to the same provider. OpenLine does not
replace Langfuse, LangSmith, Datadog, or another OpenTelemetry destination.

## Add Typed OpenLine Events

```python
import hashlib

claim_hash = hashlib.sha256(b"The tool returned the requested record").hexdigest()

with trace.get_tracer(__name__).start_as_current_span("agent.run") as span:
    span.add_event(
        "olp.claim",
        {
            "id": "claim_1",
            "content_hash": claim_hash,
            "material": True,
        },
    )
```

Typed events use strict schemas. Duplicate node IDs, broken relations, mixed signal
schemas, signal gaps, floats in COLE input, and malformed hashes are rejected. An
invalid typed graph remains a trace receipt with a signed validation error; the
processor does not invent missing semantics.

## Trust Boundary

Every receipt currently states:

```text
attestation: self
capture_status: provisional
```

Root closure plus a grace interval is a capture policy, not proof that no event was
omitted. Running the processor in another process does not create an independent
trust domain. Stronger attestation requires independently controlled capture,
signing keys, and routing enforcement.

## Deterministic Commitments

- Receipt envelopes use Ed25519 signatures and carry the verification key.
- Trace records use domain-separated RFC 6962-style Merkle hashing.
- Receipt JSON uses the `olp-canonical-json-int-v1` profile.
- Ordinary floats are committed as exact tagged IEEE-754 binary64 bytes.
- Epoch-nanosecond timestamps and other large OTel integers are committed as tagged
  canonical decimal strings.
- COLE signal values enter only as integer micros.

## Verification

```bash
pip install -e .
python -m unittest tests.test_processor -v
python -m unittest tests.test_real_sdk_integration -v
python scripts/generate_conformance.py
node verify-node.mjs artifacts/conformance-receipt.json
```

The release workflow runs the core and real-SDK integration suites on Python 3.11
and 3.12, regenerates a signed conformance receipt, and verifies it independently
with Node.

## Scope

This package is an OpenTelemetry capture adapter and receipt generator. It does not
infer claim/evidence structure from ordinary spans, compute COLE's coherence
metrics, set calibrated risk states, or control downstream execution.

OpenLine records the handoff. COLE measures the admitted graph. Governance systems
may read those outputs without becoming part of the meter.

## License

MIT License. Copyright 2026 Terrynce White.
