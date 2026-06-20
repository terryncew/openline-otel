"""OpenLine receipt processor for OpenTelemetry.

Ordinary spans produce structural trace receipts. A coherence input receipt is
produced only when explicit ``olp.*`` span events provide a typed graph and
fixed-point signal. No semantic structure is inferred from ordinary telemetry.
"""

from __future__ import annotations

import hashlib
import json
import queue
import math
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor


ALGORITHM_ID = "olp-otel-receipt-0.1"
CANONICALIZATION_ID = "olp-canonical-json-int-v1"
SPEC_URI = "https://github.com/terryncew/openline-core"
OLP_EVENT_NAMES = frozenset(
    {"olp.claim", "olp.evidence", "olp.relation", "olp.signal"}
)
MAX_SAFE_INTEGER = (1 << 53) - 1


def _validate_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer outside interoperable range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are forbidden")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"{path}: keys must be ASCII strings")
            _validate_json(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Canonical JSON profile for ASCII-keyed, integer-only OLP data."""
    _validate_json(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes_raw().hex()


def sign_receipt(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical_json(body)
    envelope = dict(body)
    envelope["payload_hash"] = hashlib.sha256(payload).hexdigest()
    envelope["signature"] = {
        "algorithm": "Ed25519",
        "public_key": _public_key_hex(key),
        "value": key.sign(payload).hex(),
    }
    return envelope


def verify_receipt(receipt: Mapping[str, Any]) -> bool:
    try:
        body = dict(receipt)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        payload = canonical_json(body)
        if hashlib.sha256(payload).hexdigest() != payload_hash:
            return False
        if signature.get("algorithm") != "Ed25519":
            return False
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["public_key"]))
        key.verify(bytes.fromhex(signature["value"]), payload)
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def _hex_id(value: int, width: int) -> str:
    return f"{value:0{width}x}"


def _normalize_value(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            return {"$int": str(value)}
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite OTel float attribute")
        return {"$f64": struct.pack(">d", value).hex()}
    if isinstance(value, tuple):
        return [_normalize_value(item) for item in value]
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    return value


def merkle_root(records: Sequence[Any]) -> str:
    """RFC 6962-style domain-separated tree with odd nodes promoted."""
    if not records:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + canonical_json(record)).digest() for record in records]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(
                    hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
                )
        level = next_level
    return level[0].hex()


def _attributes(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        str(key): _normalize_value(item)
        for key, item in sorted((value or {}).items(), key=lambda pair: pair[0])
    }


@dataclass(frozen=True)
class EventSnapshot:
    name: str
    timestamp_unix_nano: int
    attributes: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "timestamp_unix_nano": _normalize_value(self.timestamp_unix_nano),
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class SpanSnapshot:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: int
    start_time_unix_nano: int
    end_time_unix_nano: int
    status_code: int
    status_description: str | None
    attributes: dict[str, Any]
    events: tuple[EventSnapshot, ...]
    links: tuple[dict[str, Any], ...]
    resource: dict[str, Any]
    instrumentation_scope: dict[str, Any]

    @classmethod
    def from_readable_span(cls, span: ReadableSpan) -> "SpanSnapshot":
        context = span.context
        if context is None:
            raise ValueError("ended span has no context")
        parent_span_id = None
        if span.parent is not None and span.parent.span_id:
            parent_span_id = _hex_id(span.parent.span_id, 16)
        events = tuple(
            EventSnapshot(
                name=event.name,
                timestamp_unix_nano=int(event.timestamp or 0),
                attributes=_attributes(event.attributes),
            )
            for event in span.events
        )
        links = tuple(
            {
                "trace_id": _hex_id(link.context.trace_id, 32),
                "span_id": _hex_id(link.context.span_id, 16),
                "attributes": _attributes(link.attributes),
            }
            for link in span.links
        )
        scope = span.instrumentation_scope
        return cls(
            trace_id=_hex_id(context.trace_id, 32),
            span_id=_hex_id(context.span_id, 16),
            parent_span_id=parent_span_id,
            name=span.name,
            kind=int(span.kind.value),
            start_time_unix_nano=int(span.start_time or 0),
            end_time_unix_nano=int(span.end_time or 0),
            status_code=int(span.status.status_code.value),
            status_description=span.status.description,
            attributes=_attributes(span.attributes),
            events=events,
            links=links,
            resource=_attributes(span.resource.attributes),
            instrumentation_scope={
                "name": scope.name if scope else "",
                "version": scope.version if scope else None,
                "schema_url": scope.schema_url if scope else None,
                "attributes": _attributes(scope.attributes if scope else None),
            },
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind,
            "start_time_unix_nano": _normalize_value(self.start_time_unix_nano),
            "end_time_unix_nano": _normalize_value(self.end_time_unix_nano),
            "status": {
                "code": self.status_code,
                "description": self.status_description,
            },
            "attributes": self.attributes,
            "events": [event.as_dict() for event in self.events],
            "links": list(self.links),
            "resource": self.resource,
            "instrumentation_scope": self.instrumentation_scope,
        }


class ReceiptStore:
    """Thread-safe in-memory sink used by the package and conformance tests."""

    def __init__(self) -> None:
        self._receipts: list[dict[str, Any]] = []
        self._condition = threading.Condition()

    def emit(self, receipt: dict[str, Any]) -> None:
        with self._condition:
            self._receipts.append(receipt)
            self._condition.notify_all()

    def all(self) -> list[dict[str, Any]]:
        with self._condition:
            return list(self._receipts)

    def wait_for(self, predicate: Callable[[dict[str, Any]], bool], timeout: float = 2) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                for receipt in self._receipts:
                    if predicate(receipt):
                        return receipt
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("receipt was not emitted")
                self._condition.wait(remaining)


@dataclass
class TraceState:
    spans: dict[str, SpanSnapshot] = field(default_factory=dict)
    root_closed_monotonic: float | None = None
    dropped_span_count: int = 0
    receipt: dict[str, Any] | None = None
    amendment_count: int = 0
    last_amendment_hash: str | None = None
    pending_reported_loss: int = 0


@dataclass(frozen=True)
class QueueItem:
    kind: str
    trace_id: str
    span: SpanSnapshot | None = None
    observed_monotonic: float = 0


class OpenLineReceiptProcessor(SpanProcessor):
    """Non-blocking OTel processor that emits provisional signed receipts."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        *,
        grace_interval_seconds: float = 30,
        queue_size: int = 2048,
        receipt_store: ReceiptStore | None = None,
        semconv_schema_id: str = "otel-genai-development-2026-06",
    ) -> None:
        if grace_interval_seconds < 0:
            raise ValueError("grace interval must be non-negative")
        if queue_size < 1:
            raise ValueError("queue size must be positive")
        self._key = signing_key
        self._grace = grace_interval_seconds
        self._queue: queue.Queue[QueueItem] = queue.Queue(maxsize=queue_size)
        self._store = receipt_store or ReceiptStore()
        self._semconv_schema_id = semconv_schema_id
        self._states: dict[str, TraceState] = {}
        self._loss_lock = threading.Lock()
        self._pending_loss: dict[str, int] = {}
        self._stop = threading.Event()
        self._shutdown = False
        self._thread = threading.Thread(target=self._run, name="openline-otel", daemon=True)
        self._thread.start()

    @property
    def receipt_store(self) -> ReceiptStore:
        return self._store

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        return None

    def on_end(self, span: ReadableSpan) -> None:
        if self._shutdown:
            return
        snapshot = SpanSnapshot.from_readable_span(span)
        item = QueueItem(
            kind="span",
            trace_id=snapshot.trace_id,
            span=snapshot,
            observed_monotonic=time.monotonic(),
        )
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._loss_lock:
                self._pending_loss[snapshot.trace_id] = self._pending_loss.get(snapshot.trace_id, 0) + 1

    def _take_loss(self, trace_id: str) -> int:
        with self._loss_lock:
            return self._pending_loss.pop(trace_id, 0)

    def _apply_pending_loss(self) -> None:
        with self._loss_lock:
            losses = self._pending_loss
            self._pending_loss = {}
        for trace_id, count in losses.items():
            state = self._states.setdefault(trace_id, TraceState())
            state.dropped_span_count += count
            if state.receipt is not None:
                state.pending_reported_loss += count
                self._emit_loss_amendment(state, trace_id)

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.01)
            except queue.Empty:
                self._apply_pending_loss()
                self._finalize_due()
                continue
            try:
                self._consume(item)
            finally:
                self._queue.task_done()
            self._apply_pending_loss()
            self._finalize_due()

    def _consume(self, item: QueueItem) -> None:
        if item.span is None:
            return
        state = self._states.setdefault(item.trace_id, TraceState())
        state.dropped_span_count += self._take_loss(item.trace_id)
        if item.span.span_id in state.spans:
            existing = state.spans[item.span.span_id]
            if existing != item.span:
                state.dropped_span_count += 1
            return
        if state.receipt is not None:
            self._emit_amendment(state, item.span)
            return
        state.spans[item.span.span_id] = item.span
        if item.span.parent_span_id is None:
            state.root_closed_monotonic = item.observed_monotonic

    def _finalize_due(self) -> None:
        now = time.monotonic()
        for trace_id, state in list(self._states.items()):
            if state.receipt is not None or state.root_closed_monotonic is None:
                continue
            if now - state.root_closed_monotonic >= self._grace:
                self._emit_initial(trace_id, state, reason="grace_elapsed")

    def _typed_events(self, spans: Sequence[SpanSnapshot]) -> list[EventSnapshot]:
        return [
            event
            for span in spans
            for event in span.events
            if event.name in OLP_EVENT_NAMES
        ]

    def _validate_typed_events(self, events: Sequence[EventSnapshot]) -> dict[str, Any]:
        claims: dict[str, dict[str, Any]] = {}
        evidence: dict[str, dict[str, Any]] = {}
        relations: list[dict[str, Any]] = []
        signals: dict[int, dict[str, Any]] = {}
        schemas: set[str] = set()

        def exact(attrs: dict[str, Any], required: set[str]) -> None:
            if set(attrs) != required:
                raise ValueError(f"typed event fields mismatch: expected {sorted(required)}")

        for event in events:
            attrs = event.attributes
            if event.name == "olp.claim":
                exact(attrs, {"id", "content_hash", "material"})
                self._validate_id_hash(attrs["id"], attrs["content_hash"])
                if not isinstance(attrs["material"], bool):
                    raise ValueError("claim material must be boolean")
                if attrs["id"] in claims:
                    raise ValueError("duplicate claim id")
                claims[attrs["id"]] = attrs
            elif event.name == "olp.evidence":
                exact(attrs, {"id", "content_hash", "observed"})
                self._validate_id_hash(attrs["id"], attrs["content_hash"])
                if attrs["observed"] is not True:
                    raise ValueError("evidence must be directly observed")
                if attrs["id"] in evidence:
                    raise ValueError("duplicate evidence id")
                evidence[attrs["id"]] = attrs
            elif event.name == "olp.relation":
                exact(attrs, {"src", "dst", "relation_type"})
                if attrs["relation_type"] not in {"supports", "contradicts", "depends_on"}:
                    raise ValueError("unsupported relation type")
                relations.append(attrs)
            elif event.name == "olp.signal":
                exact(attrs, {"sequence", "value_micros", "signal_schema_id"})
                sequence = attrs["sequence"]
                value = attrs["value_micros"]
                schema = attrs["signal_schema_id"]
                if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
                    raise ValueError("signal sequence must be a non-negative integer")
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ValueError("signal value must be integer micros")
                if not isinstance(schema, str) or not schema:
                    raise ValueError("signal schema id is required")
                if sequence in signals:
                    raise ValueError("duplicate signal sequence")
                schemas.add(schema)
                signals[sequence] = attrs

        if set(claims) & set(evidence):
            raise ValueError("node ids must be globally unique")
        nodes = set(claims) | set(evidence)
        for relation in relations:
            if relation["src"] not in nodes or relation["dst"] not in nodes:
                raise ValueError("relation references missing node")
        if len(schemas) > 1:
            raise ValueError("signal schema must be uniform within a trace")
        ordered_sequences = sorted(signals)
        if ordered_sequences and ordered_sequences != list(range(ordered_sequences[0], ordered_sequences[0] + len(ordered_sequences))):
            raise ValueError("signal sequence contains gaps")
        return {
            "claims": [claims[key] for key in sorted(claims)],
            "evidence": [evidence[key] for key in sorted(evidence)],
            "relations": sorted(relations, key=lambda item: (item["src"], item["dst"], item["relation_type"])),
            "signals": [signals[key] for key in ordered_sequences],
        }

    @staticmethod
    def _validate_id_hash(node_id: Any, content_hash: Any) -> None:
        if not isinstance(node_id, str) or not node_id or not node_id.isascii():
            raise ValueError("node id must be non-empty ASCII")
        if not isinstance(content_hash, str) or len(content_hash) != 64:
            raise ValueError("content hash must be 64 hexadecimal characters")
        try:
            bytes.fromhex(content_hash)
        except ValueError as exc:
            raise ValueError("content hash is not hexadecimal") from exc

    def _base(self, trace_id: str, state: TraceState, spans: list[SpanSnapshot]) -> dict[str, Any]:
        span_records = [span.as_dict() for span in spans]
        return {
            "kind": "trace_receipt",
            "receipt_version": "0.1",
            "algorithm_id": ALGORITHM_ID,
            "canonicalization_id": CANONICALIZATION_ID,
            "spec_uri": SPEC_URI,
            "trace_id": trace_id,
            "attestation": "self",
            "capture_status": "provisional",
            "capture_loss": state.dropped_span_count > 0,
            "dropped_span_count": state.dropped_span_count,
            "observed_span_count": len(spans),
            "trace_root": merkle_root(span_records),
            "tree_algorithm": "rfc6962-mth-sha256-promote-odd-v1",
            "completion_policy": {
                "type": "root_close_plus_grace",
                "grace_millis": int(self._grace * 1000),
                "semconv_schema_id": self._semconv_schema_id,
            },
        }

    def _emit_initial(self, trace_id: str, state: TraceState, reason: str) -> None:
        spans = sorted(
            state.spans.values(),
            key=lambda span: (span.start_time_unix_nano, span.span_id),
        )
        base = self._base(trace_id, state, spans)
        base["seal_reason"] = reason
        events = self._typed_events(spans)
        if events:
            try:
                typed = self._validate_typed_events(events)
            except ValueError as exc:
                base["typed_event_status"] = "invalid"
                base["typed_event_error"] = str(exc)
            else:
                base.update(
                    {
                        "kind": "coherence_input_receipt",
                        "semantic_claims": True,
                        "typed_event_status": "valid",
                        "semantic_graph_hash": _sha256(
                            {
                                "claims": typed["claims"],
                                "evidence": typed["evidence"],
                                "relations": typed["relations"],
                            }
                        ),
                        "signal_schema_id": (
                            typed["signals"][0]["signal_schema_id"]
                            if typed["signals"]
                            else None
                        ),
                        "signal_points_micros": [
                            signal["value_micros"] for signal in typed["signals"]
                        ],
                        "state_cap": "white",
                    }
                )
        else:
            base["semantic_claims"] = False
        receipt = sign_receipt(base, self._key)
        state.receipt = receipt
        self._store.emit(receipt)

    def _emit_amendment(self, state: TraceState, span: SpanSnapshot) -> None:
        assert state.receipt is not None
        state.amendment_count += 1
        parent_hash = state.last_amendment_hash or state.receipt["payload_hash"]
        body = {
            "kind": "amendment_receipt",
            "receipt_version": "0.1",
            "algorithm_id": ALGORITHM_ID,
            "canonicalization_id": CANONICALIZATION_ID,
            "spec_uri": SPEC_URI,
            "trace_id": span.trace_id,
            "attestation": "self",
            "capture_status": "provisional",
            "amendment_sequence": state.amendment_count,
            "previous_receipt_hash": parent_hash,
            "late_span_hash": _sha256(span.as_dict()),
            "reason": "span_arrived_after_provisional_seal",
        }
        receipt = sign_receipt(body, self._key)
        state.last_amendment_hash = receipt["payload_hash"]
        self._store.emit(receipt)

    def _emit_loss_amendment(self, state: TraceState, trace_id: str) -> None:
        if state.receipt is None or state.pending_reported_loss == 0:
            return
        state.amendment_count += 1
        parent_hash = state.last_amendment_hash or state.receipt["payload_hash"]
        body = {
            "kind": "capture_loss_amendment",
            "receipt_version": "0.1",
            "algorithm_id": ALGORITHM_ID,
            "canonicalization_id": CANONICALIZATION_ID,
            "spec_uri": SPEC_URI,
            "trace_id": trace_id,
            "attestation": "self",
            "capture_status": "provisional",
            "amendment_sequence": state.amendment_count,
            "previous_receipt_hash": parent_hash,
            "new_dropped_span_count": state.pending_reported_loss,
            "cumulative_dropped_span_count": state.dropped_span_count,
            "reason": "processor_queue_overflow_after_provisional_seal",
        }
        receipt = sign_receipt(body, self._key)
        state.pending_reported_loss = 0
        state.last_amendment_hash = receipt["payload_hash"]
        self._store.emit(receipt)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        deadline = time.monotonic() + timeout_millis / 1000
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.001)
        return self._queue.unfinished_tasks == 0

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._stop.set()
        self._thread.join(timeout=max(1.0, self._grace + 0.5))
        self._apply_pending_loss()
        for trace_id, state in list(self._states.items()):
            if state.receipt is None and state.spans:
                self._emit_initial(trace_id, state, reason="shutdown_before_grace_elapsed")
