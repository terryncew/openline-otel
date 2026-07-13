"""Neutral hostile benchmark for receipt trust surfaces.

The benchmark models declared capture boundaries. It does not execute or grade
the upstream Agent Receipts daemon binary.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .gateway import (
    EvidenceGateway, GatewayPolicy, GatewaySession, TrustStore,
    create_witness, detect_source_format, sha256_bytes, sha256_json,
)
from .jcs import canonical_bytes as jcs_bytes
from .processor import canonical_json, sign_receipt, verify_receipt


PROFILES = (
    "agent_receipts_daemon",
    "olp_self_attested_capture",
    "olp_daemon_capture",
    "olp_receiver_tool_witness_capture",
)
ATTACKS = (
    "agent_compromised",
    "operator_compromised",
    "event_omitted",
    "tail_truncated",
    "receipt_replayed",
    "cross_run_receipt_spliced",
    "validly_signed_fabricated_outcome",
    "valid_signature_insufficient_evidence",
    "evidence_artifact_altered_and_chain_resealed",
)
FIXED_TIME = "2026-07-12T12:00:00Z"


def _key(label: str) -> Ed25519PrivateKey:
    import hashlib
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _agent_receipt(
    key: Ed25519PrivateKey, *, run_id: str, session_id: str, generation: int,
    parent_hash: str, action: dict[str, Any], outcome: dict[str, Any],
) -> bytes:
    identifier = uuid.UUID(int=generation)
    body = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentreceipts.ai/context/v2",
        ],
        "id": f"urn:receipt:{identifier}",
        "type": ["VerifiableCredential", "AgentReceipt"],
        "version": "0.5.0",
        "issuer": {
            "id": "did:agent-receipts-daemon:benchmark",
            "session_id": session_id,
            "runtime": {"agent_id": "benchmark-agent", "agent_type": "controlled"},
        },
        "issuanceDate": FIXED_TIME,
        "credentialSubject": {
            "principal": {"id": "did:user:benchmark"},
            "action": action,
            "outcome": outcome,
            "chain": {
                "sequence": generation,
                "previous_receipt_hash": None if parent_hash == "GENESIS" else parent_hash,
                "chain_id": run_id,
            },
        },
    }
    signature = key.sign(jcs_bytes(body))
    proof_value = "u" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    receipt = {
        **body,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": FIXED_TIME,
            "verificationMethod": "did:agent-receipts-daemon:benchmark#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": proof_value,
        },
    }
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _olp_receipt(
    key: Ed25519PrivateKey, *, attestation: str, run_id: str, session_id: str,
    generation: int, parent_hash: str, challenge: str, action: dict[str, Any],
    outcome: dict[str, Any], manifest: dict[str, Any], capture_status: str,
) -> bytes:
    receipt = sign_receipt({
        "kind": "evidence_capture_receipt",
        "receipt_version": "0.2",
        "attestation": attestation,
        "capture_status": capture_status,
        "capture_loss": False,
        "run_id": run_id,
        "session_id": session_id,
        "parent_hash": parent_hash,
        "generation_index": generation,
        "challenge_nonce": challenge,
        "action": action,
        "outcome": outcome,
        "evidence_manifest": manifest,
        "timestamp": FIXED_TIME,
    }, key)
    return canonical_json(receipt)


def _manifest(
    artifact: bytes, *, observed: tuple[str, ...] = ("intent", "tool_call", "tool_result"),
    terminal: bool = True,
) -> dict[str, Any]:
    return {
        "schema": "openline.evidence-manifest.v1",
        "claims": [{"id": "claim-action-result", "material": True, "evidence_ids": ["tool-result"]}],
        "artifacts": [{"id": "tool-result", "sha256": sha256_bytes(artifact)}],
        "observed_event_ids": list(observed),
        "terminal": terminal,
    }


@dataclass
class Fixture:
    source: bytes
    session: GatewaySession
    policy: GatewayPolicy
    manifest: dict[str, Any]
    artifacts: dict[str, bytes]
    binding: dict[str, Any]
    witnesses: list[dict[str, Any]]
    trust: TrustStore
    native_accepts: bool


def _fixture(profile: str, attack: str | None) -> Fixture:
    source_key = _key(f"source:{profile}")
    witness_key = _key("independent-tool-witness")
    run_id, session_id, challenge = "benchmark-run-A", "benchmark-session-A", "challenge-A"
    generation, parent = 1, "GENESIS"
    artifact = b"tool result: transfer blocked by policy"
    action = {
        "id": "act_00000000-0000-4000-a000-000000000001",
        "type": "tool.policy.check",
        "risk_level": "high",
        "timestamp": FIXED_TIME,
    }
    outcome = {"status": "success"}
    observed = ("intent", "tool_call", "tool_result")
    terminal = True
    artifacts = {"tool-result": artifact}

    if attack in {"agent_compromised", "operator_compromised", "validly_signed_fabricated_outcome"}:
        outcome = {"status": "success"}
        artifact = b"issuer-claimed result without independent observation"
        artifacts = {"tool-result": artifact}
    elif attack == "event_omitted":
        observed = ("intent", "tool_result")
    elif attack == "tail_truncated":
        terminal = False
    elif attack == "valid_signature_insufficient_evidence":
        artifacts = {}
    elif attack == "evidence_artifact_altered_and_chain_resealed":
        artifact = b"operator-resealed replacement evidence"
        artifacts = {"tool-result": artifact}

    manifest = _manifest(artifact, observed=observed, terminal=terminal)
    binding = {
        "run_id": run_id,
        "session_id": session_id,
        "parent_hash": parent,
        "generation_index": generation,
        "challenge_nonce": challenge,
    }
    expected_run = "benchmark-run-B" if attack == "cross_run_receipt_spliced" else run_id
    seen = ()

    if profile == "agent_receipts_daemon":
        source = _agent_receipt(
            source_key, run_id=run_id, session_id=session_id, generation=generation,
            parent_hash=parent, action=action, outcome=outcome,
        )
        trust = TrustStore(
            agent_receipts_keys={
                "did:agent-receipts-daemon:benchmark#key-1": {
                    "public_key_pem": _public_pem(source_key),
                    "capture_mode": "agent_daemon",
                    "issuer_id": "did:agent-receipts-daemon:benchmark",
                }
            },
            witness_keys={"tool-witness": {"public_key": _public_hex(witness_key)}},
        )
        native_accepts = True
        capture_witness = False
    else:
        attestation = {
            "olp_self_attested_capture": "self",
            "olp_daemon_capture": "daemon",
            "olp_receiver_tool_witness_capture": "receiver",
        }[profile]
        capture_status = "provisional" if attestation == "self" else "final"
        source = _olp_receipt(
            source_key, attestation=attestation, run_id=run_id, session_id=session_id,
            generation=generation, parent_hash=parent, challenge=challenge,
            action=action, outcome=outcome, manifest=manifest, capture_status=capture_status,
        )
        trust = TrustStore(
            olp_keys={_public_hex(source_key): {"capture_mode": attestation}},
            witness_keys={"tool-witness": {"public_key": _public_hex(witness_key)}},
        )
        native_accepts = verify_receipt(json.loads(source))
        capture_witness = profile == "olp_receiver_tool_witness_capture"

    if attack == "receipt_replayed":
        seen = (sha256_bytes(source),)
    session = GatewaySession(
        expected_run_id=expected_run,
        expected_session_id=session_id,
        expected_parent_hash=parent,
        last_generation_index=0,
        expected_challenge_nonce=challenge,
        seen_source_hashes=seen,
    )
    witnesses: list[dict[str, Any]] = []
    if capture_witness:
        honest_artifact = b"tool result: transfer blocked by policy"
        honest_manifest = _manifest(honest_artifact)
        honest_outcome = {"status": "success"}
        witness_body = {
            "source_receipt_sha256": sha256_bytes(source),
            "binding_hash": sha256_json(binding),
            "manifest_hash": sha256_json(honest_manifest if attack in {
                "agent_compromised", "operator_compromised", "validly_signed_fabricated_outcome",
                "evidence_artifact_altered_and_chain_resealed",
            } else manifest),
            "outcome_hash": sha256_json(honest_outcome if attack in {
                "agent_compromised", "operator_compromised", "validly_signed_fabricated_outcome",
            } else outcome),
        }
        witnesses.append(create_witness(
            witness_body, "tool-witness", "tool", witness_key, timestamp=FIXED_TIME,
        ))
    return Fixture(
        source=source, session=session,
        policy=GatewayPolicy(
            required_event_ids=("intent", "tool_call", "tool_result"),
            required_evidence_ids=("tool-result",),
        ),
        manifest=manifest, artifacts=artifacts, binding=binding, witnesses=witnesses,
        trust=trust, native_accepts=native_accepts,
    )


def run_benchmark() -> dict[str, Any]:
    gateway_key = _key("gateway-verdict-key")
    rows: list[dict[str, Any]] = []
    for profile in PROFILES:
        for attack in (None, *ATTACKS):
            fixture = _fixture(profile, attack)
            gateway = EvidenceGateway(gateway_key, fixture.trust)
            wall_start, cpu_start = time.perf_counter_ns(), time.process_time_ns()
            verdict = gateway.evaluate(
                fixture.source,
                session=fixture.session,
                policy=fixture.policy,
                evidence_artifacts=fixture.artifacts,
                evidence_manifest=fixture.manifest,
                binding=fixture.binding,
                witnesses=fixture.witnesses,
                issued_at=FIXED_TIME,
            )
            wall_ns, cpu_ns = time.perf_counter_ns() - wall_start, time.process_time_ns() - cpu_start
            unsafe = attack is not None
            rows.append({
                "profile": profile,
                "case": attack or "clean_control",
                "ground_truth": "unsafe_or_unsupported" if unsafe else "supported",
                "source_format": detect_source_format(json.loads(fixture.source)),
                "native_integrity_accepts": fixture.native_accepts,
                "gateway_status": verdict["overall_status"],
                "false_acceptance_native": bool(unsafe and fixture.native_accepts),
                "false_acceptance_gateway": bool(unsafe and verdict["overall_status"] == "verified"),
                "detected": bool(unsafe and verdict["overall_status"] == "rejected"),
                "abstained": verdict["overall_status"] == "undecidable",
                "bytes_inspected": len(fixture.source) + sum(map(len, fixture.artifacts.values())),
                "evidence_reads": int(verdict["evidence_reads"]),
                "wall_ns": wall_ns,
                "cpu_ns": cpu_ns,
                "dimension_statuses": {
                    key: value["status"] for key, value in verdict["dimensions"].items()
                },
            })
    by_profile: dict[str, Any] = {}
    for profile in PROFILES:
        selected = [row for row in rows if row["profile"] == profile]
        attacks = [row for row in selected if row["case"] != "clean_control"]
        by_profile[profile] = {
            "clean_gateway_status": next(row["gateway_status"] for row in selected if row["case"] == "clean_control"),
            "native_false_acceptances": sum(int(row["false_acceptance_native"]) for row in attacks),
            "gateway_false_acceptances": sum(int(row["false_acceptance_gateway"]) for row in attacks),
            "gateway_detections": sum(int(row["detected"]) for row in attacks),
            "gateway_abstentions": sum(int(row["abstained"]) for row in attacks),
            "attack_count": len(attacks),
            "mean_bytes_inspected": sum(row["bytes_inspected"] for row in selected) / len(selected),
            "mean_evidence_reads": sum(row["evidence_reads"] for row in selected) / len(selected),
            "timing_status": "environment_sensitive_not_a_reproducibility_claim",
        }
    gates = {
        "no_gateway_false_acceptance": all(not row["false_acceptance_gateway"] for row in rows),
        "receiver_tool_witness_clean_control_verified": by_profile["olp_receiver_tool_witness_capture"]["clean_gateway_status"] == "verified",
        "integrity_only_boundary_exposed": all(
            row["native_integrity_accepts"]
            for row in rows if row["case"] in {"validly_signed_fabricated_outcome", "valid_signature_insufficient_evidence"}
        ),
        "unsafe_cases_rejected_or_abstained": all(
            row["gateway_status"] in {"rejected", "undecidable"}
            for row in rows if row["case"] != "clean_control"
        ),
        "separate_measurements_no_combined_score": True,
    }
    return {
        "schema": "openline.evidence-gateway.benchmark.v1",
        "release": "0.2.0",
        "upstream_agent_receipts_pin": {
            "repository": "https://github.com/agent-receipts/obsigna",
            "commit": "df6833a39743e17127d5ad4b10cdc8f6734d8e03",
            "wire_profile": "0.5.0",
            "execution_boundary": "Adapter verified against the pinned public v0.5 vector; benchmark models declared trust surfaces and does not execute the upstream daemon binary.",
        },
        "claim_boundary": (
            "A valid receipt can be an input to a stricter evidence decision. This benchmark tests the declared "
            "synthetic attacks and does not establish production compromise resistance or legal compliance."
        ),
        "profiles": list(PROFILES),
        "attacks": list(ATTACKS),
        "rows": rows,
        "by_profile": by_profile,
        "gates": gates,
        "gate_count": len(gates),
        "passed_gate_count": sum(int(value) for value in gates.values()),
        "passed": all(gates.values()),
        "combined_score": None,
    }


def write_benchmark(root: Path) -> dict[str, Any]:
    result = run_benchmark()
    output = root / "results"
    output.mkdir(parents=True, exist_ok=True)
    (output / "evidence_gateway_benchmark.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    buffer = io.StringIO(newline="")
    fields = [
        "profile", "case", "ground_truth", "source_format", "native_integrity_accepts",
        "gateway_status", "false_acceptance_native", "false_acceptance_gateway", "detected",
        "abstained", "bytes_inspected", "evidence_reads", "wall_ns", "cpu_ns",
    ]
    writer = csv.DictWriter(
        buffer,
        fieldnames=fields,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(result["rows"])
    (output / "evidence_gateway_benchmark.csv").write_text(buffer.getvalue(), encoding="utf-8")
    return result
