"""Evidence Gateway: receipt integrity is an input, never the final verdict."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .jcs import canonical_bytes as jcs_bytes
from .processor import canonical_json, sign_receipt, verify_receipt


GATEWAY_SCHEMA = "openline.evidence-gateway.verdict.v1"
WITNESS_SCHEMA = "openline.evidence-gateway.witness.v1"
UPTAKE_SCHEMA = "openline.evidence-gateway.uptake.v1"
DIMENSIONS = (
    "integrity",
    "provenance",
    "coverage",
    "freshness",
    "evidence_sufficiency",
    "independently_witnessed_outcome",
    "causal_uptake",
)
MAX_SAFE_INTEGER = (1 << 53) - 1
AGENT_RECEIPT_ID = re.compile(r"^urn:receipt:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
AGENT_ACTION_ID = re.compile(r"^act_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256_TAGGED = re.compile(r"^sha256:[0-9a-f]{64}$")
MULTIBASE_SIGNATURE = re.compile(r"^u[A-Za-z0-9_-]{86}$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(jcs_bytes(value))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _loads_strict(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON key: {key}")
            output[key] = value
        return output

    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-JSON numeric constant: {value}")

    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("receipt must be a JSON object")
    return value


def _dimension(status: str, *reasons: str, evidence: Sequence[str] = ()) -> dict[str, Any]:
    if status not in {"verified", "rejected", "undecidable"}:
        raise ValueError(f"invalid dimension status: {status}")
    return {
        "status": status,
        "reason_codes": sorted(set(reason for reason in reasons if reason)),
        "evidence": sorted(set(evidence)),
    }


def _binding_input(value: Mapping[str, Any] | None) -> tuple[dict[str, Any], str | None]:
    if value is None:
        return {}, None
    if not isinstance(value, Mapping):
        return {}, "external_binding_not_an_object"
    allowed = {
        "run_id", "session_id", "parent_hash", "generation_index", "challenge_nonce",
    }
    if set(value) - allowed:
        return {}, "external_binding_unknown_fields"
    output = dict(value)
    for key in ("run_id", "session_id", "parent_hash"):
        if key in output and (not isinstance(output[key], str) or not output[key]):
            return {}, f"external_binding_{key}_invalid"
    if "challenge_nonce" in output and not isinstance(output["challenge_nonce"], str):
        return {}, "external_binding_challenge_nonce_invalid"
    if "generation_index" in output and (
        not isinstance(output["generation_index"], int)
        or isinstance(output["generation_index"], bool)
        or not 1 <= output["generation_index"] <= MAX_SAFE_INTEGER
    ):
        return {}, "external_binding_generation_index_invalid"
    return output, None


def _manifest_error(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value.get("artifacts", []), list):
        return "evidence_manifest_artifacts_invalid"
    if not isinstance(value.get("claims", []), list):
        return "evidence_manifest_claims_invalid"
    if not isinstance(value.get("observed_event_ids", []), list):
        return "evidence_manifest_observed_events_invalid"
    if "terminal" in value and not isinstance(value["terminal"], bool):
        return "evidence_manifest_terminal_invalid"
    for item in value.get("artifacts", []):
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            return "evidence_manifest_artifact_invalid"
        digest = str(item.get("sha256", "")).removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            return "evidence_manifest_artifact_hash_invalid"
    for claim in value.get("claims", []):
        if not isinstance(claim, Mapping) or not isinstance(claim.get("evidence_ids", []), list):
            return "evidence_manifest_claim_invalid"
    return None


@dataclass(frozen=True)
class GatewaySession:
    expected_run_id: str
    expected_session_id: str
    expected_parent_hash: str = "GENESIS"
    last_generation_index: int = 0
    expected_challenge_nonce: str | None = None
    seen_source_hashes: tuple[str, ...] = ()


@dataclass(frozen=True)
class GatewayPolicy:
    required_event_ids: tuple[str, ...] = ()
    required_evidence_ids: tuple[str, ...] = ()
    require_provenance: bool = True
    require_coverage: bool = True
    require_freshness: bool = True
    require_evidence_sufficiency: bool = True
    require_outcome_witness: bool = True
    require_causal_uptake: bool = False
    consequential_risk_levels: tuple[str, ...] = ("high", "critical")
    denied_action_types: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | None) -> "GatewayPolicy":
        value = value or {}
        return cls(
            required_event_ids=tuple(map(str, value.get("required_event_ids", ()))),
            required_evidence_ids=tuple(map(str, value.get("required_evidence_ids", ()))),
            require_provenance=bool(value.get("require_provenance", True)),
            require_coverage=bool(value.get("require_coverage", True)),
            require_freshness=bool(value.get("require_freshness", True)),
            require_evidence_sufficiency=bool(value.get("require_evidence_sufficiency", True)),
            require_outcome_witness=bool(value.get("require_outcome_witness", True)),
            require_causal_uptake=bool(value.get("require_causal_uptake", False)),
            consequential_risk_levels=tuple(map(str, value.get("consequential_risk_levels", ("high", "critical")))),
            denied_action_types=tuple(map(str, value.get("denied_action_types", ()))),
        )


@dataclass
class TrustStore:
    agent_receipts_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    olp_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    witness_keys: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | None) -> "TrustStore":
        value = value or {}
        return cls(
            agent_receipts_keys={str(k): dict(v) for k, v in value.get("agent_receipts_keys", {}).items()},
            olp_keys={str(k): dict(v) for k, v in value.get("olp_keys", {}).items()},
            witness_keys={str(k): dict(v) for k, v in value.get("witness_keys", {}).items()},
        )


@dataclass(frozen=True)
class AdapterResult:
    source_format: str
    integrity: dict[str, Any]
    provenance: dict[str, Any]
    binding: dict[str, Any]
    action: dict[str, Any]
    outcome: dict[str, Any]
    embedded_manifest: dict[str, Any] | None
    chain_hash: str
    capture_status: str
    capture_loss: bool


def _agent_required_shape(receipt: Mapping[str, Any]) -> None:
    top_allowed = {
        "@context", "id", "type", "version", "issuer", "issuanceDate",
        "credentialSubject", "proof",
    }
    if set(receipt) != top_allowed:
        raise ValueError("agent_receipts_top_level_schema_invalid")
    if receipt.get("version") != "0.5.0":
        raise ValueError("agent_receipts_version_not_v0_5_0")
    context = receipt.get("@context")
    if not isinstance(context, list) or context[:2] != [
        "https://www.w3.org/ns/credentials/v2",
        "https://agentreceipts.ai/context/v2",
    ]:
        raise ValueError("agent_receipts_context_mismatch")
    if receipt.get("type") != ["VerifiableCredential", "AgentReceipt"]:
        raise ValueError("agent_receipts_type_mismatch")
    if not isinstance(receipt.get("id"), str) or not AGENT_RECEIPT_ID.fullmatch(receipt["id"]):
        raise ValueError("agent_receipts_id_invalid")
    if not isinstance(receipt.get("issuanceDate"), str):
        raise ValueError("agent_receipts_issuance_date_invalid")
    subject = receipt.get("credentialSubject")
    if not isinstance(subject, dict):
        raise ValueError("agent_receipts_subject_missing")
    for key in ("principal", "action", "outcome", "chain"):
        if not isinstance(subject.get(key), dict):
            raise ValueError(f"agent_receipts_{key}_missing")
    chain = subject["chain"]
    for key in ("chain_id", "sequence", "previous_receipt_hash"):
        if key not in chain:
            raise ValueError(f"agent_receipts_chain_{key}_missing")
    if not isinstance(chain["chain_id"], str) or not chain["chain_id"]:
        raise ValueError("agent_receipts_chain_id_invalid")
    if (
        not isinstance(chain["sequence"], int)
        or isinstance(chain["sequence"], bool)
        or not 1 <= chain["sequence"] <= MAX_SAFE_INTEGER
    ):
        raise ValueError("agent_receipts_chain_sequence_invalid")
    if chain["previous_receipt_hash"] is not None and not isinstance(chain["previous_receipt_hash"], str):
        raise ValueError("agent_receipts_previous_hash_invalid")
    if chain["sequence"] == 1 and chain["previous_receipt_hash"] is not None:
        raise ValueError("agent_receipts_genesis_previous_hash_invalid")
    if chain["sequence"] > 1 and (
        not isinstance(chain["previous_receipt_hash"], str)
        or not SHA256_TAGGED.fullmatch(chain["previous_receipt_hash"])
    ):
        raise ValueError("agent_receipts_previous_hash_invalid")
    if set(chain) - {"sequence", "previous_receipt_hash", "chain_id", "terminal", "status"}:
        raise ValueError("agent_receipts_chain_unknown_field")
    if "terminal" in chain and chain["terminal"] is not True:
        raise ValueError("agent_receipts_terminal_invalid")
    if "status" in chain and (chain["status"] not in {"complete", "interrupted"} or chain.get("terminal") is not True):
        raise ValueError("agent_receipts_chain_status_invalid")
    issuer = receipt.get("issuer")
    if not isinstance(issuer, dict) or not isinstance(issuer.get("id"), str):
        raise ValueError("agent_receipts_issuer_invalid")
    if set(issuer) - {"id", "type", "name", "operator", "model", "session_id", "runtime"}:
        raise ValueError("agent_receipts_issuer_unknown_field")
    if "session_id" in issuer and not isinstance(issuer["session_id"], str):
        raise ValueError("agent_receipts_session_id_invalid")
    if "runtime" in issuer and not isinstance(issuer["runtime"], dict):
        raise ValueError("agent_receipts_runtime_invalid")
    principal, action, outcome = subject["principal"], subject["action"], subject["outcome"]
    if not isinstance(principal.get("id"), str) or set(principal) - {"id", "type"}:
        raise ValueError("agent_receipts_principal_invalid")
    if not isinstance(action.get("id"), str) or not AGENT_ACTION_ID.fullmatch(action["id"]):
        raise ValueError("agent_receipts_action_id_invalid")
    for key in ("type", "risk_level", "timestamp"):
        if not isinstance(action.get(key), str):
            raise ValueError(f"agent_receipts_action_{key}_invalid")
    if action["risk_level"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("agent_receipts_action_risk_level_invalid")
    action_allowed = {
        "id", "type", "risk_level", "target", "parameters_hash", "parameters_disclosure",
        "peer_credential", "emitter_metadata", "timestamp", "trusted_timestamp", "idempotency_key",
    }
    if set(action) - action_allowed:
        raise ValueError("agent_receipts_action_unknown_field")
    if outcome.get("status") not in {"success", "failure", "pending"}:
        raise ValueError("agent_receipts_outcome_status_invalid")
    outcome_allowed = {
        "status", "error", "reversible", "reversal_method", "reversal_window_seconds",
        "reversal_of", "state_change", "response_hash", "response_disclosure",
    }
    if set(outcome) - outcome_allowed:
        raise ValueError("agent_receipts_outcome_unknown_field")
    proof = receipt.get("proof")
    if not isinstance(proof, dict) or set(proof) != {
        "type", "created", "verificationMethod", "proofPurpose", "proofValue",
    }:
        raise ValueError("agent_receipts_proof_schema_invalid")
    if proof["type"] != "Ed25519Signature2020" or proof["proofPurpose"] != "assertionMethod":
        raise ValueError("agent_receipts_proof_profile_invalid")
    if not isinstance(proof["verificationMethod"], str) or not isinstance(proof["created"], str):
        raise ValueError("agent_receipts_proof_metadata_invalid")
    if not isinstance(proof["proofValue"], str) or not MULTIBASE_SIGNATURE.fullmatch(proof["proofValue"]):
        raise ValueError("agent_receipts_proof_value_invalid")


def _verify_agent_receipt(
    receipt: dict[str, Any], trust: TrustStore,
) -> AdapterResult:
    try:
        _agent_required_shape(receipt)
    except ValueError as exc:
        return AdapterResult(
            "agent_receipts_v0.5", _dimension("rejected", str(exc)),
            _dimension("undecidable", "provenance_not_evaluated"), {}, {}, {}, None,
            "", "unknown", False,
        )
    proof = receipt.get("proof") if isinstance(receipt.get("proof"), dict) else {}
    verification_method = str(proof.get("verificationMethod", ""))
    key_record = trust.agent_receipts_keys.get(verification_method)
    body = dict(receipt)
    body.pop("proof", None)
    try:
        body_bytes = jcs_bytes(body)
    except (TypeError, ValueError):
        return AdapterResult(
            "agent_receipts_v0.5", _dimension("rejected", "agent_receipts_jcs_invalid"),
            _dimension("undecidable", "provenance_not_evaluated"), {}, {}, {}, None,
            "", "unknown", False,
        )
    chain_hash = "sha256:" + sha256_bytes(body_bytes)
    subject = receipt["credentialSubject"]
    chain = subject["chain"]
    issuer = receipt.get("issuer") if isinstance(receipt.get("issuer"), dict) else {}
    binding = {
        "run_id": chain.get("chain_id"),
        "session_id": issuer.get("session_id"),
        "parent_hash": chain.get("previous_receipt_hash") or "GENESIS",
        "generation_index": chain.get("sequence"),
        "challenge_nonce": None,
    }
    if proof.get("type") != "Ed25519Signature2020":
        integrity = _dimension("rejected", "agent_receipts_proof_type_invalid")
    elif not key_record:
        integrity = _dimension("undecidable", "agent_receipts_public_key_unresolved")
    else:
        try:
            public = load_pem_public_key(key_record["public_key_pem"].encode("ascii"))
            if not isinstance(public, Ed25519PublicKey):
                raise TypeError("not Ed25519")
            proof_value = str(proof.get("proofValue", ""))
            if not proof_value.startswith("u"):
                raise ValueError("proofValue is not multibase base64url")
            encoded = proof_value[1:]
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            public.verify(base64.urlsafe_b64decode(encoded), body_bytes)
            integrity = _dimension("verified", evidence=(chain_hash,))
        except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error):
            integrity = _dimension("rejected", "agent_receipts_signature_invalid")
    capture_mode = (key_record or {}).get("capture_mode", "unknown")
    issuer_expected = (key_record or {}).get("issuer_id")
    if key_record and issuer_expected and issuer.get("id") != issuer_expected:
        provenance = _dimension("rejected", "agent_receipts_issuer_key_mismatch")
    elif capture_mode in {"agent_daemon", "receiver", "tool_witness"}:
        provenance = _dimension("verified", f"trusted_{capture_mode}_key")
    elif key_record:
        provenance = _dimension("undecidable", "agent_receipts_direct_or_operator_controlled_key")
    else:
        provenance = _dimension("undecidable", "agent_receipts_provenance_unresolved")
    return AdapterResult(
        "agent_receipts_v0.5", integrity, provenance, binding,
        dict(subject["action"]), dict(subject["outcome"]), None, chain_hash,
        "terminal" if bool(chain.get("terminal")) else "issuer_asserted", False,
    )


def _verify_olp_receipt(receipt: dict[str, Any], trust: TrustStore) -> AdapterResult:
    signature = receipt.get("signature") if isinstance(receipt.get("signature"), dict) else {}
    public_hex = str(signature.get("public_key", ""))
    valid = verify_receipt(receipt)
    integrity = (
        _dimension("verified", evidence=(str(receipt.get("payload_hash", "")),))
        if valid else _dimension("rejected", "olp_signature_or_payload_hash_invalid")
    )
    key_record = trust.olp_keys.get(public_hex)
    attestation = str(receipt.get("attestation", "self"))
    trusted_mode = (key_record or {}).get("capture_mode")
    if key_record and trusted_mode == attestation and attestation in {"daemon", "receiver", "tool_witness"}:
        provenance = _dimension("verified", f"trusted_{attestation}_key")
    elif key_record and trusted_mode and trusted_mode != attestation:
        provenance = _dimension("rejected", "olp_attestation_key_role_mismatch")
    elif attestation == "self":
        provenance = _dimension("undecidable", "olp_self_attested_capture")
    else:
        provenance = _dimension("undecidable", "olp_capture_key_untrusted")
    binding = {
        key: receipt.get(key)
        for key in ("run_id", "session_id", "parent_hash", "generation_index", "challenge_nonce")
    }
    action = receipt.get("action") if isinstance(receipt.get("action"), dict) else {}
    outcome = receipt.get("outcome") if isinstance(receipt.get("outcome"), dict) else {}
    manifest = receipt.get("evidence_manifest")
    return AdapterResult(
        "olp_canon", integrity, provenance, binding, dict(action), dict(outcome),
        dict(manifest) if isinstance(manifest, dict) else None,
        "sha256:" + str(receipt.get("payload_hash", "")),
        str(receipt.get("capture_status", "unknown")), bool(receipt.get("capture_loss", False)),
    )


def detect_source_format(receipt: Mapping[str, Any]) -> str:
    if receipt.get("type") == ["VerifiableCredential", "AgentReceipt"]:
        return "agent_receipts_v0.5"
    if "payload_hash" in receipt and "signature" in receipt:
        return "olp_canon"
    return "unknown"


def create_witness(
    body: Mapping[str, Any], witness_id: str, witness_type: str,
    key: Ed25519PrivateKey, *, timestamp: str | None = None,
) -> dict[str, Any]:
    witness_body = {
        "schema": WITNESS_SCHEMA,
        "witness_id": witness_id,
        "witness_type": witness_type,
        "timestamp": timestamp or _utc_now(),
        **dict(body),
    }
    return sign_receipt(witness_body, key)


def create_uptake(
    prior_verdict_hash: str, action: str, witness_id: str,
    key: Ed25519PrivateKey, *, timestamp: str | None = None,
) -> dict[str, Any]:
    if action not in {"allow", "block", "quarantine", "retry", "human_review"}:
        raise ValueError("unsupported uptake action")
    return sign_receipt({
        "schema": UPTAKE_SCHEMA,
        "witness_id": witness_id,
        "prior_verdict_hash": prior_verdict_hash,
        "action": action,
        "timestamp": timestamp or _utc_now(),
    }, key)


def _verify_signed_statement(
    statement: Mapping[str, Any], trust: TrustStore, *, expected_schema: str,
) -> tuple[bool, str]:
    if statement.get("schema") != expected_schema:
        return False, "statement_schema_invalid"
    witness_id = str(statement.get("witness_id", ""))
    key_record = trust.witness_keys.get(witness_id)
    if not key_record:
        return False, "witness_key_untrusted"
    signature = statement.get("signature") if isinstance(statement.get("signature"), dict) else {}
    if signature.get("public_key") != key_record.get("public_key"):
        return False, "witness_key_mismatch"
    return (True, "") if verify_receipt(statement) else (False, "witness_signature_invalid")


class EvidenceGateway:
    def __init__(self, signing_key: Ed25519PrivateKey, trust_store: TrustStore | None = None) -> None:
        self._key = signing_key
        self.trust = trust_store or TrustStore()

    def evaluate(
        self,
        source_receipt: bytes,
        *,
        session: GatewaySession,
        policy: GatewayPolicy | None = None,
        evidence_artifacts: Mapping[str, bytes] | None = None,
        evidence_manifest: Mapping[str, Any] | None = None,
        binding: Mapping[str, Any] | None = None,
        witnesses: Sequence[Mapping[str, Any]] = (),
        uptake: Mapping[str, Any] | None = None,
        parent_verdict_hash: str = "GENESIS",
        issued_at: str | None = None,
    ) -> dict[str, Any]:
        policy = policy or GatewayPolicy()
        artifacts = dict(evidence_artifacts or {})
        source_hash = sha256_bytes(source_receipt)
        try:
            parsed = _loads_strict(source_receipt)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            parsed = {}
            adapter = AdapterResult(
                "unknown", _dimension("rejected", "source_json_invalid"),
                _dimension("undecidable", "provenance_not_evaluated"), {}, {}, {}, None,
                "", "unknown", False,
            )
        else:
            source_format = detect_source_format(parsed)
            if source_format == "agent_receipts_v0.5":
                adapter = _verify_agent_receipt(parsed, self.trust)
            elif source_format == "olp_canon":
                adapter = _verify_olp_receipt(parsed, self.trust)
            else:
                adapter = AdapterResult(
                    "unknown", _dimension("rejected", "unsupported_receipt_format"),
                    _dimension("undecidable", "provenance_not_evaluated"), {}, {}, {}, None,
                    "", "unknown", False,
                )

        supporting_error: str | None = None
        if evidence_manifest is not None:
            if isinstance(evidence_manifest, Mapping):
                manifest = dict(evidence_manifest)
            else:
                manifest = None
                supporting_error = "evidence_manifest_not_an_object"
        else:
            manifest = adapter.embedded_manifest
        supporting_error = supporting_error or _manifest_error(manifest)
        requested_binding, binding_error = _binding_input(binding)
        try:
            manifest_hash = sha256_json(manifest) if manifest is not None else None
        except (TypeError, ValueError):
            manifest_hash = None
            supporting_error = "evidence_manifest_not_valid_ijson"
        outcome_hash = sha256_json(adapter.outcome) if adapter.outcome else None

        valid_witnesses: list[dict[str, Any]] = []
        witness_errors: list[str] = []
        for witness in witnesses:
            valid, error = _verify_signed_statement(witness, self.trust, expected_schema=WITNESS_SCHEMA)
            if not valid:
                witness_errors.append(error)
                continue
            if witness.get("source_receipt_sha256") != source_hash:
                witness_errors.append("witness_source_hash_mismatch")
                continue
            valid_witnesses.append(dict(witness))

        effective_binding = dict(adapter.binding)
        source_binding_keys = (
            ("run_id", "session_id", "parent_hash", "generation_index", "challenge_nonce")
            if adapter.source_format == "olp_canon"
            else ("run_id", "session_id", "parent_hash", "generation_index")
        )
        binding_is_source_signed = adapter.source_format in {"olp_canon", "agent_receipts_v0.5"} and all(
            effective_binding.get(key) is not None for key in source_binding_keys
        ) and not (
            adapter.source_format == "agent_receipts_v0.5"
            and session.expected_challenge_nonce is not None
        )
        binding_hash: str | None = None
        binding_witnessed = False
        if binding_error:
            freshness = _dimension("rejected", binding_error)
        elif requested_binding:
            conflicts = [
                key for key, value in effective_binding.items()
                if value is not None and key in requested_binding and requested_binding[key] != value
            ]
            if conflicts:
                freshness = _dimension("rejected", "binding_conflicts_with_signed_source")
            else:
                effective_binding.update(requested_binding)
                binding_hash = sha256_json(effective_binding)
                binding_witnessed = any(
                    witness.get("binding_hash") == binding_hash for witness in valid_witnesses
                )
                if adapter.source_format == "agent_receipts_v0.5" and not binding_witnessed:
                    freshness = _dimension("undecidable", "external_binding_not_independently_witnessed")
                else:
                    freshness = self._freshness(
                        source_hash, effective_binding, session,
                        binding_is_source_signed or binding_witnessed,
                    )
        else:
            binding_hash = sha256_json(effective_binding) if effective_binding else None
            binding_witnessed = any(
                binding_hash and witness.get("binding_hash") == binding_hash
                for witness in valid_witnesses
            )
            freshness = self._freshness(source_hash, effective_binding, session, binding_is_source_signed)

        if supporting_error:
            coverage = _dimension("rejected", supporting_error)
            evidence_sufficiency, evidence_reads = _dimension("rejected", supporting_error), 0
        else:
            coverage = self._coverage(adapter, manifest, policy, valid_witnesses, manifest_hash)
            evidence_sufficiency, evidence_reads = self._evidence(
                manifest, artifacts, policy, adapter, valid_witnesses, manifest_hash,
            )
        outcome_witness = self._outcome_witness(
            valid_witnesses, witness_errors, outcome_hash, manifest_hash, binding_hash,
        )
        causal_uptake = self._causal_uptake(uptake, parent_verdict_hash)

        dimensions = {
            "integrity": adapter.integrity,
            "provenance": adapter.provenance,
            "coverage": coverage,
            "freshness": freshness,
            "evidence_sufficiency": evidence_sufficiency,
            "independently_witnessed_outcome": outcome_witness,
            "causal_uptake": causal_uptake,
        }
        required = ["integrity"]
        if policy.require_provenance:
            required.append("provenance")
        if policy.require_coverage:
            required.append("coverage")
        if policy.require_freshness:
            required.append("freshness")
        if policy.require_evidence_sufficiency:
            required.append("evidence_sufficiency")
        consequential = str(adapter.action.get("risk_level", "")) in policy.consequential_risk_levels
        if policy.require_outcome_witness and consequential:
            required.append("independently_witnessed_outcome")
        if policy.require_causal_uptake:
            required.append("causal_uptake")

        policy_denied = str(adapter.action.get("type", "")) in policy.denied_action_types
        if policy_denied:
            overall = "rejected"
            next_use = "block"
        elif any(dimensions[name]["status"] == "rejected" for name in required):
            overall = "rejected"
            next_use = "quarantine"
        elif all(dimensions[name]["status"] == "verified" for name in required):
            overall = "verified"
            next_use = "allow"
        else:
            overall = "undecidable"
            next_use = "human_review"

        proposed_update = None
        if overall == "verified":
            proposed_update = {
                "expected_parent_hash": adapter.chain_hash,
                "last_generation_index": int(effective_binding["generation_index"]),
                "seen_source_hashes": sorted(set((*session.seen_source_hashes, source_hash))),
            }
        body = {
            "kind": "evidence_gateway_verdict",
            "schema": GATEWAY_SCHEMA,
            "issued_at": issued_at or _utc_now(),
            "source_format": adapter.source_format,
            "source_receipt_sha256": source_hash,
            "source_receipt_preserved_unchanged": True,
            "parent_verdict_hash": parent_verdict_hash,
            "binding": effective_binding,
            "dimensions": dimensions,
            "required_dimensions": required,
            "overall_status": overall,
            "policy_denied": policy_denied,
            "next_use": next_use,
            "evidence_reads": evidence_reads,
            "proposed_session_update": proposed_update,
            "gateway_claim_boundary": (
                "The verdict evaluates the supplied receipt and evidence under the declared trust store and policy. "
                "It does not prove that an unwitnessed event occurred or that the verifier received every event."
            ),
        }
        return sign_receipt(body, self._key)

    @staticmethod
    def _freshness(
        source_hash: str, binding: Mapping[str, Any], session: GatewaySession,
        binding_authenticated: bool,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        missing: list[str] = []
        if source_hash in session.seen_source_hashes:
            reasons.append("source_receipt_replayed")
        if binding.get("run_id") is None:
            missing.append("run_id_missing")
        elif binding.get("run_id") != session.expected_run_id:
            reasons.append("run_id_mismatch")
        if binding.get("session_id") is None:
            missing.append("session_id_missing")
        elif binding.get("session_id") != session.expected_session_id:
            reasons.append("session_id_mismatch")
        if binding.get("parent_hash") is None:
            missing.append("parent_hash_missing")
        elif binding.get("parent_hash") != session.expected_parent_hash:
            reasons.append("parent_hash_mismatch")
        generation = binding.get("generation_index")
        if generation is None:
            missing.append("generation_index_missing")
        elif not isinstance(generation, int) or isinstance(generation, bool):
            reasons.append("generation_index_invalid")
        elif generation <= session.last_generation_index:
            reasons.append("generation_index_not_advancing")
        if session.expected_challenge_nonce is not None:
            if binding.get("challenge_nonce") is None:
                missing.append("challenge_nonce_missing")
            elif binding.get("challenge_nonce") != session.expected_challenge_nonce:
                reasons.append("challenge_nonce_mismatch")
        if reasons:
            return _dimension("rejected", *reasons)
        if missing:
            return _dimension("undecidable", *missing)
        if not binding_authenticated:
            return _dimension("undecidable", "freshness_binding_not_authenticated")
        return _dimension("verified", evidence=(sha256_json(dict(binding)),))

    @staticmethod
    def _coverage(
        adapter: AdapterResult, manifest: Mapping[str, Any] | None, policy: GatewayPolicy,
        witnesses: Sequence[Mapping[str, Any]], manifest_hash: str | None,
    ) -> dict[str, Any]:
        if adapter.capture_loss:
            return _dimension("undecidable", "capture_loss_declared")
        if manifest is None:
            return _dimension("undecidable", "coverage_manifest_missing")
        observed = set(map(str, manifest.get("observed_event_ids", ())))
        missing = sorted(set(policy.required_event_ids) - observed)
        if missing:
            return _dimension("undecidable", "required_events_missing", evidence=missing)
        if manifest.get("terminal") is not True:
            return _dimension("undecidable", "terminal_coverage_unproven")
        witness_bound = any(manifest_hash and item.get("manifest_hash") == manifest_hash for item in witnesses)
        if adapter.capture_status == "provisional" and not witness_bound:
            return _dimension("undecidable", "provisional_capture_cannot_prove_completeness")
        if adapter.source_format == "agent_receipts_v0.5" and not witness_bound:
            return _dimension("undecidable", "external_coverage_manifest_unwitnessed")
        return _dimension("verified", evidence=(manifest_hash or "",))

    @staticmethod
    def _evidence(
        manifest: Mapping[str, Any] | None, artifacts: Mapping[str, bytes],
        policy: GatewayPolicy, adapter: AdapterResult,
        witnesses: Sequence[Mapping[str, Any]], manifest_hash: str | None,
    ) -> tuple[dict[str, Any], int]:
        if manifest is None:
            return _dimension("undecidable", "evidence_manifest_missing"), 0
        artifact_items = [
            item for item in manifest.get("artifacts", ())
            if isinstance(item, dict) and item.get("id")
        ]
        artifact_ids = [str(item["id"]) for item in artifact_items]
        if len(artifact_ids) != len(set(artifact_ids)):
            return _dimension("rejected", "duplicate_evidence_artifact_id"), 0
        declared = {
            str(item["id"]): str(item.get("sha256", "")).removeprefix("sha256:")
            for item in artifact_items
        }
        claims = [item for item in manifest.get("claims", ()) if isinstance(item, dict)]
        required = set(policy.required_evidence_ids)
        for claim in claims:
            if claim.get("material", True):
                required.update(map(str, claim.get("evidence_ids", ())))
        if not claims:
            return _dimension("undecidable", "material_claims_missing"), 0
        missing = sorted(item for item in required if item not in declared or item not in artifacts)
        if missing:
            return _dimension("undecidable", "required_evidence_missing", evidence=missing), 0
        mismatched = sorted(
            item for item in required if sha256_bytes(artifacts[item]) != declared[item]
        )
        if mismatched:
            return _dimension("rejected", "evidence_hash_mismatch", evidence=mismatched), len(required)
        witness_bound = any(manifest_hash and item.get("manifest_hash") == manifest_hash for item in witnesses)
        embedded = adapter.embedded_manifest is not None
        if not embedded and not witness_bound:
            return _dimension("undecidable", "evidence_manifest_not_bound_to_source_or_witness"), len(required)
        return _dimension("verified", evidence=tuple(declared[item] for item in sorted(required))), len(required)

    @staticmethod
    def _outcome_witness(
        witnesses: Sequence[Mapping[str, Any]], errors: Sequence[str], outcome_hash: str | None,
        manifest_hash: str | None, binding_hash: str | None,
    ) -> dict[str, Any]:
        eligible = [
            item for item in witnesses
            if item.get("witness_type") in {"tool", "user_wallet", "outcome_service", "receiver"}
        ]
        if not eligible:
            return _dimension(
                "undecidable", "independent_outcome_witness_missing", *errors,
            )
        matching = [
            item for item in eligible
            if item.get("outcome_hash") == outcome_hash
            and (manifest_hash is None or item.get("manifest_hash") == manifest_hash)
            and (binding_hash is None or item.get("binding_hash") == binding_hash)
        ]
        if not matching:
            return _dimension("rejected", "outcome_witness_binding_mismatch")
        return _dimension("verified", evidence=tuple(str(item.get("payload_hash")) for item in matching))

    def _causal_uptake(
        self, uptake: Mapping[str, Any] | None, expected_prior_verdict_hash: str,
    ) -> dict[str, Any]:
        if uptake is None:
            return _dimension("undecidable", "causal_uptake_receipt_missing")
        valid, error = _verify_signed_statement(uptake, self.trust, expected_schema=UPTAKE_SCHEMA)
        if not valid:
            return _dimension("rejected", error)
        if uptake.get("prior_verdict_hash") != expected_prior_verdict_hash:
            return _dimension("rejected", "causal_uptake_prior_verdict_mismatch")
        if uptake.get("action") not in {"allow", "block", "quarantine", "retry", "human_review"}:
            return _dimension("rejected", "causal_uptake_action_invalid")
        return _dimension("verified", evidence=(str(uptake.get("payload_hash", "")),))


def advance_gateway_session(session: GatewaySession, verdict: Mapping[str, Any]) -> GatewaySession:
    if verdict.get("overall_status") != "verified":
        return session
    update = verdict.get("proposed_session_update")
    if not isinstance(update, dict):
        raise ValueError("verified verdict is missing proposed_session_update")
    return GatewaySession(
        expected_run_id=session.expected_run_id,
        expected_session_id=session.expected_session_id,
        expected_parent_hash=str(update["expected_parent_hash"]),
        last_generation_index=int(update["last_generation_index"]),
        expected_challenge_nonce=None,
        seen_source_hashes=tuple(map(str, update["seen_source_hashes"])),
    )


def verify_gateway_verdict(verdict: Mapping[str, Any]) -> bool:
    return verdict.get("schema") == GATEWAY_SCHEMA and verdict.get("overall_status") in {
        "verified", "rejected", "undecidable",
    } and set(verdict.get("dimensions", {})) == set(DIMENSIONS) and verify_receipt(verdict)
