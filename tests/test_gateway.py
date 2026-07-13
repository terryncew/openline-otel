import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_otel.benchmark import FIXED_TIME, _fixture, _key
from openline_otel.gateway import (
    EvidenceGateway,
    GatewayPolicy,
    GatewaySession,
    TrustStore,
    advance_gateway_session,
    create_uptake,
    sha256_bytes,
    verify_gateway_verdict,
)
from openline_otel.wallet import ReceiptWallet


ROOT = Path(__file__).resolve().parents[1]


def test_pinned_agent_receipts_v050_vector_verifies_integrity() -> None:
    vector = json.loads((ROOT / "artifacts/agent-receipts-v050-runtime-receipt.json").read_text())
    source = json.dumps(vector["receipt"], separators=(",", ":"), ensure_ascii=False).encode()
    trust = TrustStore(agent_receipts_keys={
        vector["verification_method"]: {
            "public_key_pem": vector["public_key_pem"],
            "capture_mode": "agent_daemon",
            "issuer_id": vector["issuer_id"],
        }
    })
    verdict = EvidenceGateway(_key("gateway"), trust).evaluate(
        source,
        session=GatewaySession(
            expected_run_id="chain_v050_test/agent/a3e49db54342a92d4",
            expected_session_id="a9a50488-d6f2-4dee-ac2e-ed3db47b9d00",
        ),
        policy=GatewayPolicy(),
        issued_at=FIXED_TIME,
    )
    assert verdict["source_format"] == "agent_receipts_v0.5"
    assert verdict["dimensions"]["integrity"]["status"] == "verified"
    assert verdict["dimensions"]["integrity"]["evidence"] == [vector["expected_body_hash"]]
    assert verdict["dimensions"]["freshness"]["status"] == "verified"
    assert verdict["overall_status"] == "undecidable"
    assert verify_gateway_verdict(verdict)


def test_pinned_vector_signature_mutation_is_rejected() -> None:
    vector = json.loads((ROOT / "artifacts/agent-receipts-v050-runtime-receipt.json").read_text())
    vector["receipt"]["credentialSubject"]["outcome"]["status"] = "failure"
    source = json.dumps(vector["receipt"], separators=(",", ":")).encode()
    trust = TrustStore(agent_receipts_keys={
        vector["verification_method"]: {
            "public_key_pem": vector["public_key_pem"],
            "capture_mode": "agent_daemon",
            "issuer_id": vector["issuer_id"],
        }
    })
    verdict = EvidenceGateway(_key("gateway"), trust).evaluate(
        source,
        session=GatewaySession(
            expected_run_id="chain_v050_test/agent/a3e49db54342a92d4",
            expected_session_id="a9a50488-d6f2-4dee-ac2e-ed3db47b9d00",
        ),
        issued_at=FIXED_TIME,
    )
    assert verdict["dimensions"]["integrity"]["status"] == "rejected"
    assert verdict["overall_status"] == "rejected"


def test_existing_self_attested_otel_receipt_is_preserved_as_undecidable_evidence() -> None:
    source = (ROOT / "artifacts/conformance-receipt.json").read_bytes()
    verdict = EvidenceGateway(_key("gateway")).evaluate(
        source,
        session=GatewaySession(expected_run_id="run", expected_session_id="session"),
        issued_at=FIXED_TIME,
    )
    assert verdict["source_format"] == "olp_canon"
    assert verdict["dimensions"]["integrity"]["status"] == "verified"
    assert verdict["dimensions"]["provenance"]["status"] == "undecidable"
    assert verdict["dimensions"]["freshness"]["status"] == "undecidable"
    assert verdict["overall_status"] == "undecidable"


def test_receiver_tool_witness_clean_control_is_verified() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source,
        session=fixture.session,
        policy=fixture.policy,
        evidence_artifacts=fixture.artifacts,
        evidence_manifest=fixture.manifest,
        binding=fixture.binding,
        witnesses=fixture.witnesses,
        issued_at=FIXED_TIME,
    )
    assert verdict["overall_status"] == "verified"
    assert all(
        verdict["dimensions"][name]["status"] == "verified"
        for name in verdict["required_dimensions"]
    )


def test_valid_signature_with_insufficient_evidence_abstains() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", "valid_signature_insufficient_evidence")
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source,
        session=fixture.session,
        policy=fixture.policy,
        evidence_artifacts=fixture.artifacts,
        evidence_manifest=fixture.manifest,
        binding=fixture.binding,
        witnesses=fixture.witnesses,
        issued_at=FIXED_TIME,
    )
    assert verdict["dimensions"]["integrity"]["status"] == "verified"
    assert verdict["dimensions"]["evidence_sufficiency"]["status"] == "undecidable"
    assert verdict["overall_status"] == "undecidable"


def test_replay_and_cross_run_splice_are_rejected() -> None:
    for attack, reason in (
        ("receipt_replayed", "source_receipt_replayed"),
        ("cross_run_receipt_spliced", "run_id_mismatch"),
    ):
        fixture = _fixture("olp_receiver_tool_witness_capture", attack)
        verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
            fixture.source,
            session=fixture.session,
            policy=fixture.policy,
            evidence_artifacts=fixture.artifacts,
            evidence_manifest=fixture.manifest,
            binding=fixture.binding,
            witnesses=fixture.witnesses,
            issued_at=FIXED_TIME,
        )
        assert verdict["dimensions"]["freshness"]["status"] == "rejected"
        assert reason in verdict["dimensions"]["freshness"]["reason_codes"]
        assert verdict["overall_status"] == "rejected"


def test_session_transition_is_pure_and_only_advances_verified() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source,
        session=fixture.session,
        policy=fixture.policy,
        evidence_artifacts=fixture.artifacts,
        evidence_manifest=fixture.manifest,
        binding=fixture.binding,
        witnesses=fixture.witnesses,
        issued_at=FIXED_TIME,
    )
    updated = advance_gateway_session(fixture.session, verdict)
    assert fixture.session.expected_parent_hash == "GENESIS"
    assert updated.expected_parent_hash != "GENESIS"
    assert updated.last_generation_index == 1
    rejected = dict(verdict, overall_status="rejected")
    assert advance_gateway_session(updated, rejected) == updated


def test_causal_uptake_must_name_the_prior_verdict() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    uptake_key = Ed25519PrivateKey.from_private_bytes(b"u" * 32)
    fixture.trust.witness_keys["uptake-controller"] = {
        "public_key": uptake_key.public_key().public_bytes_raw().hex()
    }
    policy = GatewayPolicy(
        required_event_ids=fixture.policy.required_event_ids,
        required_evidence_ids=fixture.policy.required_evidence_ids,
        require_causal_uptake=True,
    )
    gateway = EvidenceGateway(_key("gateway"), fixture.trust)
    wrong = create_uptake("wrong", "allow", "uptake-controller", uptake_key, timestamp=FIXED_TIME)
    rejected = gateway.evaluate(
        fixture.source, session=fixture.session, policy=policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=fixture.witnesses, uptake=wrong,
        parent_verdict_hash="prior-verdict", issued_at=FIXED_TIME,
    )
    assert rejected["dimensions"]["causal_uptake"]["status"] == "rejected"
    correct = create_uptake(
        "prior-verdict", "allow", "uptake-controller", uptake_key, timestamp=FIXED_TIME,
    )
    verified = gateway.evaluate(
        fixture.source, session=fixture.session, policy=policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=fixture.witnesses, uptake=correct,
        parent_verdict_hash="prior-verdict", issued_at=FIXED_TIME,
    )
    assert verified["dimensions"]["causal_uptake"]["status"] == "verified"


def test_wallet_preserves_source_bytes_exactly(tmp_path: Path) -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source, session=fixture.session, policy=fixture.policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=fixture.witnesses, issued_at=FIXED_TIME,
    )
    with ReceiptWallet(tmp_path / "wallet.sqlite3") as wallet:
        wallet.append(fixture.source, verdict)
        assert wallet.get_source(sha256_bytes(fixture.source)) == fixture.source


def test_malformed_supporting_manifest_rejects_without_crashing() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    malformed = dict(fixture.manifest, artifacts="not-a-list")
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source, session=fixture.session, policy=fixture.policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=malformed,
        binding=fixture.binding, witnesses=fixture.witnesses, issued_at=FIXED_TIME,
    )
    assert verdict["overall_status"] == "rejected"
    assert verdict["dimensions"]["evidence_sufficiency"]["reason_codes"] == [
        "evidence_manifest_artifacts_invalid"
    ]


def test_untrusted_invalid_extra_witness_does_not_poison_valid_witness() -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    verdict = EvidenceGateway(_key("gateway"), fixture.trust).evaluate(
        fixture.source, session=fixture.session, policy=fixture.policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=[*fixture.witnesses, {"schema": "bogus"}],
        issued_at=FIXED_TIME,
    )
    assert verdict["dimensions"]["independently_witnessed_outcome"]["status"] == "verified"
    assert verdict["overall_status"] == "verified"


def test_wallet_rejects_a_local_chain_fork(tmp_path: Path) -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    gateway = EvidenceGateway(_key("gateway"), fixture.trust)
    first = gateway.evaluate(
        fixture.source, session=fixture.session, policy=fixture.policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=fixture.witnesses, issued_at=FIXED_TIME,
    )
    fork = gateway.evaluate(
        fixture.source, session=fixture.session, policy=fixture.policy,
        evidence_artifacts=fixture.artifacts, evidence_manifest=fixture.manifest,
        binding=fixture.binding, witnesses=fixture.witnesses,
        parent_verdict_hash="GENESIS", issued_at="2026-07-12T12:00:01Z",
    )
    with ReceiptWallet(tmp_path / "wallet.sqlite3") as wallet:
        wallet.append(fixture.source, first)
        with pytest.raises(ValueError, match="local wallet chain"):
            wallet.append(fixture.source, fork)
