from openline_otel.benchmark import ATTACKS, PROFILES, run_benchmark


def test_neutral_benchmark_passes_without_combined_score() -> None:
    result = run_benchmark()
    assert result["passed"] is True
    assert result["passed_gate_count"] == result["gate_count"] == 5
    assert result["combined_score"] is None
    assert len(result["rows"]) == len(PROFILES) * (len(ATTACKS) + 1) == 40
    assert not any(row["false_acceptance_gateway"] for row in result["rows"])
    assert result["by_profile"]["olp_receiver_tool_witness_capture"]["clean_gateway_status"] == "verified"


def test_integrity_only_accepts_signed_unsupported_claims() -> None:
    result = run_benchmark()
    selected = [
        row for row in result["rows"]
        if row["case"] in {
            "validly_signed_fabricated_outcome",
            "valid_signature_insufficient_evidence",
        }
    ]
    assert len(selected) == len(PROFILES) * 2
    assert all(row["native_integrity_accepts"] for row in selected)
    assert all(row["gateway_status"] != "verified" for row in selected)
