#!/usr/bin/env python3
"""Run the v0.2.0 release gate and regenerate its machine-readable evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from openline_otel.benchmark import write_benchmark  # noqa: E402


def run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command, cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )
    output = completed.stdout + completed.stderr
    print(output, end="")
    if completed.returncode:
        raise SystemExit(f"release command failed ({completed.returncode}): {' '.join(command)}")
    return output


def environment() -> dict[str, str]:
    env = os.environ.copy()
    current = [item for item in env.get("PYTHONPATH", "").split(os.pathsep) if item]
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), *current])
    return env


def manifest() -> dict[str, object]:
    excluded_parts = {".git", ".pytest_cache", "__pycache__", "build", "openline_otel.egg-info"}
    excluded_names = {"MANIFEST.json"}
    files: list[dict[str, object]] = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or any(part in excluded_parts for part in relative.parts):
            continue
        if path.name in excluded_names or path.suffix in {".pyc", ".zip"}:
            continue
        raw = path.read_bytes()
        files.append({
            "path": relative.as_posix(),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return {
        "schema": "openline.evidence-gateway.manifest.v1",
        "release": "0.2.0",
        "hash_algorithm": "sha256",
        "excluded": sorted(excluded_names | excluded_parts | {"*.pyc", "*.zip"}),
        "file_count": len(files),
        "files": files,
    }


def main() -> int:
    env = environment()
    private_key_marker = b"BEGIN " + b"PRIVATE KEY"
    leaked = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and private_key_marker in path.read_bytes()
    ]
    if leaked:
        raise SystemExit(f"private key material found in release files: {leaked}")
    pytest_output = run([sys.executable, "-m", "pytest", "-q"], env=env)
    match = re.search(r"(\d+) passed", pytest_output)
    if not match:
        raise SystemExit("could not determine pytest pass count")
    tests_passed = int(match.group(1))

    run([sys.executable, "scripts/generate_conformance.py"], env=env)
    if shutil.which("node") is None:
        raise SystemExit("Node.js is required for independent receipt verification")
    node_output = run(["node", "verify-node.mjs", "artifacts/conformance-receipt.json"], env=env)

    benchmark = write_benchmark(ROOT)
    if not benchmark["passed"] or len(benchmark["rows"]) != 40:
        raise SystemExit("evidence gateway benchmark gate failed")

    with tempfile.TemporaryDirectory(prefix="openline-otel-release-") as temporary:
        target = Path(temporary) / "site"
        run([
            sys.executable, "-m", "pip", "install", "--quiet", "--no-deps",
            "--no-cache-dir", "--no-build-isolation", "--target", str(target), str(ROOT),
        ], env=env)
        inherited = [
            item for item in os.environ.get("PYTHONPATH", "").split(os.pathsep)
            if item and Path(item).resolve() not in {ROOT.resolve(), SRC.resolve()}
        ]
        clean_env = os.environ.copy()
        clean_env["PYTHONPATH"] = os.pathsep.join([str(target), *inherited])
        clean_output = run([
            sys.executable, "-c",
            "import openline_otel; from openline_otel.cli import build_parser; "
            "assert openline_otel.__version__ == '0.2.0'; build_parser(); print('isolated import verified')",
        ], env=clean_env)

    generated_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    gate = {
        "schema": "openline.evidence-gateway.release-gate.v1",
        "release": "0.2.0",
        "generated_at": generated_at,
        "passed": True,
        "checks": {
            "no_private_key_material": {"passed": True},
            "python_tests": {"passed": True, "count": tests_passed},
            "independent_node_verifier": {"passed": "verified" in node_output},
            "pinned_agent_receipts_v050_vector": {"passed": True, "covered_by": "tests/test_gateway.py"},
            "isolated_package_import": {"passed": "isolated import verified" in clean_output},
            "hostile_benchmark": {
                "passed": benchmark["passed"],
                "rows": len(benchmark["rows"]),
                "passed_gates": benchmark["passed_gate_count"],
                "total_gates": benchmark["gate_count"],
                "gateway_false_acceptances": sum(
                    int(row["false_acceptance_gateway"]) for row in benchmark["rows"]
                ),
            },
        },
        "claim_boundary": benchmark["claim_boundary"],
    }
    (ROOT / "EVIDENCE_GATEWAY_RELEASE_GATE.json").write_text(
        json.dumps(gate, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    report = {
        "schema": "openline.evidence-gateway.run-report.v1",
        "release": "0.2.0",
        "generated_at": generated_at,
        "python": sys.version.split()[0],
        "tests_passed": tests_passed,
        "node_verifier": node_output.strip(),
        "benchmark_passed": benchmark["passed"],
        "benchmark_rows": len(benchmark["rows"]),
        "timing_note": "Benchmark wall_ns and cpu_ns are environment-sensitive measurements, not reproducibility claims.",
    }
    (ROOT / "RUN_REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (ROOT / "MANIFEST.json").write_text(
        json.dumps(manifest(), indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print(f"release gate passed: {tests_passed} tests, {len(benchmark['rows'])} benchmark rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
