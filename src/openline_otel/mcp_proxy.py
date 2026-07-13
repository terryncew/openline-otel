"""Minimal local stdio MCP proxy for evidence verification."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .gateway import (
    EvidenceGateway, GatewayPolicy, GatewaySession,
    advance_gateway_session, create_witness, sha256_bytes, sha256_json,
)
from .processor import canonical_json, sign_receipt
from .wallet import ReceiptWallet


TOOLS = [
    {
        "name": "evidence.verify",
        "description": "Evaluate an OLP Canon or Agent Receipts v0.5 receipt and store the signed verdict locally.",
        "inputSchema": {
            "type": "object",
            "required": ["session"],
            "oneOf": [
                {"required": ["receipt_base64"]},
                {"required": ["receipt"]},
            ],
            "properties": {
                "receipt": {"type": "object"},
                "receipt_base64": {
                    "type": "string",
                    "description": "Preferred: exact source receipt bytes encoded as base64.",
                },
                "session": {"type": "object"},
                "policy": {"type": "object"},
                "evidence_manifest": {"type": "object"},
                "evidence_artifacts_base64": {"type": "object"},
                "binding": {"type": "object"},
                "witnesses": {"type": "array"},
                "uptake": {"type": "object"},
            },
        },
    },
    {
        "name": "evidence.wallet.list",
        "description": "List recent local Evidence Gateway verdicts.",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    },
    {
        "name": "evidence.wallet.get",
        "description": "Read one signed verdict by payload hash.",
        "inputSchema": {
            "type": "object", "required": ["payload_hash"],
            "properties": {"payload_hash": {"type": "string"}},
        },
    },
]


def _session(value: dict[str, Any]) -> GatewaySession:
    return GatewaySession(
        expected_run_id=str(value["expected_run_id"]),
        expected_session_id=str(value["expected_session_id"]),
        expected_parent_hash=str(value.get("expected_parent_hash", "GENESIS")),
        last_generation_index=int(value.get("last_generation_index", 0)),
        expected_challenge_nonce=value.get("expected_challenge_nonce"),
        seen_source_hashes=tuple(map(str, value.get("seen_source_hashes", ()))),
    )


def _tool_call(
    gateway: EvidenceGateway, wallet_path: Path, name: str, arguments: dict[str, Any],
) -> Any:
    if name == "evidence.wallet.list":
        with ReceiptWallet(wallet_path) as wallet:
            return wallet.list_verdicts(int(arguments.get("limit", 100)))
    if name == "evidence.wallet.get":
        with ReceiptWallet(wallet_path) as wallet:
            return wallet.get_verdict(str(arguments["payload_hash"]))
    if name != "evidence.verify":
        raise ValueError(f"unknown tool: {name}")
    if "receipt_base64" in arguments:
        source = base64.b64decode(str(arguments["receipt_base64"]), validate=True)
    elif "receipt" in arguments:
        source = json.dumps(
            arguments["receipt"], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    else:
        raise ValueError("receipt_base64 or receipt is required")
    artifacts = {
        str(key): base64.b64decode(str(value), validate=True)
        for key, value in arguments.get("evidence_artifacts_base64", {}).items()
    }
    with ReceiptWallet(wallet_path) as wallet:
        verdict = gateway.evaluate(
            source,
            session=_session(arguments["session"]),
            policy=GatewayPolicy.from_dict(arguments.get("policy")),
            evidence_artifacts=artifacts,
            evidence_manifest=arguments.get("evidence_manifest"),
            binding=arguments.get("binding"),
            witnesses=arguments.get("witnesses", ()),
            uptake=arguments.get("uptake"),
            parent_verdict_hash=wallet.latest_verdict_hash(),
        )
        wallet.append(source, verdict)
    return verdict


def handle_message(
    gateway: EvidenceGateway, wallet_path: Path, message: dict[str, Any],
) -> dict[str, Any] | None:
    identifier = message.get("id")
    method = message.get("method")
    if identifier is None:
        return None
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "openline-evidence-gateway", "version": "0.2.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params", {})
            value = _tool_call(gateway, wallet_path, str(params.get("name")), dict(params.get("arguments", {})))
            result = {"content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}], "isError": False}
        else:
            return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": identifier, "result": result}
    except Exception as exc:  # local proxy must return a protocol error, not crash the stream
        return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32000, "message": str(exc)}}


def run_stdio(
    gateway: EvidenceGateway, wallet_path: Path, *, input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
) -> int:
    for line in input_stream:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            response = handle_message(gateway, wallet_path, message)
        except json.JSONDecodeError as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        if response is not None:
            output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
            output_stream.flush()
    return 0


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def _record_forwarded_tool_result(
    gateway: EvidenceGateway,
    wallet_path: Path,
    receiver_key: Ed25519PrivateKey,
    *,
    request: dict[str, Any],
    request_raw: bytes,
    response_raw: bytes,
    response: dict[str, Any],
    session: GatewaySession,
    generation_index: int,
    challenge_nonce: str,
) -> tuple[GatewaySession, str]:
    timestamp = _now()
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    tool_name = str(params.get("name", "unknown"))
    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    failed = "error" in response or bool(result.get("isError"))
    outcome = {
        "status": "error" if failed else "success",
        "response_sha256": sha256_bytes(response_raw),
    }
    action = {
        "id": f"mcp:{request.get('id')}:{generation_index}",
        "type": f"mcp.tool.{tool_name}",
        "risk_level": "high",
        "timestamp": timestamp,
    }
    manifest = {
        "schema": "openline.evidence-manifest.v1",
        "claims": [{
            "id": "mcp-tool-outcome",
            "material": True,
            "evidence_ids": ["mcp-request", "mcp-response"],
        }],
        "artifacts": [
            {"id": "mcp-request", "sha256": sha256_bytes(request_raw)},
            {"id": "mcp-response", "sha256": sha256_bytes(response_raw)},
        ],
        "observed_event_ids": ["intent", "tool_call", "tool_result"],
        "terminal": True,
    }
    binding = {
        "run_id": session.expected_run_id,
        "session_id": session.expected_session_id,
        "parent_hash": session.expected_parent_hash,
        "generation_index": generation_index,
        "challenge_nonce": challenge_nonce,
    }
    source = sign_receipt({
        "kind": "mcp_receiver_action_receipt",
        "receipt_version": "0.2",
        "attestation": "receiver",
        "capture_status": "final",
        "capture_loss": False,
        **binding,
        "action": action,
        "outcome": outcome,
        "evidence_manifest": manifest,
        "timestamp": timestamp,
    }, receiver_key)
    source_raw = canonical_json(source)
    witness_id = "mcp-receiver"
    witness = create_witness({
        "source_receipt_sha256": sha256_bytes(source_raw),
        "binding_hash": sha256_json(binding),
        "manifest_hash": sha256_json(manifest),
        "outcome_hash": sha256_json(outcome),
    }, witness_id, "receiver", receiver_key, timestamp=timestamp)
    public_hex = _public_hex(receiver_key)
    gateway.trust.olp_keys[public_hex] = {"capture_mode": "receiver"}
    gateway.trust.witness_keys[witness_id] = {"public_key": public_hex}
    with ReceiptWallet(wallet_path) as wallet:
        verdict = gateway.evaluate(
            source_raw,
            session=GatewaySession(
                expected_run_id=session.expected_run_id,
                expected_session_id=session.expected_session_id,
                expected_parent_hash=session.expected_parent_hash,
                last_generation_index=session.last_generation_index,
                expected_challenge_nonce=(
                    challenge_nonce if session.last_generation_index == 0 else None
                ),
                seen_source_hashes=session.seen_source_hashes,
            ),
            policy=GatewayPolicy(
                required_event_ids=("intent", "tool_call", "tool_result"),
                required_evidence_ids=("mcp-request", "mcp-response"),
            ),
            evidence_artifacts={"mcp-request": request_raw, "mcp-response": response_raw},
            binding=binding,
            witnesses=[witness],
            parent_verdict_hash=wallet.latest_verdict_hash(),
            issued_at=timestamp,
        )
        wallet.append(source_raw, verdict)
    if verdict["overall_status"] != "verified":
        raise RuntimeError(f"MCP receiver evidence gate returned {verdict['overall_status']}")
    return advance_gateway_session(session, verdict), str(verdict["payload_hash"])


def run_forward_proxy(
    gateway: EvidenceGateway,
    wallet_path: Path,
    receiver_key: Ed25519PrivateKey,
    upstream_command: list[str],
    *,
    run_id: str,
    session_id: str,
    challenge_nonce: str,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
) -> int:
    """Forward stdio MCP one request at a time and receipt every tool result."""
    if not upstream_command:
        raise ValueError("an upstream MCP command is required")
    process = subprocess.Popen(
        upstream_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None and process.stdout is not None
    session = GatewaySession(
        expected_run_id=run_id,
        expected_session_id=session_id,
        expected_challenge_nonce=challenge_nonce,
    )
    generation = 0
    try:
        for raw in input_stream:
            request = json.loads(raw)
            process.stdin.write(raw if raw.endswith("\n") else raw + "\n")
            process.stdin.flush()
            if request.get("id") is None:
                continue
            while True:
                upstream_raw = process.stdout.readline()
                if not upstream_raw:
                    raise RuntimeError("upstream MCP server closed before responding")
                response = json.loads(upstream_raw)
                if response.get("id") != request.get("id"):
                    output_stream.write(upstream_raw)
                    output_stream.flush()
                    continue
                if request.get("method") == "tools/call":
                    generation += 1
                    session, _ = _record_forwarded_tool_result(
                        gateway, wallet_path, receiver_key,
                        request=request,
                        request_raw=(raw if raw.endswith("\n") else raw + "\n").encode("utf-8"),
                        response_raw=upstream_raw.encode("utf-8"),
                        response=response,
                        session=session,
                        generation_index=generation,
                        challenge_nonce=challenge_nonce,
                    )
                output_stream.write(upstream_raw)
                output_stream.flush()
                break
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    return 0
