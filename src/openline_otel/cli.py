"""Command-line surface for the Evidence Gateway."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .benchmark import write_benchmark
from .dashboard import serve_dashboard
from .gateway import (
    EvidenceGateway, GatewayPolicy, GatewaySession, TrustStore,
    create_witness, sha256_bytes, sha256_json,
)
from .wallet import ReceiptWallet, load_or_create_private_key


def _json_file(path: str | None, default: Any = None) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else default


def _session(value: dict[str, Any]) -> GatewaySession:
    return GatewaySession(
        expected_run_id=str(value["expected_run_id"]),
        expected_session_id=str(value["expected_session_id"]),
        expected_parent_hash=str(value.get("expected_parent_hash", "GENESIS")),
        last_generation_index=int(value.get("last_generation_index", 0)),
        expected_challenge_nonce=value.get("expected_challenge_nonce"),
        seen_source_hashes=tuple(map(str, value.get("seen_source_hashes", ()))),
    )


def _artifacts(directory: str | None, manifest: dict[str, Any] | None) -> dict[str, bytes]:
    if not directory or not manifest:
        return {}
    root = Path(directory).resolve()
    output: dict[str, bytes] = {}
    for item in manifest.get("artifacts", ()):
        if not isinstance(item, dict) or not item.get("id"):
            continue
        relative = str(item.get("path", item["id"]))
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise ValueError(f"artifact escapes evidence directory: {relative}")
        if candidate.exists() and candidate.is_file():
            output[str(item["id"])] = candidate.read_bytes()
    return output


def _gateway(args: argparse.Namespace) -> EvidenceGateway:
    key = load_or_create_private_key(Path(args.key))
    trust = TrustStore.from_dict(_json_file(getattr(args, "trust", None), {}))
    return EvidenceGateway(key, trust)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openline-evidence")
    parser.add_argument("--key", default="~/.openline/evidence-gateway.key")
    parser.add_argument("--trust", help="JSON trust store")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="evaluate one OLP or Agent Receipts v0.5 receipt")
    verify.add_argument("receipt")
    verify.add_argument("--session", required=True)
    verify.add_argument("--policy")
    verify.add_argument("--manifest")
    verify.add_argument("--evidence-dir")
    verify.add_argument("--binding")
    verify.add_argument("--witness", action="append", default=[])
    verify.add_argument("--uptake")
    verify.add_argument("--wallet", default="~/.openline/evidence-wallet.sqlite3")

    benchmark = sub.add_parser("benchmark", help="run the pinned four-profile hostile benchmark")
    benchmark.add_argument("--root", default=".")

    wallet = sub.add_parser("wallet", help="inspect the local receipt wallet")
    wallet.add_argument("--wallet", default="~/.openline/evidence-wallet.sqlite3")
    wallet.add_argument("--limit", type=int, default=100)
    wallet.add_argument("--show")
    wallet.add_argument("--source")

    witness = sub.add_parser("witness", help="co-sign an independently observed outcome")
    witness.add_argument("receipt")
    witness.add_argument("--outcome", required=True)
    witness.add_argument("--witness-id", required=True)
    witness.add_argument(
        "--witness-type", required=True,
        choices=("tool", "user_wallet", "outcome_service", "receiver"),
    )
    witness.add_argument("--manifest")
    witness.add_argument("--binding")
    witness.add_argument("--output")

    serve = sub.add_parser("serve", help="run the local browser verifier")
    serve.add_argument("--wallet", default="~/.openline/evidence-wallet.sqlite3")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    mcp = sub.add_parser("mcp", help="run the local stdio MCP proxy")
    mcp.add_argument("--wallet", default="~/.openline/evidence-wallet.sqlite3")

    forward = sub.add_parser(
        "mcp-proxy", help="gate responses from an upstream stdio MCP server",
    )
    forward.add_argument("--wallet", default="~/.openline/evidence-wallet.sqlite3")
    forward.add_argument("--run-id", required=True)
    forward.add_argument("--session-id", required=True)
    forward.add_argument("--challenge", required=True)
    forward.add_argument("upstream", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "benchmark":
        result = write_benchmark(Path(args.root).resolve())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "wallet":
        with ReceiptWallet(Path(args.wallet)) as wallet:
            if args.show:
                value = wallet.get_verdict(args.show)
            elif args.source:
                raw = wallet.get_source(args.source)
                value = json.loads(raw) if raw else None
            else:
                value = wallet.list_verdicts(args.limit)
        print(json.dumps(value, indent=2, sort_keys=True))
        return 0 if value is not None else 1
    if args.command == "witness":
        source = Path(args.receipt).read_bytes()
        manifest = _json_file(args.manifest)
        binding = _json_file(args.binding)
        statement = create_witness(
            {
                "source_receipt_sha256": sha256_bytes(source),
                "outcome_hash": sha256_json(_json_file(args.outcome)),
                "manifest_hash": sha256_json(manifest) if manifest is not None else None,
                "binding_hash": sha256_json(binding) if binding is not None else None,
            },
            args.witness_id,
            args.witness_type,
            load_or_create_private_key(Path(args.key)),
        )
        encoded = json.dumps(statement, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
        return 0
    gateway = _gateway(args)
    if args.command == "serve":
        serve_dashboard(gateway, Path(args.wallet), host=args.host, port=args.port)
        return 0
    if args.command == "mcp":
        from .mcp_proxy import run_stdio
        return run_stdio(gateway, Path(args.wallet))
    if args.command == "mcp-proxy":
        from .mcp_proxy import run_forward_proxy
        upstream = list(args.upstream)
        if upstream[:1] == ["--"]:
            upstream = upstream[1:]
        return run_forward_proxy(
            gateway,
            Path(args.wallet),
            load_or_create_private_key(Path(args.key)),
            upstream,
            run_id=args.run_id,
            session_id=args.session_id,
            challenge_nonce=args.challenge,
        )
    if args.command == "verify":
        source = Path(args.receipt).read_bytes()
        manifest = _json_file(args.manifest)
        witnesses = [_json_file(path) for path in args.witness]
        wallet_path = Path(args.wallet)
        with ReceiptWallet(wallet_path) as wallet:
            verdict = gateway.evaluate(
                source,
                session=_session(_json_file(args.session)),
                policy=GatewayPolicy.from_dict(_json_file(args.policy, {})),
                evidence_artifacts=_artifacts(args.evidence_dir, manifest),
                evidence_manifest=manifest,
                binding=_json_file(args.binding),
                witnesses=witnesses,
                uptake=_json_file(args.uptake),
                parent_verdict_hash=wallet.latest_verdict_hash(),
            )
            wallet.append(source, verdict)
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if verdict["overall_status"] == "verified" else 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
