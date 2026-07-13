import base64
import io
import json
import sys
from pathlib import Path

import pytest

from openline_otel.benchmark import _fixture, _key
from openline_otel.cli import build_parser
from openline_otel.dashboard import serve_dashboard
from openline_otel.gateway import EvidenceGateway
from openline_otel.mcp_proxy import TOOLS, handle_message, run_forward_proxy
from openline_otel.wallet import ReceiptWallet


def test_cli_exposes_all_four_surfaces(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    for command in ("verify", "benchmark", "wallet", "witness", "serve", "mcp", "mcp-proxy"):
        with pytest.raises(SystemExit) as stopped:
            parser.parse_args([command, "--help"])
        assert stopped.value.code == 0
        assert command in capsys.readouterr().out


def test_dashboard_refuses_non_loopback(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="local-only"):
        serve_dashboard(
            EvidenceGateway(_key("gateway")), tmp_path / "wallet.sqlite3",
            host="0.0.0.0", port=0,
        )


def test_mcp_lists_tools_and_preserves_raw_base64_source(tmp_path: Path) -> None:
    fixture = _fixture("olp_receiver_tool_witness_capture", None)
    wallet_path = tmp_path / "wallet.sqlite3"
    gateway = EvidenceGateway(_key("gateway"), fixture.trust)
    listed = handle_message(gateway, wallet_path, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    })
    assert {item["name"] for item in listed["result"]["tools"]} == {item["name"] for item in TOOLS}
    arguments = {
        "receipt_base64": base64.b64encode(fixture.source).decode(),
        "session": fixture.session.__dict__,
        "policy": fixture.policy.__dict__,
        "evidence_manifest": fixture.manifest,
        "evidence_artifacts_base64": {
            key: base64.b64encode(value).decode() for key, value in fixture.artifacts.items()
        },
        "binding": fixture.binding,
        "witnesses": fixture.witnesses,
    }
    response = handle_message(gateway, wallet_path, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "evidence.verify", "arguments": arguments},
    })
    assert "error" not in response
    value = json.loads(response["result"]["content"][0]["text"])
    assert value["overall_status"] == "verified"
    with ReceiptWallet(wallet_path) as wallet:
        assert wallet.get_source(value["source_receipt_sha256"]) == fixture.source


def test_forward_proxy_gates_and_receipts_exact_tool_response(tmp_path: Path) -> None:
    upstream = (
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " if r.get('id') is not None:\n"
        "  out={'jsonrpc':'2.0','id':r['id'],'result':"
        "({'content':[{'type':'text','text':'ok'}],'isError':False} "
        "if r.get('method')=='tools/call' else {})}\n"
        "  print(json.dumps(out,separators=(',',':')),flush=True)\n"
    )
    request = {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "safe-tool", "arguments": {"value": 1}},
    }
    input_stream = io.StringIO(json.dumps(request, separators=(",", ":")) + "\n")
    output_stream = io.StringIO()
    wallet_path = tmp_path / "proxy-wallet.sqlite3"
    key = _key("mcp-receiver")
    assert run_forward_proxy(
        EvidenceGateway(key), wallet_path, key,
        [sys.executable, "-u", "-c", upstream],
        run_id="proxy-run", session_id="proxy-session", challenge_nonce="proxy-nonce",
        input_stream=input_stream, output_stream=output_stream,
    ) == 0
    forwarded = json.loads(output_stream.getvalue())
    assert forwarded["id"] == 7
    assert forwarded["result"]["content"][0]["text"] == "ok"
    with ReceiptWallet(wallet_path) as wallet:
        rows = wallet.list_verdicts()
        assert len(rows) == 1
        assert rows[0]["overall_status"] == "verified"
        verdict = wallet.get_verdict(rows[0]["payload_hash"])
        source = json.loads(wallet.get_source(verdict["source_receipt_sha256"]))
        assert source["kind"] == "mcp_receiver_action_receipt"
        assert {item["id"] for item in source["evidence_manifest"]["artifacts"]} == {
            "mcp-request", "mcp-response",
        }
