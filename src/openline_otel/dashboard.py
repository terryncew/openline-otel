"""Local-only browser verifier and wallet dashboard."""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .gateway import EvidenceGateway, GatewayPolicy, GatewaySession
from .wallet import ReceiptWallet


DASHBOARD_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OLP Evidence Gateway</title><style>
:root{color-scheme:dark;background:#0b0e13;color:#e7edf5;font:15px system-ui}body{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:26px;margin-bottom:4px}.sub{color:#91a0b5;margin-top:0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
section{background:#121824;border:1px solid #263247;border-radius:12px;padding:16px}textarea,input{box-sizing:border-box;width:100%;background:#080b10;color:#dce8f8;border:1px solid #34445e;border-radius:7px;padding:10px}textarea{min-height:270px;font:12px ui-monospace,monospace}
button{margin-top:10px;background:#68d391;color:#071109;border:0;border-radius:7px;padding:10px 14px;font-weight:700;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px ui-monospace,monospace}.verified{color:#68d391}.rejected{color:#ff7b7b}.undecidable{color:#ffd166}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;border-bottom:1px solid #283348;padding:8px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style></head><body><h1>OLP Evidence Gateway</h1><p class="sub">Signature validity is one line of the verdict, never the whole verdict.</p>
<div class="grid"><section><h2>Verify a receipt</h2><textarea id="receipt" placeholder="Paste exact OLP Canon or Agent Receipts v0.5 JSON"></textarea>
<input id="run" value="browser-run" aria-label="run id"><input id="session" value="browser-session" aria-label="session id"><input id="nonce" value="browser-challenge" aria-label="challenge nonce">
<textarea id="support" style="min-height:130px" placeholder='Optional supporting JSON: {"policy":{},"evidence_manifest":{},"evidence_artifacts_base64":{},"binding":{},"witnesses":[]}'></textarea>
<button onclick="verifyReceipt()">Evaluate</button></section><section><h2>Verdict</h2><pre id="result">No receipt evaluated.</pre></section></div>
<section style="margin-top:18px"><h2>Local wallet</h2><table><thead><tr><th>Status</th><th>Issued</th><th>Source</th></tr></thead><tbody id="wallet"></tbody></table></section>
<script>
async function verifyReceipt(){const out=document.getElementById('result');try{const receiptText=document.getElementById('receipt').value;JSON.parse(receiptText);const supportText=document.getElementById('support').value.trim();const support=supportText?JSON.parse(supportText):{};const response=await fetch('/api/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...support,receipt_text:receiptText,session:{expected_run_id:document.getElementById('run').value,expected_session_id:document.getElementById('session').value,expected_parent_hash:'GENESIS',last_generation_index:0,expected_challenge_nonce:document.getElementById('nonce').value}})});const data=await response.json();out.className=data.overall_status||'rejected';out.textContent=JSON.stringify(data,null,2);loadWallet()}catch(error){out.className='rejected';out.textContent=String(error)}}
async function loadWallet(){const rows=await (await fetch('/api/verdicts')).json();document.getElementById('wallet').innerHTML=rows.map(r=>`<tr><td class="${r.overall_status}">${r.overall_status}</td><td>${r.issued_at}</td><td>${r.source_sha256.slice(0,16)}…</td></tr>`).join('')}loadWallet();
</script></body></html>"""


def _session(value: dict[str, Any]) -> GatewaySession:
    return GatewaySession(
        expected_run_id=str(value["expected_run_id"]),
        expected_session_id=str(value["expected_session_id"]),
        expected_parent_hash=str(value.get("expected_parent_hash", "GENESIS")),
        last_generation_index=int(value.get("last_generation_index", 0)),
        expected_challenge_nonce=value.get("expected_challenge_nonce"),
        seen_source_hashes=tuple(map(str, value.get("seen_source_hashes", ()))),
    )


def make_handler(gateway: EvidenceGateway, wallet_path: Path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenLineEvidenceGateway/0.2"

        def _json(self, status: int, value: Any) -> None:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                encoded = DASHBOARD_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(encoded)))
                self.send_header("content-security-policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(encoded)
                return
            if path == "/api/verdicts":
                with ReceiptWallet(wallet_path) as wallet:
                    self._json(200, wallet.list_verdicts())
                return
            if path == "/health":
                self._json(200, {"status": "ok", "binding": "127.0.0.1"})
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/api/verify":
                self._json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("content-length", "0"))
            if length < 1 or length > 5_000_000:
                self._json(413, {"error": "body_size_invalid"})
                return
            try:
                request = json.loads(self.rfile.read(length))
                if "receipt_text" in request:
                    source = str(request["receipt_text"]).encode("utf-8")
                else:
                    source = json.dumps(
                        request["receipt"], separators=(",", ":"), ensure_ascii=False,
                    ).encode("utf-8")
                artifacts = {
                    str(key): base64.b64decode(str(value), validate=True)
                    for key, value in request.get("evidence_artifacts_base64", {}).items()
                }
                session = _session(request["session"])
                with ReceiptWallet(wallet_path) as wallet:
                    verdict = gateway.evaluate(
                        source,
                        session=session,
                        policy=GatewayPolicy.from_dict(request.get("policy")),
                        evidence_artifacts=artifacts,
                        evidence_manifest=request.get("evidence_manifest"),
                        binding=request.get("binding"),
                        witnesses=request.get("witnesses", ()),
                        uptake=request.get("uptake"),
                        parent_verdict_hash=wallet.latest_verdict_hash(),
                    )
                    wallet.append(source, verdict)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(200, verdict)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def serve_dashboard(
    gateway: EvidenceGateway, wallet_path: Path, *, host: str = "127.0.0.1", port: int = 8765,
) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("dashboard is local-only; bind to a loopback address")
    server = ThreadingHTTPServer((host, port), make_handler(gateway, wallet_path))
    try:
        server.serve_forever()
    finally:
        server.server_close()
