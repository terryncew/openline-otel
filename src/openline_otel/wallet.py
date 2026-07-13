"""Local receipt wallet. Source receipt bytes are retained unchanged."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .gateway import sha256_bytes, verify_gateway_verdict


def load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    path = path.expanduser().resolve()
    if path.exists():
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = os.urandom(32)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(base64.b64encode(raw).decode("ascii") + "\n", encoding="ascii")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return Ed25519PrivateKey.from_private_bytes(raw)


class ReceiptWallet:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS source_receipts (
                sha256 TEXT PRIMARY KEY,
                source_format TEXT NOT NULL,
                raw_bytes BLOB NOT NULL,
                stored_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verdicts (
                payload_hash TEXT PRIMARY KEY,
                source_sha256 TEXT NOT NULL REFERENCES source_receipts(sha256),
                overall_status TEXT NOT NULL,
                parent_verdict_hash TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                verdict_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS verdicts_source ON verdicts(source_sha256);
            """
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "ReceiptWallet":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def append(self, source_receipt: bytes, verdict: Mapping[str, Any]) -> None:
        source_hash = sha256_bytes(source_receipt)
        if not verify_gateway_verdict(verdict):
            raise ValueError("gateway verdict signature or schema is invalid")
        if verdict.get("source_receipt_sha256") != source_hash:
            raise ValueError("verdict does not bind the supplied source receipt")
        encoded = json.dumps(verdict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._db:
            expected_parent = self.latest_verdict_hash()
            if verdict.get("parent_verdict_hash") != expected_parent:
                raise ValueError("verdict does not extend the local wallet chain")
            existing = self._db.execute(
                "SELECT raw_bytes FROM source_receipts WHERE sha256 = ?", (source_hash,)
            ).fetchone()
            if existing is not None and bytes(existing["raw_bytes"]) != source_receipt:
                raise ValueError("source hash collision or wallet corruption")
            self._db.execute(
                "INSERT OR IGNORE INTO source_receipts VALUES (?, ?, ?, ?)",
                (
                    source_hash,
                    str(verdict.get("source_format", "unknown")),
                    source_receipt,
                    str(verdict.get("issued_at", "")),
                ),
            )
            self._db.execute(
                "INSERT INTO verdicts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(verdict["payload_hash"]), source_hash,
                    str(verdict["overall_status"]), str(verdict["parent_verdict_hash"]),
                    str(verdict["issued_at"]), encoded,
                ),
            )

    def list_verdicts(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        rows = self._db.execute(
            "SELECT payload_hash, source_sha256, overall_status, parent_verdict_hash, issued_at "
            "FROM verdicts ORDER BY rowid DESC LIMIT ?", (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_verdict(self, payload_hash: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT verdict_json FROM verdicts WHERE payload_hash = ?", (payload_hash,)
        ).fetchone()
        return json.loads(row["verdict_json"]) if row else None

    def get_source(self, source_sha256: str) -> bytes | None:
        row = self._db.execute(
            "SELECT raw_bytes FROM source_receipts WHERE sha256 = ?", (source_sha256,)
        ).fetchone()
        return bytes(row["raw_bytes"]) if row else None

    def latest_verdict_hash(self) -> str:
        row = self._db.execute("SELECT payload_hash FROM verdicts ORDER BY rowid DESC LIMIT 1").fetchone()
        return str(row["payload_hash"]) if row else "GENESIS"
