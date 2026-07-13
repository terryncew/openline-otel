"""RFC 8785/JCS encoding used by the Agent Receipts adapter."""

from __future__ import annotations

from typing import Any

import rfc8785


def canonical_bytes(value: Any) -> bytes:
    """Return complete RFC 8785 canonical bytes or raise on invalid I-JSON."""
    return rfc8785.dumps(value)
