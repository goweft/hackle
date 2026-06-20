"""Stable fingerprint for a proposed action (tool + params).

A short content hash that identifies an action — used to match an
approval to the exact action it authorizes, or to detect repeats.
"""
from __future__ import annotations

import hashlib
import json


def action_fingerprint(tool: str, params: dict) -> str:
    blob = json.dumps({"tool": tool, "params": params}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]
