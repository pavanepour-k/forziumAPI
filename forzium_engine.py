"""Stub module for optional Rust extension used in tests."""

from __future__ import annotations

from typing import Any, Dict


class ComputeRequestSchema:
    """Minimal stub replicating the validation API expected by tests."""

    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # The stub simply echoes the provided payload. Real validation would be
        # performed by the optional Rust extension which is not available in the
        # testing environment.
        return {
            "data": payload.get("data"),
            "operation": payload.get("operation"),
            "parameters": payload.get("parameters"),
        }