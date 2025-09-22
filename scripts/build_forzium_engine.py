"""Stubbed build helper for tests."""

from __future__ import annotations


def build_forzium_engine() -> None:
    """Pretend to build the (optional) forzium engine extension."""

    # The actual build step is not required for these tests. The stub allows
    # the pytest configuration to proceed without failing due to the optional
    # dependency being unavailable in the CI environment.
    return None