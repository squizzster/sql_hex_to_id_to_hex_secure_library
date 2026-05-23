#!/usr/bin/env python3
"""Compatibility test runner.

The canonical test command is:

    python -m pytest

This wrapper keeps the historical script entry point working while delegating
collection and reporting to pytest.
"""

from __future__ import annotations

import sys

import pytest


if __name__ == "__main__":
    pytest_args = sys.argv[1:] or ["tests"]
    raise SystemExit(pytest.main(pytest_args))
