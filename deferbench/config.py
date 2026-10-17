"""Configuration: paths and optional integrations, from env vars or explicit arguments."""
from __future__ import annotations
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def results_dir() -> Path:
    return Path(os.environ.get("DEFERBENCH_RESULTS_DIR", PROJECT_ROOT / "results"))


def scenarios_dir() -> Path:
    return Path(os.environ.get("DEFERBENCH_SCENARIOS_DIR", PROJECT_ROOT / "scenarios"))


def process_timeout() -> float:
    return float(os.environ.get("DEFERBENCH_TIMEOUT", "60"))


def integration_bin(name: str) -> str | None:
    """Explicit path for an optional external tool, e.g. DEFERBENCH_GENSEE_BIN."""
    return os.environ.get(f"DEFERBENCH_{name.upper()}_BIN") or None
