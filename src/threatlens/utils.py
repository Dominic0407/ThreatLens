"""
utils.py - Shared utilities for ThreatLens.

Provides logging setup, path helpers, and small convenience functions
used across the pipeline.
"""

import logging
import sys
from pathlib import Path


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    return logger


def ensure_dir(path: Path) -> Path:
    """Create directory if it does not exist and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def truncate(text: str, max_len: int = 80) -> str:
    """Truncate a string for display, appending ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def severity_color(severity: str) -> str:
    """Return a Rich markup color string for a given severity label."""
    mapping = {
        "benign": "green",
        "low": "cyan",
        "suspicious": "yellow",
        "malicious": "red",
    }
    return mapping.get(severity.lower(), "white")


def risk_level_from_score(score: float) -> str:
    """
    Convert a numeric risk score (0–100) to a human-readable risk level.

    Thresholds are documented in docs/scoring.md.
    """
    if score >= 76:
        return "malicious"
    if score >= 51:
        return "suspicious"
    if score >= 26:
        return "low"
    return "benign"
