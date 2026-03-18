"""
scorer.py - Transparent weighted scoring engine for ThreatLens.

Each security signal contributes a fixed, documented point value to a
running total.  The raw total is then normalised to a 0–100 scale.

This design is intentionally transparent: every weight can be read,
understood, and tuned without touching any model file.  Full
documentation lives in docs/scoring.md.

Scoring weights (out of MAX_RAW_SCORE = 130):
    encoded_command              +30
    privilege_escalation_flag    +25
    persistence_flag             +20
    failed_logins >= 10          +20  (high-volume brute-force)
    failed_logins 5–9            +10  (moderate failed-login activity)
    external_connection          +10
    is_suspicious_port           +20
    is_suspicious_process        +10
    is_suspicious_parent_child   +15
    has_suspicious_cmdline       +15
    is_discovery_process         + 5
"""

from typing import TypedDict

import pandas as pd

from threatlens.utils import risk_level_from_score

# ---------------------------------------------------------------------------
# Weight configuration
# ---------------------------------------------------------------------------

# Each entry is (feature_key, points, description_for_explanation).
# The feature_key must match a column in the features DataFrame produced
# by features.extract_features(), or be a special computed key.

SCORING_RULES: list[tuple[str, int, str]] = [
    ("encoded_command",             30, "Encoded/obfuscated command detected (common in PS attacks)"),
    ("privilege_escalation_flag",   25, "Privilege escalation indicator present"),
    ("persistence_flag",            20, "Persistence mechanism detected (registry/scheduled task)"),
    ("failed_logins_high",          20, "High failed-login count (≥10) — possible brute-force"),
    ("failed_logins_medium",        10, "Moderate failed-login count (5–9)"),
    ("external_connection",         10, "Outbound connection to external IP"),
    ("is_suspicious_port",          20, "Destination port associated with C2 or bind shells"),
    ("is_suspicious_process",       10, "Process name is a known LOLBin or abuse target"),
    ("is_suspicious_parent_child",  15, "Suspicious parent→child process chain (e.g. Word→PowerShell)"),
    ("has_suspicious_cmdline",      15, "Command line contains high-risk pattern"),
    ("is_discovery_process",         5, "Recon/discovery tool executed"),
]

# Normalisation cap: treat 100 raw points as a full-risk event.
# This means each rule's weight directly represents its contribution
# to the final 0-100 score, and the score caps at 100.
# (Actual rule sum is higher, allowing multiple strong signals to compound
# while still normalising cleanly.)
MAX_RAW_SCORE: int = 100


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ScoredEvent(TypedDict):
    """Scoring output for a single event."""
    raw_score: int
    risk_score: float       # 0–100 normalised
    risk_level: str         # benign / low / suspicious / malicious
    triggered_rules: list[str]


def score_events(features: pd.DataFrame) -> pd.DataFrame:
    """
    Score every event in the feature DataFrame.

    Parameters
    ----------
    features : pd.DataFrame
        Output of features.extract_features().

    Returns
    -------
    pd.DataFrame
        Columns: raw_score, risk_score, risk_level, explanation
        Index matches the input.
    """
    results = []
    for _, row in features.iterrows():
        scored = _score_row(row)
        results.append(scored)

    scores_df = pd.DataFrame(results, index=features.index)
    return scores_df


def _score_row(row: pd.Series) -> dict:
    """Compute score and collect triggered rule explanations for one event."""
    raw = 0
    triggered: list[str] = []

    for rule_key, points, description in SCORING_RULES:
        if _rule_fires(rule_key, row):
            raw += points
            triggered.append(description)

    # Normalise to 0–100 and cap at 100.
    # Using MAX_RAW_SCORE=100 means each rule's point value directly represents
    # its percentage-point contribution to the final score.
    risk_score = round(min((raw / MAX_RAW_SCORE) * 100, 100.0), 1)
    risk_level = risk_level_from_score(risk_score)

    explanation = _build_explanation(triggered, risk_level)

    return {
        "raw_score": raw,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "triggered_rules": triggered,
    }


def _rule_fires(rule_key: str, row: pd.Series) -> bool:
    """
    Evaluate whether a named scoring rule fires for this event row.

    Most rules map directly to a feature column (True/False).
    A few compound rules require special logic.
    """
    if rule_key == "failed_logins_high":
        return int(row.get("failed_logins", 0)) >= 10

    if rule_key == "failed_logins_medium":
        fl = int(row.get("failed_logins", 0))
        return 5 <= fl < 10

    # Standard boolean feature column.
    value = row.get(rule_key)
    if value is None:
        return False
    return bool(value)


def _build_explanation(triggered: list[str], risk_level: str) -> str:
    """Build a human-readable explanation string from triggered rules."""
    if not triggered:
        return "No high-risk signals detected. Event appears benign."

    header = f"Risk level '{risk_level}' — {len(triggered)} signal(s) triggered:"
    bullets = "\n".join(f"  • {desc}" for desc in triggered)
    return f"{header}\n{bullets}"
