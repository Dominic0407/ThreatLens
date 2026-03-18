"""
test_scorer.py - Tests for the transparent scoring engine.
"""

import pandas as pd
import pytest

from threatlens.scorer import (
    score_events,
    _score_row,
    _rule_fires,
    SCORING_RULES,
    MAX_RAW_SCORE,
)
from threatlens.parser import _normalize
from threatlens.features import extract_features


def _get_features(event_dict: dict) -> pd.DataFrame:
    df = _normalize(pd.DataFrame([event_dict]))
    return extract_features(df)


class TestScoringRules:
    def test_max_raw_score_positive(self):
        assert MAX_RAW_SCORE > 0

    def test_rule_fires_encoded_command(self):
        row = pd.Series({"encoded_command": True, "failed_logins": 0})
        assert _rule_fires("encoded_command", row) is True

    def test_rule_fires_not_encoded(self):
        row = pd.Series({"encoded_command": False, "failed_logins": 0})
        assert _rule_fires("encoded_command", row) is False

    def test_rule_fires_failed_logins_high(self):
        row = pd.Series({"failed_logins": 10})
        assert _rule_fires("failed_logins_high", row) is True

    def test_rule_fires_failed_logins_not_high(self):
        row = pd.Series({"failed_logins": 4})
        assert _rule_fires("failed_logins_high", row) is False

    def test_rule_fires_failed_logins_medium(self):
        row = pd.Series({"failed_logins": 7})
        assert _rule_fires("failed_logins_medium", row) is True

    def test_rule_fires_failed_logins_not_medium_low(self):
        row = pd.Series({"failed_logins": 2})
        assert _rule_fires("failed_logins_medium", row) is False

    def test_rule_fires_failed_logins_not_medium_high(self):
        # 10+ should NOT fire the medium rule (high rule handles it)
        row = pd.Series({"failed_logins": 12})
        assert _rule_fires("failed_logins_medium", row) is False


class TestScoreEvents:
    def test_benign_event_low_score(self, benign_event_row):
        features = _get_features(benign_event_row)
        scores = score_events(features)
        assert scores.iloc[0]["risk_score"] < 26  # should be "benign"

    def test_malicious_event_high_score(self, malicious_event_row):
        features = _get_features(malicious_event_row)
        scores = score_events(features)
        assert scores.iloc[0]["risk_score"] >= 51  # at least suspicious

    def test_score_in_range(self, sample_df):
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        scores = score_events(features)
        assert (scores["risk_score"] >= 0).all()
        assert (scores["risk_score"] <= 100).all()

    def test_risk_level_column_present(self, sample_df):
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        scores = score_events(features)
        assert "risk_level" in scores.columns

    def test_risk_level_valid_values(self, sample_df):
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        scores = score_events(features)
        valid = {"benign", "low", "suspicious", "malicious"}
        assert set(scores["risk_level"].unique()).issubset(valid)

    def test_explanation_populated(self, malicious_event_row):
        features = _get_features(malicious_event_row)
        scores = score_events(features)
        explanation = scores.iloc[0]["explanation"]
        assert len(explanation) > 10  # should be non-trivial

    def test_benign_no_triggered_rules(self, benign_event_row):
        features = _get_features(benign_event_row)
        scores = score_events(features)
        triggered = scores.iloc[0]["triggered_rules"]
        assert isinstance(triggered, list)
        assert len(triggered) == 0

    def test_malicious_has_triggered_rules(self, malicious_event_row):
        features = _get_features(malicious_event_row)
        scores = score_events(features)
        triggered = scores.iloc[0]["triggered_rules"]
        assert len(triggered) > 0

    def test_returns_correct_row_count(self, sample_df):
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        scores = score_events(features)
        assert len(scores) == len(df)


class TestRiskLevelThresholds:
    """Verify the score→risk_level thresholds from utils."""

    def test_score_0_is_benign(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(0) == "benign"

    def test_score_25_is_benign(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(25) == "benign"

    def test_score_26_is_low(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(26) == "low"

    def test_score_51_is_suspicious(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(51) == "suspicious"

    def test_score_76_is_malicious(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(76) == "malicious"

    def test_score_100_is_malicious(self):
        from threatlens.utils import risk_level_from_score
        assert risk_level_from_score(100) == "malicious"
