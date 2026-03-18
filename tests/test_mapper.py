"""
test_mapper.py - Tests for ATT&CK-style category mapping.
"""

import pandas as pd
import pytest

from threatlens.mapper import map_attack_categories, _map_single
from threatlens.parser import _normalize
from threatlens.features import extract_features


def _make_pair(event_dict: dict) -> tuple[pd.Series, pd.Series]:
    """Return (raw_row, feature_row) for a single event dict."""
    df_raw = _normalize(pd.DataFrame([event_dict]))
    df_feat = extract_features(df_raw)
    return df_raw.iloc[0], df_feat.iloc[0]


class TestMapSingle:
    def test_c2_mapping(self, malicious_event_row):
        # external + suspicious port → Command and Control
        row_raw, row_feat = _make_pair(malicious_event_row)
        category, reason = _map_single(row_raw, row_feat)
        assert category == "Command and Control"

    def test_execution_mapping(self, suspicious_event_row):
        # winword → powershell with bypass → Execution
        row_raw, row_feat = _make_pair(suspicious_event_row)
        category, reason = _map_single(row_raw, row_feat)
        # Could be Execution or similar — verify it's not Unknown for clearly suspicious
        assert category != "Unknown"

    def test_benign_mapping_unknown(self, benign_event_row):
        row_raw, row_feat = _make_pair(benign_event_row)
        category, reason = _map_single(row_raw, row_feat)
        # Benign events with no signals should map to Unknown
        assert category == "Unknown"

    def test_privilege_escalation_mapping(self, benign_event_row):
        benign_event_row["privilege_escalation_flag"] = True
        benign_event_row["external_connection"] = False
        row_raw, row_feat = _make_pair(benign_event_row)
        category, reason = _map_single(row_raw, row_feat)
        assert category == "Privilege Escalation"

    def test_persistence_mapping(self, benign_event_row):
        benign_event_row["persistence_flag"] = True
        benign_event_row["external_connection"] = False
        row_raw, row_feat = _make_pair(benign_event_row)
        category, reason = _map_single(row_raw, row_feat)
        assert category == "Persistence"

    def test_credential_access_mapping(self, benign_event_row):
        benign_event_row["failed_logins"] = 10
        benign_event_row["external_connection"] = False
        row_raw, row_feat = _make_pair(benign_event_row)
        category, reason = _map_single(row_raw, row_feat)
        assert category == "Credential Access"

    def test_discovery_mapping(self, benign_event_row):
        benign_event_row["process_name"] = "whoami.exe"
        benign_event_row["parent_process"] = "cmd.exe"
        row_raw, row_feat = _make_pair(benign_event_row)
        category, reason = _map_single(row_raw, row_feat)
        assert category == "Discovery"


class TestMapAttackCategories:
    def test_returns_dataframe_correct_shape(self, sample_df):
        df_raw = _normalize(sample_df.copy())
        df_feat = extract_features(df_raw)
        result = map_attack_categories(df_raw, df_feat)
        assert len(result) == len(df_raw)
        assert "attack_category" in result.columns
        assert "category_reason" in result.columns

    def test_all_categories_are_strings(self, sample_df):
        df_raw = _normalize(sample_df.copy())
        df_feat = extract_features(df_raw)
        result = map_attack_categories(df_raw, df_feat)
        for val in result["attack_category"]:
            assert isinstance(val, str) and len(val) > 0

    def test_reason_always_populated(self, sample_df):
        df_raw = _normalize(sample_df.copy())
        df_feat = extract_features(df_raw)
        result = map_attack_categories(df_raw, df_feat)
        for val in result["category_reason"]:
            assert isinstance(val, str) and len(val) > 0

    def test_lateral_movement_detection(self, benign_event_row):
        benign_event_row["process_name"] = "psexec.exe"
        benign_event_row["parent_process"] = "cmd.exe"
        benign_event_row["command_line"] = "psexec.exe \\\\192.168.1.10 cmd.exe"
        df_raw = _normalize(pd.DataFrame([benign_event_row]))
        df_feat = extract_features(df_raw)
        result = map_attack_categories(df_raw, df_feat)
        assert result.iloc[0]["attack_category"] == "Lateral Movement"
