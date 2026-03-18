"""
test_features.py - Tests for feature extraction.
"""

import pandas as pd
import pytest

from threatlens.parser import load_events
from threatlens.features import (
    extract_features,
    _has_suspicious_cmdline,
    _detect_parent_child_chains,
    SUSPICIOUS_PROCESSES,
    SUSPICIOUS_PORTS,
)
from threatlens.model import ML_FEATURE_COLS


class TestExtractFeatures:
    def test_returns_dataframe_same_index(self, sample_df):
        from threatlens.parser import _normalize
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        assert isinstance(features, pd.DataFrame)
        assert list(features.index) == list(df.index)

    def test_all_expected_columns_present(self, sample_df):
        from threatlens.parser import _normalize
        df = _normalize(sample_df.copy())
        features = extract_features(df)
        expected = [
            "encoded_command", "privilege_escalation_flag", "persistence_flag",
            "failed_logins", "external_connection", "is_suspicious_port",
            "is_suspicious_process", "is_suspicious_parent_child",
            "has_suspicious_cmdline", "is_discovery_process", "failed_logins_norm",
        ]
        for col in expected:
            assert col in features.columns, f"Missing feature column: {col}"

    def test_benign_event_all_false(self, benign_event_row):
        from threatlens.parser import _normalize
        df = _normalize(pd.DataFrame([benign_event_row]))
        features = extract_features(df)
        row = features.iloc[0]
        assert row["encoded_command"] is False or row["encoded_command"] == 0
        assert row["is_suspicious_process"] is False or row["is_suspicious_process"] == 0
        assert row["is_suspicious_port"] is False or row["is_suspicious_port"] == 0

    def test_malicious_event_flags_set(self, malicious_event_row):
        from threatlens.parser import _normalize
        df = _normalize(pd.DataFrame([malicious_event_row]))
        features = extract_features(df)
        row = features.iloc[0]
        assert row["encoded_command"] == True
        assert row["external_connection"] == True
        assert row["is_suspicious_port"] == True   # port 4444
        assert row["is_suspicious_process"] == True  # powershell.exe

    def test_failed_logins_norm_capped_at_1(self, benign_event_row):
        from threatlens.parser import _normalize
        benign_event_row["failed_logins"] = 100
        df = _normalize(pd.DataFrame([benign_event_row]))
        features = extract_features(df)
        assert features.iloc[0]["failed_logins_norm"] == 1.0

    def test_failed_logins_norm_zero(self, benign_event_row):
        from threatlens.parser import _normalize
        df = _normalize(pd.DataFrame([benign_event_row]))
        features = extract_features(df)
        assert features.iloc[0]["failed_logins_norm"] == 0.0

    def test_suspicious_parent_child_detected(self, suspicious_event_row):
        # winword.exe -> powershell.exe is suspicious
        from threatlens.parser import _normalize
        df = _normalize(pd.DataFrame([suspicious_event_row]))
        features = extract_features(df)
        assert features.iloc[0]["is_suspicious_parent_child"] == True


class TestHasSuspiciousCmdline:
    def test_encoded_flag_detected(self):
        assert _has_suspicious_cmdline("powershell.exe -Enc JABjAGwA") is True

    def test_iex_detected(self):
        assert _has_suspicious_cmdline("powershell.exe -c IEX(payload)") is True

    def test_download_string_detected(self):
        assert _has_suspicious_cmdline("DownloadString('http://evil.com')") is True

    def test_bypass_detected(self):
        assert _has_suspicious_cmdline("powershell.exe -ExecutionPolicy Bypass") is True

    def test_base64_decode_detected(self):
        assert _has_suspicious_cmdline("FromBase64String('abc')") is True

    def test_benign_cmdline_not_flagged(self):
        assert _has_suspicious_cmdline("chrome.exe --profile-directory=Default") is False

    def test_empty_cmdline(self):
        assert _has_suspicious_cmdline("") is False

    def test_mimikatz_detected(self):
        assert _has_suspicious_cmdline("mimikatz.exe privilege::debug") is True


class TestSuspiciousSets:
    def test_known_suspicious_process(self):
        assert "powershell.exe" in SUSPICIOUS_PROCESSES

    def test_known_safe_process_not_in_set(self):
        assert "chrome.exe" not in SUSPICIOUS_PROCESSES
        assert "WINWORD.EXE".lower() not in SUSPICIOUS_PROCESSES

    def test_known_suspicious_port(self):
        assert 4444 in SUSPICIOUS_PORTS
        assert 31337 in SUSPICIOUS_PORTS

    def test_standard_port_not_suspicious(self):
        assert 443 not in SUSPICIOUS_PORTS
        assert 80 not in SUSPICIOUS_PORTS
