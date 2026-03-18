"""
test_parser.py - Tests for event loading and normalization.
"""

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from threatlens.parser import load_events, _to_bool, SCHEMA


class TestToBool:
    def test_true_values(self):
        for val in [True, "True", "true", "1", "yes", "y"]:
            assert _to_bool(val) is True

    def test_false_values(self):
        for val in [False, "False", "false", "0", "no", "n", "", "none"]:
            assert _to_bool(val) is False


class TestLoadCsv:
    def test_loads_benign_csv(self, sample_data_dir):
        df = load_events(sample_data_dir / "benign_events.csv")
        assert not df.empty
        assert "hostname" in df.columns
        assert "risk_score" not in df.columns  # scorer not involved yet

    def test_loads_mixed_csv(self, sample_data_dir):
        df = load_events(sample_data_dir / "mixed_events.csv")
        assert len(df) > 0

    def test_loads_high_risk_csv(self, sample_data_dir):
        df = load_events(sample_data_dir / "high_risk_events.csv")
        assert len(df) > 0

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_events(Path("/nonexistent/path/events.csv"))

    def test_unsupported_extension_raises(self, tmp_path):
        bad_file = tmp_path / "events.txt"
        bad_file.write_text("timestamp,hostname\n")
        with pytest.raises(ValueError, match="Unsupported file format"):
            load_events(bad_file)

    def test_all_schema_columns_present(self, sample_data_dir):
        df = load_events(sample_data_dir / "benign_events.csv")
        for col in SCHEMA:
            assert col in df.columns, f"Missing column: {col}"

    def test_bool_columns_are_bool(self, sample_data_dir):
        df = load_events(sample_data_dir / "benign_events.csv")
        for col in ["encoded_command", "external_connection",
                    "privilege_escalation_flag", "persistence_flag"]:
            assert df[col].dtype == bool, f"{col} should be bool"

    def test_int_columns_are_int(self, sample_data_dir):
        df = load_events(sample_data_dir / "benign_events.csv")
        assert df["failed_logins"].dtype in [int, "int64", "int32"]
        assert df["destination_port"].dtype in [int, "int64", "int32"]


class TestLoadJson:
    def _write_json(self, tmp_path: Path, data) -> Path:
        path = tmp_path / "events.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_loads_json_list(self, tmp_path):
        data = [
            {
                "timestamp": "2024-01-15 09:00:00",
                "hostname": "HOST-01",
                "username": "user",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "destination_port": "443",
                "process_name": "chrome.exe",
                "parent_process": "explorer.exe",
                "command_line": "chrome.exe",
                "event_type": "network_connection",
                "protocol": "TCP",
                "failed_logins": "0",
                "encoded_command": "False",
                "external_connection": "False",
                "privilege_escalation_flag": "False",
                "persistence_flag": "False",
                "severity_label": "benign",
                "probable_attack_category": "None",
            }
        ]
        path = self._write_json(tmp_path, data)
        df = load_events(path)
        assert len(df) == 1
        assert df.iloc[0]["hostname"] == "HOST-01"

    def test_loads_json_envelope(self, tmp_path):
        data = {"events": [{"hostname": "H1", "timestamp": "2024-01-01 00:00:00"}]}
        path = self._write_json(tmp_path, data)
        df = load_events(path)
        assert len(df) == 1

    def test_invalid_json_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_events(path)

    def test_empty_json_raises(self, tmp_path):
        path = self._write_json(tmp_path, [])
        with pytest.raises(ValueError, match="No events found"):
            load_events(path)


class TestNormalization:
    def test_missing_columns_filled_with_defaults(self, tmp_path):
        # Write a CSV with only a few columns.
        csv_content = "timestamp,hostname\n2024-01-01 00:00:00,TEST-HOST\n"
        path = tmp_path / "minimal.csv"
        path.write_text(csv_content)
        df = load_events(path)
        assert "failed_logins" in df.columns
        assert df.iloc[0]["failed_logins"] == 0
        assert not df.iloc[0]["encoded_command"]

    def test_extra_columns_are_dropped(self, tmp_path):
        csv_content = "timestamp,hostname,EXTRA_COL\n2024-01-01,H1,foo\n"
        path = tmp_path / "extra.csv"
        path.write_text(csv_content)
        df = load_events(path)
        assert "extra_col" not in df.columns
        assert "EXTRA_COL" not in df.columns
