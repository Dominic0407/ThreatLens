"""
test_reporter.py - Tests for report generation.
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from threatlens.reporter import write_json_report, write_markdown_report
from threatlens.analyzer import AnalysisResult


def _make_minimal_result(tmp_path: Path) -> AnalysisResult:
    """Build a minimal AnalysisResult for testing reporters."""
    input_file = tmp_path / "test_events.csv"
    input_file.write_text("placeholder")

    results_df = pd.DataFrame([
        {
            "timestamp": "2024-01-15 09:00:00",
            "hostname": "HOST-01",
            "username": "user",
            "source_ip": "192.168.1.1",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "process_name": "chrome.exe",
            "parent_process": "explorer.exe",
            "command_line": "chrome.exe",
            "event_type": "network_connection",
            "failed_logins": 0,
            "severity_label": "benign",
            "risk_score": 0.0,
            "risk_level": "benign",
            "raw_score": 0,
            "explanation": "No high-risk signals detected.",
            "triggered_rules": [],
            "ml_prediction": "benign",
            "ml_confidence": 0.95,
            "attack_category": "Unknown",
            "category_reason": "No pattern matched.",
        },
        {
            "timestamp": "2024-01-17 02:11:04",
            "hostname": "HOST-05",
            "username": "hacker",
            "source_ip": "192.168.1.14",
            "destination_ip": "203.0.113.44",
            "destination_port": 4444,
            "process_name": "powershell.exe",
            "parent_process": "cmd.exe",
            "command_line": "powershell.exe -Enc JABj",
            "event_type": "process_create",
            "failed_logins": 0,
            "severity_label": "malicious",
            "risk_score": 85.0,
            "risk_level": "malicious",
            "raw_score": 110,
            "explanation": "Risk level 'malicious' — 3 signal(s) triggered:\n  • Encoded command\n  • External connection\n  • Suspicious port",
            "triggered_rules": ["encoded", "external", "port"],
            "ml_prediction": "malicious",
            "ml_confidence": 0.91,
            "attack_category": "Command and Control",
            "category_reason": "External connection with suspicious port.",
        },
    ])

    return AnalysisResult(
        input_path=input_file,
        total_events=2,
        results=results_df,
        model_eval_report="              precision    recall  f1-score\n   benign       1.00      1.00      1.00",
        model_accuracy=0.95,
        model_top_features=[("encoded_command", 0.35), ("is_suspicious_port", 0.25)],
        ml_trained=True,
        version="0.1.0",
    )


class TestWriteJsonReport:
    def test_creates_file(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_json_report(result, output_dir)
        assert path.exists()

    def test_valid_json(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_json_report(result, output_dir)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, dict)

    def test_json_has_expected_keys(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_json_report(result, output_dir)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert "meta" in data
        assert "summary" in data
        assert "events" in data

    def test_json_event_count_matches(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_json_report(result, output_dir)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data["events"]) == result.total_events

    def test_json_meta_contains_version(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_json_report(result, output_dir)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["meta"]["version"] == "0.1.0"

    def test_output_dir_created_if_missing(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "nested" / "reports"
        assert not output_dir.exists()
        write_json_report(result, output_dir)
        assert output_dir.exists()


class TestWriteMarkdownReport:
    def test_creates_file(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_markdown_report(result, output_dir)
        assert path.exists()
        assert path.suffix == ".md"

    def test_markdown_contains_heading(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_markdown_report(result, output_dir)
        content = path.read_text(encoding="utf-8")
        assert "# ThreatLens Analysis Report" in content

    def test_markdown_contains_summary_table(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_markdown_report(result, output_dir)
        content = path.read_text(encoding="utf-8")
        assert "## Summary" in content
        assert "MALICIOUS" in content

    def test_markdown_contains_event_details(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_markdown_report(result, output_dir)
        content = path.read_text(encoding="utf-8")
        assert "HOST-05" in content

    def test_markdown_contains_limitations(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "reports"
        path = write_markdown_report(result, output_dir)
        content = path.read_text(encoding="utf-8")
        assert "Limitations" in content

    def test_output_dir_created_if_missing(self, tmp_path):
        result = _make_minimal_result(tmp_path)
        output_dir = tmp_path / "deeply" / "nested" / "reports"
        write_markdown_report(result, output_dir)
        assert output_dir.exists()
