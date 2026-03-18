"""
test_integration.py - End-to-end workflow and integration tests.

These tests exercise the full pipeline: load → extract → score → ML → map → report.
"""

import json
from pathlib import Path

import pytest

from threatlens.analyzer import run_analysis


class TestFullPipelineHighRisk:
    """Full pipeline test on the high-risk sample dataset."""

    @pytest.fixture(scope="class")
    def high_risk_result(self, sample_data_dir):
        input_path = sample_data_dir / "high_risk_events.csv"
        return run_analysis(input_path, training_data_dir=sample_data_dir)

    def test_total_events_nonzero(self, high_risk_result):
        assert high_risk_result.total_events > 0

    def test_results_dataframe_has_correct_shape(self, high_risk_result):
        df = high_risk_result.results
        assert len(df) == high_risk_result.total_events

    def test_results_has_risk_score_column(self, high_risk_result):
        assert "risk_score" in high_risk_result.results.columns

    def test_results_has_attack_category_column(self, high_risk_result):
        assert "attack_category" in high_risk_result.results.columns

    def test_results_has_explanation_column(self, high_risk_result):
        assert "explanation" in high_risk_result.results.columns

    def test_high_risk_dataset_has_malicious_events(self, high_risk_result):
        df = high_risk_result.results
        malicious_count = (df["risk_level"] == "malicious").sum()
        assert malicious_count > 0, "High-risk dataset should have malicious events"

    def test_ml_was_trained(self, high_risk_result):
        assert high_risk_result.ml_trained is True

    def test_ml_accuracy_reasonable(self, high_risk_result):
        # On this synthetic, clearly-labeled data, accuracy should be decent.
        assert high_risk_result.model_accuracy >= 0.5

    def test_results_sorted_by_risk_score_descending(self, high_risk_result):
        scores = high_risk_result.results["risk_score"].tolist()
        assert scores == sorted(scores, reverse=True)

    def test_attack_categories_are_known_values(self, high_risk_result):
        known_categories = {
            "Execution", "Persistence", "Privilege Escalation",
            "Credential Access", "Discovery", "Lateral Movement",
            "Command and Control", "Exfiltration", "Initial Access", "Unknown"
        }
        actual = set(high_risk_result.results["attack_category"].unique())
        assert actual.issubset(known_categories), f"Unexpected categories: {actual - known_categories}"


class TestFullPipelineBenign:
    """Full pipeline test on the benign sample dataset."""

    @pytest.fixture(scope="class")
    def benign_result(self, sample_data_dir):
        input_path = sample_data_dir / "benign_events.csv"
        return run_analysis(input_path, training_data_dir=sample_data_dir)

    def test_total_events_nonzero(self, benign_result):
        assert benign_result.total_events > 0

    def test_benign_dataset_mostly_low_scores(self, benign_result):
        df = benign_result.results
        low_risk_count = df[df["risk_level"].isin(["benign", "low"])].shape[0]
        total = len(df)
        # At least 80% of the benign dataset should score low.
        assert low_risk_count / total >= 0.8, (
            f"Expected ≥80% benign/low, got {low_risk_count/total:.0%}"
        )


class TestFullPipelineMixed:
    """Full pipeline test on the mixed sample dataset."""

    @pytest.fixture(scope="class")
    def mixed_result(self, sample_data_dir):
        input_path = sample_data_dir / "mixed_events.csv"
        return run_analysis(input_path, training_data_dir=sample_data_dir)

    def test_mixed_dataset_has_both_benign_and_suspicious(self, mixed_result):
        df = mixed_result.results
        levels = set(df["risk_level"].unique())
        assert "benign" in levels
        assert len(levels) > 1  # should have multiple risk levels


class TestReportGeneration:
    """Integration tests for report file generation."""

    def test_json_report_roundtrip(self, sample_data_dir, tmp_path):
        from threatlens.reporter import write_json_report
        result = run_analysis(
            sample_data_dir / "high_risk_events.csv",
            training_data_dir=sample_data_dir,
        )
        output_dir = tmp_path / "reports"
        json_path = write_json_report(result, output_dir)

        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["meta"]["total_events"] == result.total_events
        assert len(data["events"]) == result.total_events
        # Every event should have a risk_score field.
        for event in data["events"]:
            assert "risk_score" in event
            assert "attack_category" in event

    def test_markdown_report_generated(self, sample_data_dir, tmp_path):
        from threatlens.reporter import write_markdown_report
        result = run_analysis(
            sample_data_dir / "mixed_events.csv",
            training_data_dir=sample_data_dir,
        )
        output_dir = tmp_path / "reports"
        md_path = write_markdown_report(result, output_dir)

        content = md_path.read_text(encoding="utf-8")
        assert len(content) > 500
        assert "ThreatLens" in content


class TestErrorHandling:
    """Verify the pipeline fails gracefully on bad input."""

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            run_analysis(Path("/nonexistent/events.csv"))

    def test_unsupported_format_raises(self, tmp_path):
        bad = tmp_path / "events.xlsx"
        bad.write_text("data")
        with pytest.raises(ValueError):
            run_analysis(bad)
