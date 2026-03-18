"""
test_model.py - Tests for the ML classifier.
"""

import pandas as pd
import pytest

from threatlens.model import ThreatClassifier, load_labeled_training_data, ML_FEATURE_COLS
from threatlens.parser import _normalize, load_events
from threatlens.features import extract_features


def _make_minimal_labeled_data(n_per_class: int = 5):
    """Generate a small synthetic labeled dataset for unit tests."""
    rows = []

    # Benign: no signals
    for i in range(n_per_class):
        rows.append({
            "encoded_command": False, "privilege_escalation_flag": False,
            "persistence_flag": False, "failed_logins_norm": 0.0,
            "external_connection": False, "is_suspicious_port": False,
            "is_suspicious_process": False, "is_suspicious_parent_child": False,
            "has_suspicious_cmdline": False, "is_discovery_process": False,
            "label": "benign",
        })

    # Suspicious: some signals
    for i in range(n_per_class):
        rows.append({
            "encoded_command": False, "privilege_escalation_flag": False,
            "persistence_flag": False, "failed_logins_norm": 0.3,
            "external_connection": True, "is_suspicious_port": False,
            "is_suspicious_process": True, "is_suspicious_parent_child": True,
            "has_suspicious_cmdline": True, "is_discovery_process": False,
            "label": "suspicious",
        })

    # Malicious: many signals
    for i in range(n_per_class):
        rows.append({
            "encoded_command": True, "privilege_escalation_flag": True,
            "persistence_flag": True, "failed_logins_norm": 0.7,
            "external_connection": True, "is_suspicious_port": True,
            "is_suspicious_process": True, "is_suspicious_parent_child": True,
            "has_suspicious_cmdline": True, "is_discovery_process": True,
            "label": "malicious",
        })

    df = pd.DataFrame(rows)
    features = df[ML_FEATURE_COLS]
    labels = df["label"]
    return features, labels


class TestThreatClassifier:
    def test_untrained_predict_raises(self):
        clf = ThreatClassifier()
        features, _ = _make_minimal_labeled_data()
        with pytest.raises(RuntimeError, match="not been trained"):
            clf.predict(features)

    def test_train_returns_string_report(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data(n_per_class=8)
        report = clf.train(features, labels)
        assert isinstance(report, str)

    def test_trained_flag_set_after_train(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        assert clf.trained is True

    def test_predict_returns_series(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        predictions = clf.predict(features)
        assert isinstance(predictions, pd.Series)
        assert len(predictions) == len(features)

    def test_predictions_are_valid_labels(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        predictions = clf.predict(features)
        valid = {"benign", "suspicious", "malicious"}
        assert set(predictions.unique()).issubset(valid)

    def test_predict_proba_returns_dataframe(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        proba = clf.predict_proba(features)
        assert isinstance(proba, pd.DataFrame)
        assert proba.shape == (len(features), 3)

    def test_predict_proba_sums_to_one(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        proba = clf.predict_proba(features)
        row_sums = proba.sum(axis=1)
        assert (abs(row_sums - 1.0) < 1e-6).all()

    def test_top_features_after_training(self):
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data()
        clf.train(features, labels)
        top = clf.top_features(n=3)
        assert len(top) == 3
        assert all(isinstance(name, str) for name, _ in top)
        assert all(isinstance(imp, float) for _, imp in top)

    def test_benign_event_predicted_correctly(self):
        """Verify classifier tends toward 'benign' for all-zero feature rows."""
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data(n_per_class=10)
        clf.train(features, labels)
        benign_feat = pd.DataFrame([{col: 0.0 for col in ML_FEATURE_COLS}])
        pred = clf.predict(benign_feat)
        assert pred.iloc[0] == "benign"

    def test_malicious_event_predicted_correctly(self):
        """Verify classifier tends toward 'malicious' for all-true feature rows."""
        clf = ThreatClassifier()
        features, labels = _make_minimal_labeled_data(n_per_class=10)
        clf.train(features, labels)
        malicious_feat = pd.DataFrame([{col: 1.0 for col in ML_FEATURE_COLS}])
        pred = clf.predict(malicious_feat)
        assert pred.iloc[0] == "malicious"


class TestLoadLabeledTrainingData:
    def test_loads_from_sample_data_dir(self, sample_data_dir):
        features, labels = load_labeled_training_data(sample_data_dir)
        assert features is not None
        assert labels is not None
        assert len(features) > 0
        assert len(labels) == len(features)

    def test_returns_none_for_empty_dir(self, tmp_path):
        features, labels = load_labeled_training_data(tmp_path)
        assert features is None
        assert labels is None

    def test_labels_are_valid(self, sample_data_dir):
        _, labels = load_labeled_training_data(sample_data_dir)
        valid = {"benign", "suspicious", "malicious"}
        assert set(labels.unique()).issubset(valid)
