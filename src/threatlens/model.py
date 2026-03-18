"""
model.py - Lightweight ML classifier for ThreatLens.

Uses a Random Forest classifier trained on labeled synthetic event data
to predict the severity class of each event (benign / suspicious / malicious).

Design decisions:
- Random Forest: easy to explain, robust to imbalanced classes, fast on
  small datasets, and supports feature_importances_ for transparency.
- Training data: the labeled sample CSVs included with the project.
- No external model files are required; the model trains in under one
  second on the included sample data at startup.

The ML prediction is used alongside the rule-based score, not instead of
it.  Both outputs are reported to give analysts two complementary views.

Disclaimer:
    This classifier is trained on a small synthetic dataset for portfolio
    demonstration.  It should not be treated as a production-grade detector.
"""

from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

from threatlens.utils import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Feature columns fed to the ML model.
# Must be a subset of columns produced by features.extract_features().
# ---------------------------------------------------------------------------

ML_FEATURE_COLS: list[str] = [
    "encoded_command",
    "privilege_escalation_flag",
    "persistence_flag",
    "failed_logins_norm",
    "external_connection",
    "is_suspicious_port",
    "is_suspicious_process",
    "is_suspicious_parent_child",
    "has_suspicious_cmdline",
    "is_discovery_process",
]

# Ordered severity classes for display purposes.
SEVERITY_CLASSES = ["benign", "suspicious", "malicious"]


class ThreatClassifier:
    """
    Wraps a scikit-learn Random Forest for threat severity classification.

    Usage:
        clf = ThreatClassifier()
        report = clf.train(features_df, labels_series)
        predictions = clf.predict(features_df)
        probabilities = clf.predict_proba(features_df)  # DataFrame
    """

    def __init__(self) -> None:
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
            class_weight="balanced",  # handles class imbalance gracefully
        )
        self.label_encoder = LabelEncoder()
        self.trained: bool = False
        self.training_accuracy: float = 0.0
        self.eval_report: str = ""
        self.feature_importances: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        features: pd.DataFrame,
        labels: pd.Series,
        eval_split: float = 0.25,
    ) -> str:
        """
        Train the classifier on labeled feature data.

        Parameters
        ----------
        features : pd.DataFrame
            Feature DataFrame (columns from ML_FEATURE_COLS).
        labels : pd.Series
            String severity labels: 'benign', 'suspicious', or 'malicious'.
        eval_split : float
            Fraction of data held out for evaluation (default 0.25).

        Returns
        -------
        str
            A formatted classification report for display.
        """
        X = self._prepare_X(features)
        y = self.label_encoder.fit_transform(labels.str.lower().str.strip())

        if len(X) < 8:
            # Too few samples for a meaningful split; train on everything.
            logger.warning("Very small dataset (%d samples) – skipping eval split.", len(X))
            self.model.fit(X, y)
            self.trained = True
            self.training_accuracy = 1.0
            self.eval_report = "Insufficient samples for train/test split evaluation."
            return self.eval_report

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=eval_split, random_state=42, stratify=y
        )
        self.model.fit(X_train, y_train)
        self.trained = True

        # Evaluate on held-out set.
        y_pred = self.model.predict(X_test)
        self.training_accuracy = accuracy_score(y_test, y_pred)
        class_names = [
            self.label_encoder.classes_[i]
            for i in range(len(self.label_encoder.classes_))
        ]
        self.eval_report = classification_report(
            y_test,
            y_pred,
            target_names=class_names,
            zero_division=0,
        )

        # Store feature importances for reporting.
        self.feature_importances = dict(
            zip(ML_FEATURE_COLS, self.model.feature_importances_.tolist())
        )

        return self.eval_report

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features: pd.DataFrame) -> pd.Series:
        """
        Predict severity class for each event.

        Returns
        -------
        pd.Series
            String class labels, one per event. Index matches features.
        """
        self._check_trained()
        X = self._prepare_X(features)
        y_encoded = self.model.predict(X)
        labels = self.label_encoder.inverse_transform(y_encoded)
        return pd.Series(labels, index=features.index, name="ml_prediction")

    def predict_proba(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Return probability estimates for each class per event.

        Returns
        -------
        pd.DataFrame
            Columns are class names; rows correspond to events.
        """
        self._check_trained()
        X = self._prepare_X(features)
        proba = self.model.predict_proba(X)
        class_names = list(self.label_encoder.classes_)
        return pd.DataFrame(proba, columns=class_names, index=features.index)

    def top_features(self, n: int = 5) -> list[tuple[str, float]]:
        """Return the top-n most important features by Gini importance."""
        if not self.feature_importances:
            return []
        sorted_feats = sorted(
            self.feature_importances.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_feats[:n]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prepare_X(self, features: pd.DataFrame) -> np.ndarray:
        """Select and coerce feature columns to a numeric array."""
        cols = [c for c in ML_FEATURE_COLS if c in features.columns]
        if len(cols) < len(ML_FEATURE_COLS):
            missing = set(ML_FEATURE_COLS) - set(cols)
            logger.warning("Missing feature columns for ML: %s", missing)
        X = features[cols].astype(float).values
        return X

    def _check_trained(self) -> None:
        if not self.trained:
            raise RuntimeError(
                "ThreatClassifier has not been trained. Call train() first."
            )


# ---------------------------------------------------------------------------
# Convenience: load labeled training data from disk
# ---------------------------------------------------------------------------

def load_labeled_training_data(
    data_dir: Path,
) -> tuple[Optional[pd.DataFrame], Optional[pd.Series]]:
    """
    Scan data_dir for CSV files that contain a 'severity_label' column.
    Concatenate all labeled records into a single features / labels pair
    for training.

    Returns (None, None) if no labeled data is found.
    """
    from threatlens.parser import load_events
    from threatlens.features import extract_features

    labeled_features: list[pd.DataFrame] = []
    labeled_targets: list[pd.Series] = []

    for csv_path in sorted(Path(data_dir).glob("*.csv")):
        try:
            df = load_events(csv_path)
        except (FileNotFoundError, ValueError) as exc:
            logger.warning("Skipping '%s': %s", csv_path.name, exc)
            continue

        # Only use rows that have a non-empty severity_label.
        has_label = df["severity_label"].str.strip().str.lower().isin(
            {"benign", "suspicious", "malicious"}
        )
        labeled = df[has_label].copy()
        if labeled.empty:
            continue

        feats = extract_features(labeled)
        labels = labeled["severity_label"].str.strip().str.lower()

        labeled_features.append(feats)
        labeled_targets.append(labels)
        logger.info("Loaded %d labeled events from '%s'.", len(labeled), csv_path.name)

    if not labeled_features:
        return None, None

    all_features = pd.concat(labeled_features, ignore_index=True)
    all_labels = pd.concat(labeled_targets, ignore_index=True)
    return all_features, all_labels
