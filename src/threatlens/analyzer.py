"""
analyzer.py - Main analysis pipeline orchestrator for ThreatLens.

Ties together all pipeline stages in one place:
  1. Load and normalize events (parser)
  2. Extract features (features)
  3. Score each event (scorer)
  4. Predict with ML classifier (model)
  5. Map ATT&CK-style categories (mapper)
  6. Compile results into a single result DataFrame

The public entry point is `run_analysis()`.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd

from threatlens import __version__
from threatlens.features import extract_features
from threatlens.mapper import map_attack_categories
from threatlens.model import ThreatClassifier, load_labeled_training_data
from threatlens.parser import load_events
from threatlens.scorer import score_events
from threatlens.utils import get_logger

logger = get_logger(__name__)


@dataclass
class AnalysisResult:
    """
    Container for all outputs produced by a single analysis run.

    Attributes
    ----------
    input_path : Path
        The analyzed file.
    total_events : int
        Number of events processed.
    results : pd.DataFrame
        Per-event combined output (raw events + features + scores + ML predictions).
    model_eval_report : str
        Classification report from training evaluation (or empty if no training).
    model_accuracy : float
        Hold-out accuracy (0–1).
    model_top_features : list[tuple[str, float]]
        Top ML feature importances.
    ml_trained : bool
        Whether the ML model was successfully trained.
    version : str
        ThreatLens version string.
    """

    input_path: Path
    total_events: int
    results: pd.DataFrame
    model_eval_report: str = ""
    model_accuracy: float = 0.0
    model_top_features: list = field(default_factory=list)
    ml_trained: bool = False
    version: str = __version__


def run_analysis(
    input_path: Path,
    training_data_dir: Optional[Path] = None,
) -> AnalysisResult:
    """
    Execute the full ThreatLens analysis pipeline.

    Parameters
    ----------
    input_path : Path
        Path to the event CSV or JSON file to analyze.
    training_data_dir : Path, optional
        Directory containing labeled CSV files for ML training.
        Defaults to sample_data/ relative to input_path's parent hierarchy.

    Returns
    -------
    AnalysisResult
        All pipeline outputs bundled in one object.
    """
    # -- Stage 1: Load and normalize events ------------------------------------
    logger.info("Loading events from '%s'", input_path)
    df_raw = load_events(input_path)
    total = len(df_raw)

    # -- Stage 2: Feature extraction -------------------------------------------
    logger.info("Extracting features (%d events)", total)
    df_features = extract_features(df_raw)

    # -- Stage 3: Transparent rule-based scoring --------------------------------
    logger.info("Scoring events")
    df_scores = score_events(df_features)

    # -- Stage 4: ML classification --------------------------------------------
    clf = ThreatClassifier()
    ml_trained = False
    eval_report = ""
    accuracy = 0.0
    top_features: list = []

    # Resolve the training data directory.
    train_dir = _resolve_training_dir(input_path, training_data_dir)

    if train_dir and train_dir.exists():
        train_feats, train_labels = load_labeled_training_data(train_dir)
        if train_feats is not None and len(train_feats) >= 6:
            logger.info(
                "Training ML classifier on %d labeled events from '%s'",
                len(train_feats), train_dir
            )
            eval_report = clf.train(train_feats, train_labels)
            ml_trained = clf.trained
            accuracy = clf.training_accuracy
            top_features = clf.top_features(n=5)
        else:
            logger.warning("Not enough labeled events found in '%s' to train ML.", train_dir)
    else:
        logger.warning("Training data directory not found — ML predictions will be skipped.")

    if ml_trained:
        ml_predictions = clf.predict(df_features)
        ml_proba = clf.predict_proba(df_features)
        # Pull max confidence score for the predicted class.
        ml_confidence = ml_proba.max(axis=1).rename("ml_confidence")
    else:
        # Fall back: derive ML-equivalent prediction from the rule-based score.
        ml_predictions = df_scores["risk_level"].rename("ml_prediction")
        ml_confidence = pd.Series(
            [0.0] * total, index=df_features.index, name="ml_confidence"
        )

    # -- Stage 5: ATT&CK-style category mapping --------------------------------
    logger.info("Mapping ATT&CK-style categories")
    df_categories = map_attack_categories(df_raw, df_features)

    # -- Stage 6: Combine all outputs ------------------------------------------
    results = _compile_results(
        df_raw, df_features, df_scores, ml_predictions, ml_confidence, df_categories
    )

    return AnalysisResult(
        input_path=input_path,
        total_events=total,
        results=results,
        model_eval_report=eval_report,
        model_accuracy=accuracy,
        model_top_features=top_features,
        ml_trained=ml_trained,
        version=__version__,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_results(
    df_raw: pd.DataFrame,
    df_features: pd.DataFrame,
    df_scores: pd.DataFrame,
    ml_predictions: pd.Series,
    ml_confidence: pd.Series,
    df_categories: pd.DataFrame,
) -> pd.DataFrame:
    """Merge all pipeline outputs into a single result DataFrame."""
    # Core identity columns from the raw data.
    core = df_raw[[
        "timestamp", "hostname", "username",
        "source_ip", "destination_ip", "destination_port",
        "process_name", "parent_process", "command_line",
        "event_type", "failed_logins",
        "severity_label",  # ground-truth label if available
    ]].copy()

    # Scoring outputs.
    core["risk_score"] = df_scores["risk_score"]
    core["risk_level"] = df_scores["risk_level"]
    core["raw_score"] = df_scores["raw_score"]
    core["explanation"] = df_scores["explanation"]

    # ML outputs.
    core["ml_prediction"] = ml_predictions.values
    core["ml_confidence"] = ml_confidence.values.round(3)

    # ATT&CK mapping.
    core["attack_category"] = df_categories["attack_category"].values
    core["category_reason"] = df_categories["category_reason"].values

    # Sort by descending risk score so highest-priority events appear first.
    core = core.sort_values("risk_score", ascending=False).reset_index(drop=True)

    return core


def _resolve_training_dir(
    input_path: Path,
    explicit_dir: Optional[Path],
) -> Optional[Path]:
    """
    Find the training data directory.

    Priority:
    1. Explicitly supplied path.
    2. sample_data/ adjacent to the input file.
    3. sample_data/ in the project root (walk up to find pyproject.toml).
    """
    if explicit_dir is not None:
        return Path(explicit_dir)

    # Check sibling directory.
    sibling = input_path.parent / "sample_data"
    if sibling.exists():
        return sibling

    # Walk up to find project root (contains pyproject.toml).
    for parent in input_path.parents:
        candidate = parent / "sample_data"
        if candidate.exists():
            return candidate

    return None
