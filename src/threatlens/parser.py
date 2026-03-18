"""
parser.py - Event data loading and normalization.

Supports CSV and JSON input. Normalizes all records to a consistent
internal schema so the rest of the pipeline never has to worry about
input format differences.

Expected schema columns (case-insensitive, extras are ignored):
    timestamp, hostname, username, source_ip, destination_ip,
    destination_port, process_name, parent_process, command_line,
    event_type, protocol, failed_logins, encoded_command,
    external_connection, privilege_escalation_flag, persistence_flag,
    severity_label, probable_attack_category
"""

import json
from pathlib import Path
from typing import Optional

import pandas as pd

from threatlens.utils import get_logger

logger = get_logger(__name__)

# Canonical column names and their default values when absent.
SCHEMA: dict[str, object] = {
    "timestamp": "",
    "hostname": "unknown",
    "username": "unknown",
    "source_ip": "0.0.0.0",
    "destination_ip": "0.0.0.0",
    "destination_port": 0,
    "process_name": "",
    "parent_process": "",
    "command_line": "",
    "event_type": "",
    "protocol": "",
    "failed_logins": 0,
    "encoded_command": False,
    "external_connection": False,
    "privilege_escalation_flag": False,
    "persistence_flag": False,
    "severity_label": None,
    "probable_attack_category": None,
}

# Columns that should be coerced to boolean.
BOOL_COLS = {"encoded_command", "external_connection", "privilege_escalation_flag", "persistence_flag"}

# Columns that should be coerced to integers.
INT_COLS = {"destination_port", "failed_logins"}


def load_events(path: Path) -> pd.DataFrame:
    """
    Load security events from a CSV or JSON file.

    Returns a normalized DataFrame with all columns in SCHEMA present.
    Raises FileNotFoundError if the path does not exist.
    Raises ValueError if the file format is unsupported or empty.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".csv":
        df = _load_csv(path)
    elif suffix == ".json":
        df = _load_json(path)
    else:
        raise ValueError(f"Unsupported file format: '{suffix}'. Use .csv or .json")

    if df.empty:
        raise ValueError(f"No events found in '{path}'")

    return _normalize(df)


def _load_csv(path: Path) -> pd.DataFrame:
    """Read a CSV file into a DataFrame."""
    try:
        return pd.read_csv(path, dtype=str)
    except Exception as exc:
        raise ValueError(f"Failed to read CSV '{path}': {exc}") from exc


def _load_json(path: Path) -> pd.DataFrame:
    """Read a JSON file (array of objects) into a DataFrame."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "events" in data:
            # Accept {"events": [...]} envelope as well as a bare list.
            data = data["events"]
        if not isinstance(data, list):
            raise ValueError("JSON file must contain an array of event objects.")
        return pd.DataFrame(data).astype(str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in '{path}': {exc}") from exc


def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize a raw DataFrame to the canonical schema.

    Steps:
    1. Lower-case all column names and strip whitespace.
    2. Add any missing schema columns with their default values.
    3. Drop columns not in the schema (keeps the pipeline clean).
    4. Coerce data types (bool columns, int columns).
    5. Replace pandas NA / 'nan' strings with sensible defaults.
    """
    # Normalise column names.
    df.columns = [c.strip().lower() for c in df.columns]

    # Add missing columns.
    for col, default in SCHEMA.items():
        if col not in df.columns:
            df[col] = default
            logger.warning("Column '%s' missing from input – using default: %r", col, default)

    # Keep only schema columns in defined order, and make an explicit copy
    # to avoid pandas SettingWithCopyWarning on subsequent mutations.
    df = df[[c for c in SCHEMA if c in df.columns]].copy()

    # Coerce bool columns (accept True/False/1/0/'True'/'False'/'yes'/'no').
    for col in BOOL_COLS:
        df[col] = df[col].apply(_to_bool)

    # Coerce int columns.
    for col in INT_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    # Clean up string columns: replace 'nan', 'None', empty with sensible defaults.
    for col in df.columns:
        if col not in BOOL_COLS and col not in INT_COLS:
            df[col] = df[col].astype(str).replace({"nan": "", "None": "", "none": ""})

    df = df.reset_index(drop=True)
    return df


def _to_bool(value: object) -> bool:
    """Coerce a variety of truthy representations to Python bool."""
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in {"true", "1", "yes", "y"}
