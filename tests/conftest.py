"""
conftest.py - Shared pytest fixtures for ThreatLens tests.
"""

import io
from pathlib import Path

import pandas as pd
import pytest


# ---------------------------------------------------------------------------
# Minimal raw event DataFrames
# ---------------------------------------------------------------------------

@pytest.fixture
def benign_event_row() -> dict:
    """A single benign event record as a dict."""
    return {
        "timestamp": "2024-01-15 09:00:00",
        "hostname": "WORKSTATION-01",
        "username": "jsmith",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.1",
        "destination_port": 443,
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "command_line": "chrome.exe --profile-directory=Default",
        "event_type": "network_connection",
        "protocol": "TCP",
        "failed_logins": 0,
        "encoded_command": False,
        "external_connection": False,
        "privilege_escalation_flag": False,
        "persistence_flag": False,
        "severity_label": "benign",
        "probable_attack_category": "None",
    }


@pytest.fixture
def malicious_event_row() -> dict:
    """A single high-risk event record as a dict."""
    return {
        "timestamp": "2024-01-17 02:11:04",
        "hostname": "WORKSTATION-05",
        "username": "svc_backup",
        "source_ip": "192.168.1.14",
        "destination_ip": "203.0.113.44",
        "destination_port": 4444,
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA=",
        "event_type": "process_create",
        "protocol": "TCP",
        "failed_logins": 0,
        "encoded_command": True,
        "external_connection": True,
        "privilege_escalation_flag": False,
        "persistence_flag": False,
        "severity_label": "malicious",
        "probable_attack_category": "Command and Control",
    }


@pytest.fixture
def suspicious_event_row() -> dict:
    """A moderately suspicious event record."""
    return {
        "timestamp": "2024-01-16 08:58:41",
        "hostname": "WORKSTATION-04",
        "username": "bwilson",
        "source_ip": "192.168.1.13",
        "destination_ip": "192.168.1.2",
        "destination_port": 445,
        "process_name": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\update.ps1",
        "event_type": "process_create",
        "protocol": "TCP",
        "failed_logins": 0,
        "encoded_command": False,
        "external_connection": False,
        "privilege_escalation_flag": False,
        "persistence_flag": False,
        "severity_label": "suspicious",
        "probable_attack_category": "Execution",
    }


@pytest.fixture
def sample_df(benign_event_row, malicious_event_row, suspicious_event_row) -> pd.DataFrame:
    """A small mixed DataFrame with three events."""
    rows = [benign_event_row, malicious_event_row, suspicious_event_row]
    return pd.DataFrame(rows)


@pytest.fixture(scope="session")
def sample_data_dir() -> Path:
    """Return path to the project sample_data directory."""
    # Walk up from tests/ to find sample_data/
    here = Path(__file__).parent
    candidate = here.parent / "sample_data"
    if candidate.exists():
        return candidate
    raise FileNotFoundError("sample_data/ directory not found")
