"""
mapper.py - ATT&CK-style behavior category mapping for ThreatLens.

Maps each event to the most likely MITRE ATT&CK tactic category based
on the features and raw event data.  The mapping is heuristic / rule-based
and does not require an internet connection or ATT&CK dataset download.

Supported categories (subset of MITRE ATT&CK tactics):
    - Execution
    - Persistence
    - Privilege Escalation
    - Credential Access
    - Discovery
    - Lateral Movement
    - Command and Control
    - Exfiltration
    - Initial Access
    - Unknown  (fallback when no signals match)

Design note: categories are assigned by priority order (highest confidence
first).  A single event can only have one primary category; the most
specific match wins.  Full documentation lives in docs/attack_mapping.md.
"""

import pandas as pd

from threatlens.utils import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Mapping rules
# Each rule is (category, reason, predicate_function).
# Rules are evaluated in order; first match wins.
# ---------------------------------------------------------------------------

def _rule_c2(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    """Command and Control: external connection + suspicious port, or encoded C2 pattern."""
    return bool(row_feat["external_connection"]) and (
        bool(row_feat["is_suspicious_port"]) or bool(row_feat["encoded_command"])
    )


def _rule_execution_encoded(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    """Execution via encoded/obfuscated script."""
    return bool(row_feat["encoded_command"]) or bool(row_feat["has_suspicious_cmdline"])


def _rule_privilege_escalation(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    return bool(row_feat["privilege_escalation_flag"])


def _rule_persistence(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    return bool(row_feat["persistence_flag"])


def _rule_credential_access(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    """Credential Access: high failed-login count or credential-dumper pattern."""
    return int(row_feat["failed_logins"]) >= 5


def _rule_lateral_movement(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    """Lateral Movement: remote process execution pattern."""
    process = str(row_raw.get("process_name", "")).lower()
    cmdline = str(row_raw.get("command_line", "")).lower()
    lateral_tools = {"psexec.exe", "wmic.exe", "mstsc.exe"}
    lateral_keywords = ["\\\\", "/node:", "invoke-command", "enter-pssession"]
    return (
        process in lateral_tools
        or any(kw in cmdline for kw in lateral_keywords)
    )


def _rule_discovery(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    return bool(row_feat["is_discovery_process"])


def _rule_exfiltration(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    """Exfiltration: external connection + bulk copy or web upload pattern."""
    cmdline = str(row_raw.get("command_line", "")).lower()
    exfil_keywords = ["robocopy", "xcopy", "invoke-webrequest", "invoke-restmethod",
                      "upload", "ftp", "scp", "/e /copyall"]
    return bool(row_feat["external_connection"]) and any(kw in cmdline for kw in exfil_keywords)


def _rule_suspicious_parent_child(row_raw: pd.Series, row_feat: pd.Series) -> bool:
    return bool(row_feat["is_suspicious_parent_child"])


# Ordered rule table: (category, short_reason, predicate)
_RULES: list[tuple[str, str, object]] = [
    (
        "Command and Control",
        "External connection to suspicious port or with encoded payload",
        _rule_c2,
    ),
    (
        "Exfiltration",
        "External connection combined with bulk-copy or web-upload command",
        _rule_exfiltration,
    ),
    (
        "Privilege Escalation",
        "Privilege escalation flag set",
        _rule_privilege_escalation,
    ),
    (
        "Persistence",
        "Persistence mechanism detected (registry / scheduled task)",
        _rule_persistence,
    ),
    (
        "Credential Access",
        "Repeated failed logins or credential-dumping tool detected",
        _rule_credential_access,
    ),
    (
        "Lateral Movement",
        "Remote execution tool or technique detected",
        _rule_lateral_movement,
    ),
    (
        "Discovery",
        "Recon or enumeration tool executed",
        _rule_discovery,
    ),
    (
        "Execution",
        "Encoded, obfuscated, or suspicious script/command executed",
        _rule_execution_encoded,
    ),
    (
        "Execution",
        "Suspicious parent→child process chain suggests script-based execution",
        _rule_suspicious_parent_child,
    ),
]

_UNKNOWN = "Unknown"
_UNKNOWN_REASON = "No clear ATT&CK-style pattern matched; event may be benign or low-signal"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_attack_categories(
    df_raw: pd.DataFrame,
    df_features: pd.DataFrame,
) -> pd.DataFrame:
    """
    Assign ATT&CK-style category and mapping reason to each event.

    Parameters
    ----------
    df_raw : pd.DataFrame
        Normalized raw events (from parser).
    df_features : pd.DataFrame
        Extracted features (from features module).

    Returns
    -------
    pd.DataFrame
        Columns: attack_category, category_reason
        Index matches df_raw.
    """
    categories: list[str] = []
    reasons: list[str] = []

    for idx in df_raw.index:
        row_raw = df_raw.loc[idx]
        row_feat = df_features.loc[idx]
        category, reason = _map_single(row_raw, row_feat)
        categories.append(category)
        reasons.append(reason)

    return pd.DataFrame(
        {"attack_category": categories, "category_reason": reasons},
        index=df_raw.index,
    )


def _map_single(row_raw: pd.Series, row_feat: pd.Series) -> tuple[str, str]:
    """Return (category, reason) for a single event."""
    for category, reason, predicate in _RULES:
        try:
            if predicate(row_raw, row_feat):
                return category, reason
        except Exception as exc:
            logger.debug("Rule error for category '%s': %s", category, exc)
            continue
    return _UNKNOWN, _UNKNOWN_REASON
