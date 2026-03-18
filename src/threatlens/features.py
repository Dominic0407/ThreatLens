"""
features.py - Feature extraction for ThreatLens.

Transforms raw normalized event records into a structured feature set
used by both the scoring engine and the ML classifier.

All features are interpretable: each one directly corresponds to a
documented security signal. No black-box transformations are applied.

Feature columns produced (all present in returned DataFrame):
    - encoded_command          (bool) – already in raw data
    - privilege_escalation_flag (bool) – already in raw data
    - persistence_flag         (bool) – already in raw data
    - failed_logins            (int)  – already in raw data
    - external_connection      (bool) – already in raw data
    - is_suspicious_port       (bool) – derived: destination_port in known-bad set
    - is_suspicious_process    (bool) – derived: process_name in known-suspicious set
    - is_suspicious_parent_child (bool) – derived: dangerous parent→child chain
    - has_suspicious_cmdline   (bool) – derived: regex match on command_line
    - is_discovery_process     (bool) – derived: recon tool detected
    - failed_logins_norm       (float) – failed_logins / 20, capped at 1.0
"""

import re
from typing import Final

import pandas as pd

# ---------------------------------------------------------------------------
# Threat intelligence signals (all configurable)
# ---------------------------------------------------------------------------

# Processes commonly abused for LOLBins / living-off-the-land execution.
SUSPICIOUS_PROCESSES: Final[frozenset[str]] = frozenset({
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "psexec.exe",
    "wmic.exe",
})

# Ports commonly associated with C2 frameworks, bind shells, or non-standard services.
SUSPICIOUS_PORTS: Final[frozenset[int]] = frozenset({
    4444,   # Metasploit default
    1337,   # "leet" – generic RAT
    8080,   # alternate HTTP, common C2 redirect
    31337,  # "eleet" – old-school backdoor
    1234,   # generic test/bind shell
    9001,   # Tor / Cobalt Strike
    6666,   # generic IRC / reverse shell
    6667,   # IRC
    4899,   # Radmin remote admin
    5900,   # VNC (external only, flag context)
})

# Parent → child process pairs that indicate suspicious execution chains.
# e.g., a Word document spawning PowerShell is a classic macro attack pattern.
SUSPICIOUS_PARENT_CHILD: Final[frozenset[tuple[str, str]]] = frozenset({
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "wscript.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("mshta.exe", "powershell.exe"),
    ("regsvr32.exe", "powershell.exe"),
    ("psexec.exe", "cmd.exe"),
    ("psexec.exe", "powershell.exe"),
})

# Regex patterns that indicate suspicious command-line content.
SUSPICIOUS_CMDLINE_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"-[Ee][Nn][Cc](?:oded)?(?:Command)?", re.IGNORECASE),  # PS -Encoded
    re.compile(r"\bIEX\b", re.IGNORECASE),                              # Invoke-Expression
    re.compile(r"DownloadString", re.IGNORECASE),                       # WebClient download
    re.compile(r"DownloadFile", re.IGNORECASE),
    re.compile(r"Net\.WebClient", re.IGNORECASE),
    re.compile(r"-[Ee]xecution[Pp]olicy\s+[Bb]ypass"),                 # Bypass EP
    re.compile(r"-[Ww]\s*[Hh]idden"),                                   # Hidden window
    re.compile(r"FromBase64String", re.IGNORECASE),                     # Base64 decode
    re.compile(r"Invoke-Expression", re.IGNORECASE),
    re.compile(r"certutil.*-decode", re.IGNORECASE),                    # Certutil abuse
    re.compile(r"certutil.*-urlcache", re.IGNORECASE),
    re.compile(r"\bInvoke-WebRequest\b", re.IGNORECASE),               # PS web fetch
    re.compile(r"\bmimikatz\b", re.IGNORECASE),                        # Credential dumper
    re.compile(r"sekurlsa::", re.IGNORECASE),
    re.compile(r"privilege::debug", re.IGNORECASE),
]

# Processes used for host/network discovery (recon phase).
DISCOVERY_PROCESSES: Final[frozenset[str]] = frozenset({
    "whoami.exe",
    "ipconfig.exe",
    "net.exe",
    "netstat.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "arp.exe",
    "nslookup.exe",
    "nltest.exe",
    "ping.exe",
    "tracert.exe",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive a feature DataFrame from a normalized events DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Normalized event records as returned by parser.load_events().

    Returns
    -------
    pd.DataFrame
        One row per event, columns as documented in module docstring.
        Index matches the input df.
    """
    features = pd.DataFrame(index=df.index)

    # --- Pass-through flags already present in the raw data ---
    features["encoded_command"] = df["encoded_command"].astype(bool)
    features["privilege_escalation_flag"] = df["privilege_escalation_flag"].astype(bool)
    features["persistence_flag"] = df["persistence_flag"].astype(bool)
    features["failed_logins"] = df["failed_logins"].astype(int)
    features["external_connection"] = df["external_connection"].astype(bool)

    # --- Derived features ---
    process_lower = df["process_name"].str.lower().str.strip()
    parent_lower = df["parent_process"].str.lower().str.strip()

    features["is_suspicious_port"] = df["destination_port"].apply(
        lambda p: int(p) in SUSPICIOUS_PORTS
    )
    features["is_suspicious_process"] = process_lower.isin(SUSPICIOUS_PROCESSES)
    features["is_suspicious_parent_child"] = _detect_parent_child_chains(parent_lower, process_lower)
    features["has_suspicious_cmdline"] = df["command_line"].apply(_has_suspicious_cmdline)
    features["is_discovery_process"] = process_lower.isin(DISCOVERY_PROCESSES)

    # Normalised failed login count (0.0–1.0, capped at 20 raw logins).
    features["failed_logins_norm"] = (features["failed_logins"] / 20.0).clip(upper=1.0)

    return features


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_parent_child_chains(
    parent_series: pd.Series,
    child_series: pd.Series,
) -> pd.Series:
    """Return boolean Series: True where (parent, child) is in the suspicious set."""
    pairs = list(zip(parent_series, child_series))
    return pd.Series(
        [pair in SUSPICIOUS_PARENT_CHILD for pair in pairs],
        index=parent_series.index,
    )


def _has_suspicious_cmdline(cmdline: str) -> bool:
    """Return True if any suspicious cmdline pattern matches."""
    if not cmdline:
        return False
    return any(pattern.search(cmdline) for pattern in SUSPICIOUS_CMDLINE_PATTERNS)
