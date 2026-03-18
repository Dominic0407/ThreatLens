# ThreatLens Scoring Model

## Overview

ThreatLens uses a **transparent, additive weighted scoring model** to assign
each security event a risk score between **0 and 100**.  Every point added to
a score comes from a documented, human-readable rule.  There are no hidden
weights, opaque embeddings, or black-box transformations.

This model is deliberately easy to understand, audit, and tune — traits that
matter in real security work.

---

## How Scores Are Computed

### Step 1 — Feature extraction

Raw event fields are transformed into a structured feature set (see
`src/threatlens/features.py`).  Features are either pass-through boolean flags
already present in the data, or derived signals computed from event fields.

### Step 2 — Rule evaluation

Each rule is evaluated against the feature set.  If a rule fires, its
associated point value is added to a running total.  Rules do not interact
with each other (no multiplicative bonuses).

### Step 3 — Normalisation

The raw total is divided by `MAX_RAW_SCORE` (the theoretical maximum if every
rule fires simultaneously) and multiplied by 100 to yield the final 0–100
risk score.

```
risk_score = (raw_score / MAX_RAW_SCORE) × 100
```

### Step 4 — Risk level assignment

| Risk Score  | Risk Level  | Interpretation                              |
|-------------|-------------|---------------------------------------------|
| 0 – 25      | benign      | No significant signals; likely routine      |
| 26 – 50     | low         | Minor signals; worth a glance               |
| 51 – 75     | suspicious  | Multiple signals; warrants investigation    |
| 76 – 100    | malicious   | Strong signals; prioritize for review       |

---

## Scoring Rules

The table below lists every rule, its point value, and the signal it captures.
All rules are defined in `src/threatlens/scorer.py` (`SCORING_RULES`).

| Rule Key                    | Points | Signal                                              |
|-----------------------------|--------|-----------------------------------------------------|
| `encoded_command`           | 30     | Base64-encoded or obfuscated command (common in PowerShell attacks) |
| `privilege_escalation_flag` | 25     | Process or event explicitly flagged for priv-esc    |
| `persistence_flag`          | 20     | Registry run key, scheduled task, or similar persistence mechanism |
| `failed_logins_high`        | 20     | ≥ 10 failed login attempts (brute-force indicator)  |
| `is_suspicious_port`        | 20     | Destination port in the known-malicious port set    |
| `is_suspicious_parent_child`| 15     | Dangerous parent→child process chain (e.g. Word→PowerShell) |
| `has_suspicious_cmdline`    | 15     | Command line matches a high-risk regex pattern      |
| `failed_logins_medium`      | 10     | 5–9 failed login attempts                           |
| `external_connection`       | 10     | Outbound connection to an external (non-RFC 1918) IP |
| `is_suspicious_process`     | 10     | Process name is a known LOLBin or dual-use tool     |
| `is_discovery_process`      |  5     | Recon/enumeration tool (whoami, net, ipconfig, etc.)|

**MAX_RAW_SCORE** = sum of all rule points = **160**

---

## Suspicious Port Set

The following destination ports trigger the `is_suspicious_port` rule
(defined in `src/threatlens/features.py`):

| Port  | Common Association                    |
|-------|---------------------------------------|
| 4444  | Metasploit default listener           |
| 1337  | "leet" — generic RAT / backdoor       |
| 8080  | Alternate HTTP, common C2 redirect    |
| 31337 | "eleet" — classic backdoor port       |
| 1234  | Generic bind/reverse shell            |
| 9001  | Tor relay, Cobalt Strike beacon       |
| 6666  | IRC / reverse shell                   |
| 6667  | IRC                                   |
| 4899  | Radmin remote administration          |
| 5900  | VNC (flagged when external)           |

---

## Suspicious Process Set

Processes in `SUSPICIOUS_PROCESSES` trigger the `is_suspicious_process` rule.
These are all legitimate Windows binaries that are routinely abused
(*Living off the Land* / LOLBins):

`powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`,
`regsvr32.exe`, `rundll32.exe`, `certutil.exe`, `bitsadmin.exe`,
`msiexec.exe`, `psexec.exe`, `wmic.exe`

---

## Suspicious Command-Line Patterns

The `has_suspicious_cmdline` rule fires when any of these regex patterns
match the event's `command_line` field:

| Pattern                    | What it detects                             |
|----------------------------|---------------------------------------------|
| `-[Ee][Nn][Cc]`            | PowerShell `-EncodedCommand` flag           |
| `IEX\s*\(`                 | `Invoke-Expression` execution               |
| `DownloadString`           | WebClient payload download                  |
| `DownloadFile`             | WebClient file download                     |
| `Net\.WebClient`           | .NET web client instantiation               |
| `-ExecutionPolicy Bypass`  | Bypassing PS execution policy               |
| `-W Hidden`                | Hidden PowerShell window                    |
| `FromBase64String`         | Base64 decoding in script                   |
| `certutil.*-decode`        | Certutil binary-to-text abuse               |
| `certutil.*-urlcache`      | Certutil URL fetch abuse                    |
| `Invoke-WebRequest`        | PowerShell web request                      |
| `mimikatz`                 | Credential-dumping tool                     |
| `sekurlsa::`               | Mimikatz module                             |
| `privilege::debug`         | Mimikatz debug privilege                    |

---

## Suspicious Parent→Child Process Chains

The `is_suspicious_parent_child` rule fires when the combination of
`parent_process` and `process_name` matches a known-bad pattern, such as
a Microsoft Office application spawning a script interpreter — a hallmark
of macro-based attacks:

| Parent                  | Child             | Why suspicious                    |
|-------------------------|-------------------|-----------------------------------|
| `winword.exe`           | `powershell.exe`  | Word macro drops PS payload       |
| `winword.exe`           | `cmd.exe`         | Word macro spawns shell           |
| `winword.exe`           | `wscript.exe`     | Word macro runs VBS               |
| `excel.exe`             | `powershell.exe`  | Excel macro drops PS payload      |
| `outlook.exe`           | `powershell.exe`  | Email attachment macro execution  |
| `mshta.exe`             | `powershell.exe`  | HTA script spawns PS              |
| `regsvr32.exe`          | `powershell.exe`  | Squiblydoo technique              |
| `psexec.exe`            | `cmd.exe`         | Remote execution via PsExec       |

---

## Tuning the Scoring Model

All weights are defined in a single list (`SCORING_RULES`) in
`src/threatlens/scorer.py`.  Each entry is a `(rule_key, points, description)`
tuple.  To change a weight, update the `points` value and re-run the tool.

Similarly, the suspicious port set and process set in `src/threatlens/features.py`
can be extended without touching any ML code.

---

## Limitations

- Scores are computed on synthetic data and tuned for demonstration purposes.
- Weights reflect general threat intelligence heuristics, not empirical calibration
  against a real SIEM dataset.
- The scoring model does not account for context such as user role, time-of-day
  baselines, or asset criticality.
- High scores indicate the presence of suspicious signals, not confirmed compromise.
