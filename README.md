# ThreatLens

**AI-assisted threat prioritization for security events using transparent scoring and lightweight machine learning.**

ThreatLens is an offline Python CLI tool that ingests synthetic security event data, extracts interpretable features, applies a rule-based weighted scoring model, uses a lightweight Random Forest classifier to support prioritization, maps events to ATT&CK-style behavior categories, and generates analyst-friendly reports.

> **Portfolio project** — Built to demonstrate practical cybersecurity data analysis skills for hiring managers and SOC-adjacent roles.  Operates fully offline on synthetic/sanitized data.  Not a production SOC platform.

---

## Why This Project Matters

Security analysts face alert fatigue daily.  A typical SIEM floods analysts with hundreds or thousands of events — most benign — while genuinely malicious activity hides in the noise.

ThreatLens demonstrates the core engineering challenge behind threat prioritization:

- How do you **extract meaningful signals** from raw endpoint/network events?
- How do you build a scoring model that is **transparent enough to trust** in a security context?
- How do you **apply ML without overclaiming** its capabilities?
- How do you produce output that an analyst can **act on immediately**?

---

## Features

| Feature | Details |
|---|---|
| Multi-format input | Ingest `.csv` or `.json` event files |
| Transparent scoring | Additive weighted model — every point is documented |
| ML classification | Random Forest classifier (scikit-learn) trained on labeled synthetic data |
| Explainability | Per-event explanation of which signals fired and why |
| ATT&CK-style mapping | Heuristic mapping to 9 ATT&CK tactic categories |
| Rich terminal output | Color-coded tables and event details via Rich |
| JSON report | Machine-readable structured output |
| Markdown report | Analyst-friendly document suitable for ticketing systems |
| Fully offline | No API keys, no network calls, no LLM dependency |
| Lightweight | Only 3 runtime dependencies: pandas, scikit-learn, rich |

---

## Project Structure

```
ThreatLens/
├── src/threatlens/
│   ├── __init__.py        # Package metadata
│   ├── __main__.py        # python -m threatlens entry point
│   ├── main.py            # CLI argument parsing and dispatch
│   ├── parser.py          # CSV/JSON loading and normalization
│   ├── features.py        # Feature extraction pipeline
│   ├── scorer.py          # Transparent weighted scoring engine
│   ├── mapper.py          # ATT&CK-style category mapping
│   ├── model.py           # Random Forest classifier wrapper
│   ├── analyzer.py        # Pipeline orchestrator
│   ├── reporter.py        # Terminal / JSON / Markdown report generation
│   └── utils.py           # Shared utilities
├── tests/
│   ├── conftest.py        # Shared pytest fixtures
│   ├── test_parser.py     # Data loading and normalization tests
│   ├── test_features.py   # Feature extraction tests
│   ├── test_scorer.py     # Scoring engine tests
│   ├── test_mapper.py     # ATT&CK mapping tests
│   ├── test_model.py      # ML classifier tests
│   ├── test_reporter.py   # Report generation tests
│   └── test_integration.py # End-to-end pipeline tests
├── sample_data/
│   ├── benign_events.csv      # 25 benign endpoint events
│   ├── mixed_events.csv       # 30 mixed benign + suspicious events
│   └── high_risk_events.csv   # 20 malicious-leaning events
├── docs/
│   ├── scoring.md             # Full scoring model documentation
│   └── attack_mapping.md      # ATT&CK mapping rules documentation
├── reports/                   # Generated reports (gitignored)
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Installation

**Prerequisites:** Python 3.9 or later.

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/ThreatLens.git
cd ThreatLens

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Install in editable mode (includes all dependencies)
pip install -e .

# 4. Or install just the dependencies
pip install -r requirements.txt
```

---

## Usage

```
threatlens --input <FILE> [options]

  -i, --input FILE          Path to event data file (.csv or .json)  [required]
  -o, --output-dir DIR      Directory for report files (default: reports/)
  -f, --format FORMAT       Output format: terminal | json | markdown | all (default: all)
  -n, --top N               Number of top events to show (default: 10)
      --min-score SCORE     Minimum risk score for terminal output (0–100, default: 0)
      --training-dir DIR    Directory with labeled CSVs for ML training
  -V, --version             Show version
  -h, --help                Show help
```

---

## Example Commands

**Analyze the high-risk dataset (best for demo):**
```bash
threatlens --input sample_data/high_risk_events.csv
```

**Analyze the mixed dataset, show top 15 events:**
```bash
threatlens --input sample_data/mixed_events.csv --top 15
```

**Show only suspicious/malicious events (score ≥ 51):**
```bash
threatlens --input sample_data/mixed_events.csv --min-score 51
```

**Generate only a JSON report:**
```bash
threatlens --input sample_data/high_risk_events.csv --format json
```

**Generate only a Markdown report:**
```bash
threatlens --input sample_data/high_risk_events.csv --format markdown
```

**Run as a Python module:**
```bash
python -m threatlens --input sample_data/high_risk_events.csv
```

---

## Example Output

```
╭────────────────────────────────────────────────────────────╮
│ ThreatLens v0.1.0  •  AI-Assisted Threat Prioritization    │
│ Input: high_risk_events.csv  •  Events: 20  •  2024-01-17  │
╰────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────╮
│      Event Summary by Risk Level        │
├──────────────┬────────┬─────────────────┤
│ Risk Level   │  Count │     Percentage  │
├──────────────┼────────┼─────────────────┤
│ MALICIOUS    │     18 │          90.0%  │
│ SUSPICIOUS   │      2 │          10.0%  │
│ LOW          │      0 │           0.0%  │
│ BENIGN       │      0 │           0.0%  │
╰──────────────┴────────┴─────────────────╯

╭─────────────────────────────────────────────────────────────────────────────────────╮
│ Event 1 — MALICIOUS (Score: 92.5/100)                                               │
│ Host: WORKSTATION-05  User: svc_backup  Process: powershell.exe                     │
│ Command: powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA=             │
│ ATT&CK: Command and Control                                                          │
│                                                                                     │
│ Risk level 'malicious' — 5 signal(s) triggered:                                     │
│   • Encoded/obfuscated command detected (common in PS attacks)                      │
│   • Outbound connection to external IP                                               │
│   • Destination port associated with C2 or bind shells                              │
│   • Process name is a known LOLBin or abuse target                                  │
│   • Command line contains high-risk pattern                                          │
╰─────────────────────────────────────────────────────────────────────────────────────╯
```

---

## Scoring Model

ThreatLens uses an **additive weighted scoring model** where each security
signal contributes a fixed, documented point value:

| Signal | Points |
|---|---|
| Encoded/obfuscated command | 30 |
| Privilege escalation indicator | 25 |
| Persistence mechanism detected | 20 |
| High failed-login count (≥10) | 20 |
| Suspicious destination port | 20 |
| Suspicious parent→child process chain | 15 |
| Suspicious command-line pattern | 15 |
| Moderate failed-login count (5–9) | 10 |
| External connection | 10 |
| Known LOLBin process | 10 |
| Discovery/recon tool | 5 |

The raw total is normalized to 0–100.  Full documentation in [docs/scoring.md](docs/scoring.md).

---

## Machine Learning Component

ThreatLens includes a **Random Forest classifier** (scikit-learn) that predicts
event severity (`benign` / `suspicious` / `malicious`) using the same
interpretable feature set as the scoring model.

Key design decisions:
- **Why Random Forest?** Robust to small datasets, supports `feature_importances_`
  for transparency, fast to train, and easy to explain in an interview.
- **Training data:** The labeled synthetic CSVs in `sample_data/` — no external
  data required.
- **Training happens at runtime** (< 1 second on the included dataset).
- **Evaluation:** A 25% hold-out set is used to report accuracy and a
  per-class precision/recall/F1 breakdown.
- **ML + scoring:** Both outputs are shown side-by-side, giving analysts
  two complementary perspectives on each event.

Full documentation in [docs/attack_mapping.md](docs/attack_mapping.md).

---

## ATT&CK-Style Mapping

Events are mapped to the most likely ATT&CK tactic using heuristic rules:

| Category | Key Signals |
|---|---|
| Command and Control | External connection + suspicious port or encoded payload |
| Exfiltration | External connection + bulk-copy / web-upload command |
| Privilege Escalation | `privilege_escalation_flag` set |
| Persistence | `persistence_flag` set |
| Credential Access | ≥5 failed login attempts |
| Lateral Movement | Remote execution tool (PsExec, WMI, RDP) |
| Discovery | Recon tool (whoami, net, ipconfig, systeminfo) |
| Execution | Encoded/obfuscated script or suspicious process chain |

Full documentation in [docs/attack_mapping.md](docs/attack_mapping.md).

---

## Running Tests

```bash
pip install pytest
pytest
```

The test suite includes:
- Unit tests for each pipeline module (parser, features, scorer, mapper, model, reporter)
- Integration tests covering the full end-to-end pipeline
- Error-handling tests for bad inputs

---

## Limitations

- **Synthetic data only.** The sample datasets are fully fake and sanitized.
  ThreatLens has not been validated against real-world SIEM data.
- **Small training set.** The ML model is trained on ~75 labeled events.
  Accuracy is reasonable for demonstration but would need a much larger dataset
  for production use.
- **No context-awareness.** The scoring model does not know which assets are
  critical, what time of day is "normal" for a user, or what the baseline
  is for a given environment.
- **Heuristic ATT&CK mapping.** The category mapper is rule-based and will not
  catch every technique or produce authoritative technique IDs.
- **Offline only.** By design, ThreatLens makes no network calls, uses no
  threat intelligence feeds, and does not integrate with SIEM platforms.

---

## Future Improvements

- **Larger, more diverse synthetic dataset** for improved ML generalization
- **SHAP values** for per-feature contribution explanations on the ML model
- **Baseline deviation scoring** (flag events that deviate from a user's norm)
- **JSON/STIX output** for integration with threat intelligence platforms
- **YAML-configurable rule weights** for easy environment-specific tuning
- **CSV export of scored events** for import into spreadsheets or SIEM

---

## Resume Relevance

- **Security Operations / SOC Analyst roles** — event triage, alert prioritization, ATT&CK framework familiarity
- **Security Engineering roles** — building detection logic, feature engineering from security telemetry
- **Data Science / ML Engineering in security** — applying ML to labeled security event data with transparent, explainable models
- **Python Engineering** — modular, well-documented, tested Python package design

---

## License

MIT — see [LICENSE](LICENSE).
