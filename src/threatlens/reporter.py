"""
reporter.py - Report generation for ThreatLens.

Produces three output formats from an AnalysisResult:
  1. Terminal summary  – rich-formatted tables and panels
  2. JSON report       – machine-readable structured output
  3. Markdown report   – analyst-friendly readable document

All report files are written to the specified output directory.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatlens.analyzer import AnalysisResult
from threatlens.utils import severity_color, truncate, ensure_dir

# Number of top events shown in terminal / report summaries.
TOP_N_DEFAULT = 10

console = Console()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_terminal_report(
    result: AnalysisResult,
    top_n: int = TOP_N_DEFAULT,
    min_score: float = 0.0,
) -> None:
    """Print a rich-formatted analysis summary to the terminal."""
    df = result.results
    filtered = df[df["risk_score"] >= min_score]

    _print_header(result)
    _print_summary_table(result, df)
    _print_top_events_table(filtered, top_n)

    if result.ml_trained:
        _print_ml_summary(result)

    _print_footer(result)


def write_json_report(
    result: AnalysisResult,
    output_dir: Path,
) -> Path:
    """
    Write a JSON report and return its path.

    The JSON contains a summary block plus a per-event array.
    """
    ensure_dir(output_dir)
    timestamp = _report_timestamp()
    stem = result.input_path.stem
    out_path = output_dir / f"threatlens_{stem}_{timestamp}.json"

    payload = _build_json_payload(result)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    return out_path


def write_markdown_report(
    result: AnalysisResult,
    output_dir: Path,
    top_n: int = TOP_N_DEFAULT,
) -> Path:
    """
    Write a Markdown report and return its path.
    """
    ensure_dir(output_dir)
    timestamp = _report_timestamp()
    stem = result.input_path.stem
    out_path = output_dir / f"threatlens_{stem}_{timestamp}.md"

    content = _build_markdown(result, top_n)
    out_path.write_text(content, encoding="utf-8")

    return out_path


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

def _print_header(result: AnalysisResult) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]ThreatLens v{result.version}[/bold cyan]  •  "
            f"AI-Assisted Threat Prioritization Engine\n"
            f"[dim]Input:[/dim] {result.input_path.name}  •  "
            f"[dim]Events:[/dim] {result.total_events}  •  "
            f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            border_style="cyan",
        )
    )


def _print_summary_table(result: AnalysisResult, df: pd.DataFrame) -> None:
    counts = df["risk_level"].value_counts().to_dict()
    total = len(df)

    table = Table(
        title="[bold]Event Summary by Risk Level[/bold]",
        box=box.ROUNDED,
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("Risk Level", style="bold", width=16)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Percentage", justify="right", width=12)

    for level in ["malicious", "suspicious", "low", "benign"]:
        count = counts.get(level, 0)
        pct = f"{(count / total * 100):.1f}%" if total > 0 else "0.0%"
        color = severity_color(level)
        table.add_row(
            f"[{color}]{level.upper()}[/{color}]",
            str(count),
            pct,
        )

    console.print()
    console.print(table)


def _print_top_events_table(df: pd.DataFrame, top_n: int) -> None:
    top = df.head(top_n)
    if top.empty:
        console.print("[yellow]No events meet the minimum score threshold.[/yellow]")
        return

    table = Table(
        title=f"[bold]Top {min(top_n, len(top))} Highest-Priority Events[/bold]",
        box=box.ROUNDED,
        header_style="bold white",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", justify="right", width=4, style="dim")
    table.add_column("Score", justify="right", width=7)
    table.add_column("Risk Level", width=12)
    table.add_column("ML Prediction", width=13)
    table.add_column("Hostname", width=16)
    table.add_column("Process", width=18)
    table.add_column("ATT&CK Category", width=22)
    table.add_column("Key Signal", width=36)

    for rank, (_, row) in enumerate(top.iterrows(), start=1):
        color = severity_color(str(row["risk_level"]))
        ml_color = severity_color(str(row["ml_prediction"]))
        # Pull first bullet from explanation as the key signal.
        key_signal = _first_signal(str(row.get("explanation", "")))
        table.add_row(
            str(rank),
            f"[{color}]{row['risk_score']:.1f}[/{color}]",
            f"[{color}]{str(row['risk_level']).upper()}[/{color}]",
            f"[{ml_color}]{str(row['ml_prediction']).upper()}[/{ml_color}]",
            truncate(str(row["hostname"]), 16),
            truncate(str(row["process_name"]), 18),
            str(row["attack_category"]),
            truncate(key_signal, 36),
        )

    console.print()
    console.print(table)

    # Print detailed explanations for malicious-level events.
    malicious_rows = df[df["risk_level"] == "malicious"].head(top_n)
    if not malicious_rows.empty:
        console.print()
        console.print("[bold red]Malicious-Level Event Details[/bold red]")
        for i, (_, row) in enumerate(malicious_rows.iterrows(), start=1):
            console.print(
                Panel(
                    f"[bold]Host:[/bold] {row['hostname']}  "
                    f"[bold]User:[/bold] {row['username']}  "
                    f"[bold]Process:[/bold] {row['process_name']}\n"
                    f"[bold]Command:[/bold] {truncate(str(row['command_line']), 120)}\n\n"
                    f"[bold]Score:[/bold] {row['risk_score']:.1f}/100  "
                    f"[bold]ATT&CK:[/bold] {row['attack_category']}\n\n"
                    f"{row['explanation']}",
                    title=f"[red]Event {i}[/red]",
                    border_style="red",
                )
            )


def _print_ml_summary(result: AnalysisResult) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold]Random Forest Classifier — Training Summary[/bold]\n\n"
            f"[dim]Hold-out accuracy:[/dim] [cyan]{result.model_accuracy:.1%}[/cyan]\n\n"
            f"[bold]Top Feature Importances:[/bold]\n"
            + "\n".join(
                f"  • {feat}: {imp:.3f}"
                for feat, imp in result.model_top_features
            )
            + f"\n\n[dim italic]Full evaluation report available in the JSON output.[/dim italic]",
            title="[cyan]ML Model Summary[/cyan]",
            border_style="cyan",
        )
    )


def _print_footer(result: AnalysisResult) -> None:
    console.print()
    console.print(
        "[dim]ThreatLens operates fully offline on synthetic/sanitized data. "
        "Not for production SOC use. See README for limitations.[/dim]"
    )
    console.print()


def _first_signal(explanation: str) -> str:
    """Extract the first bullet point from an explanation string."""
    for line in explanation.splitlines():
        stripped = line.strip()
        if stripped.startswith("•"):
            return stripped[1:].strip()
    return explanation.splitlines()[0] if explanation else "—"


# ---------------------------------------------------------------------------
# JSON report helpers
# ---------------------------------------------------------------------------

def _build_json_payload(result: AnalysisResult) -> dict:
    """Build the full JSON report structure."""
    df = result.results
    counts = df["risk_level"].value_counts().to_dict()

    return {
        "meta": {
            "tool": "ThreatLens",
            "version": result.version,
            "generated_at": datetime.now().isoformat(),
            "input_file": str(result.input_path),
            "total_events": result.total_events,
        },
        "summary": {
            "risk_level_counts": {
                "malicious": counts.get("malicious", 0),
                "suspicious": counts.get("suspicious", 0),
                "low": counts.get("low", 0),
                "benign": counts.get("benign", 0),
            },
            "ml_trained": result.ml_trained,
            "ml_accuracy": round(result.model_accuracy, 4) if result.ml_trained else None,
            "ml_top_features": [
                {"feature": f, "importance": round(i, 4)}
                for f, i in result.model_top_features
            ],
        },
        "ml_eval_report": result.model_eval_report if result.ml_trained else None,
        "events": _events_to_records(df),
    }


def _events_to_records(df: pd.DataFrame) -> list[dict]:
    """Convert results DataFrame to a list of dicts for JSON serialization."""
    records = []
    for _, row in df.iterrows():
        records.append({
            "timestamp": str(row["timestamp"]),
            "hostname": str(row["hostname"]),
            "username": str(row["username"]),
            "source_ip": str(row["source_ip"]),
            "destination_ip": str(row["destination_ip"]),
            "destination_port": int(row["destination_port"]),
            "process_name": str(row["process_name"]),
            "command_line": str(row["command_line"]),
            "event_type": str(row["event_type"]),
            "failed_logins": int(row["failed_logins"]),
            "risk_score": float(row["risk_score"]),
            "risk_level": str(row["risk_level"]),
            "ml_prediction": str(row["ml_prediction"]),
            "ml_confidence": float(row["ml_confidence"]),
            "attack_category": str(row["attack_category"]),
            "category_reason": str(row["category_reason"]),
            "explanation": str(row["explanation"]),
            "severity_label": str(row.get("severity_label", "")),
        })
    return records


# ---------------------------------------------------------------------------
# Markdown report helpers
# ---------------------------------------------------------------------------

def _build_markdown(result: AnalysisResult, top_n: int) -> str:
    df = result.results
    counts = df["risk_level"].value_counts().to_dict()
    total = len(df)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# ThreatLens Analysis Report",
        "",
        f"**Generated:** {now}  ",
        f"**Tool version:** ThreatLens v{result.version}  ",
        f"**Input file:** `{result.input_path.name}`  ",
        f"**Events analyzed:** {total}  ",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Risk Level | Count | Percentage |",
        "|---|---|---|",
    ]
    for level in ["malicious", "suspicious", "low", "benign"]:
        count = counts.get(level, 0)
        pct = f"{(count / total * 100):.1f}%" if total > 0 else "0.0%"
        lines.append(f"| {level.upper()} | {count} | {pct} |")

    lines += [
        "",
        "---",
        "",
        f"## Top {top_n} High-Priority Events",
        "",
        "| # | Score | Risk Level | ML Prediction | Hostname | Process | ATT&CK Category |",
        "|---|---|---|---|---|---|---|",
    ]

    top = df.head(top_n)
    for rank, (_, row) in enumerate(top.iterrows(), start=1):
        lines.append(
            f"| {rank} | {row['risk_score']:.1f} | {str(row['risk_level']).upper()} "
            f"| {str(row['ml_prediction']).upper()} "
            f"| {row['hostname']} | {row['process_name']} "
            f"| {row['attack_category']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Detailed Event Analysis",
        "",
    ]

    high_priority = df[df["risk_level"].isin(["malicious", "suspicious"])].head(top_n)
    if high_priority.empty:
        lines.append("*No suspicious or malicious events detected.*")
    else:
        for rank, (_, row) in enumerate(high_priority.iterrows(), start=1):
            lines += [
                f"### Event {rank} — {str(row['risk_level']).upper()} "
                f"(Score: {row['risk_score']:.1f}/100)",
                "",
                f"- **Timestamp:** {row['timestamp']}",
                f"- **Host:** {row['hostname']}  |  **User:** {row['username']}",
                f"- **Source IP:** {row['source_ip']}  →  "
                f"**Dest IP:** {row['destination_ip']}:{row['destination_port']}",
                f"- **Process:** `{row['process_name']}`  "
                f"(parent: `{row['parent_process']}`)",
                f"- **Command:** `{truncate(str(row['command_line']), 200)}`",
                f"- **Failed Logins:** {row['failed_logins']}",
                f"- **ATT&CK Category:** {row['attack_category']}",
                f"- **ML Prediction:** {str(row['ml_prediction']).upper()} "
                f"(confidence: {float(row['ml_confidence']):.1%})",
                "",
                "**Why this event was flagged:**",
                "",
                f"```",
                str(row["explanation"]),
                f"```",
                "",
            ]

    if result.ml_trained:
        lines += [
            "---",
            "",
            "## ML Model Summary",
            "",
            f"- **Model:** Random Forest Classifier (scikit-learn)",
            f"- **Hold-out accuracy:** {result.model_accuracy:.1%}",
            f"- **Training data:** labeled events from `sample_data/`",
            "",
            "**Top feature importances:**",
            "",
        ]
        for feat, imp in result.model_top_features:
            lines.append(f"- `{feat}`: {imp:.3f}")

        if result.model_eval_report:
            lines += [
                "",
                "**Classification report (held-out evaluation set):**",
                "",
                "```",
                result.model_eval_report.strip(),
                "```",
                "",
            ]

    lines += [
        "---",
        "",
        "## Limitations",
        "",
        "- Trained on a small synthetic dataset for demonstration purposes.",
        "- Not validated against real-world threat data.",
        "- ATT&CK category mapping is heuristic, not authoritative.",
        "- Should not be used as a sole detection mechanism in a production SOC.",
        "",
        "*ThreatLens is a portfolio project demonstrating transparent threat "
        "prioritization using rule-based scoring and lightweight machine learning.*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def _report_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
