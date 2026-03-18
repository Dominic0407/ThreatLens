"""
main.py - CLI entry point for ThreatLens.

Usage examples:
    threatlens --input sample_data/high_risk_events.csv
    threatlens --input sample_data/mixed_events.csv --top 15 --min-score 30
    threatlens --input sample_data/benign_events.csv --format json
    threatlens --input sample_data/high_risk_events.csv --format all --output-dir reports/

Run `threatlens --help` for full usage.
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console

from threatlens import __version__
from threatlens.analyzer import run_analysis
from threatlens.reporter import (
    print_terminal_report,
    write_json_report,
    write_markdown_report,
)

console = Console()

# Default reports output directory (relative to CWD, created if absent).
DEFAULT_OUTPUT_DIR = Path("reports")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description=(
            "ThreatLens — AI-assisted threat prioritization engine.\n"
            "Analyzes synthetic security event data, scores events using a "
            "transparent rule-based model, applies lightweight ML classification, "
            "and maps events to ATT&CK-style behavior categories."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  threatlens --input sample_data/high_risk_events.csv\n"
            "  threatlens --input sample_data/mixed_events.csv --top 15\n"
            "  threatlens --input sample_data/benign_events.csv --format json\n"
            "  threatlens --input sample_data/high_risk_events.csv --format all\n"
            "\n"
            "Disclaimer:\n"
            "  ThreatLens is a portfolio demonstration tool that operates fully\n"
            "  offline on synthetic data. It is not a production SOC platform.\n"
        ),
    )

    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="FILE",
        help="Path to event data file (.csv or .json)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=str(DEFAULT_OUTPUT_DIR),
        metavar="DIR",
        help=f"Directory for report files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["terminal", "json", "markdown", "all"],
        default="all",
        help="Output format(s) to produce (default: all)",
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        metavar="N",
        help="Number of top events to display/include in reports (default: 10)",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="Minimum risk score (0–100) for events shown in terminal output (default: 0)",
    )
    parser.add_argument(
        "--training-dir",
        default=None,
        metavar="DIR",
        help=(
            "Directory with labeled CSV files for ML training. "
            "Defaults to sample_data/ in the project root."
        ),
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"ThreatLens {__version__}",
    )

    return parser


def main() -> None:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    training_dir = Path(args.training_dir) if args.training_dir else None

    # -- Validate input --------------------------------------------------------
    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file not found: {input_path}")
        sys.exit(1)

    if input_path.suffix.lower() not in {".csv", ".json"}:
        console.print(
            f"[bold red]Error:[/bold red] Unsupported file format '{input_path.suffix}'. "
            "Use .csv or .json"
        )
        sys.exit(1)

    # -- Run analysis ----------------------------------------------------------
    try:
        result = run_analysis(input_path, training_data_dir=training_dir)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
        sys.exit(1)

    # -- Produce outputs -------------------------------------------------------
    fmt = args.format
    top_n = args.top
    min_score = args.min_score

    if fmt in ("terminal", "all"):
        print_terminal_report(result, top_n=top_n, min_score=min_score)

    report_paths: list[Path] = []

    if fmt in ("json", "all"):
        json_path = write_json_report(result, output_dir)
        report_paths.append(json_path)

    if fmt in ("markdown", "all"):
        md_path = write_markdown_report(result, output_dir, top_n=top_n)
        report_paths.append(md_path)

    if report_paths:
        console.print("[bold green]Reports written:[/bold green]")
        for p in report_paths:
            console.print(f"  [cyan]{p}[/cyan]")
        console.print()


if __name__ == "__main__":
    main()
