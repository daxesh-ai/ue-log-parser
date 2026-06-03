"""CLI interface for the log parser — works without PySide6."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="5G/4G UE Log Parser (QCAT-style)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  logparser-cli file.hdf                            # Print decoded messages
  logparser-cli file.hdf --csv out.csv              # Export to CSV
  logparser-cli file.hdf --filter NR_RRC            # Show only NR RRC messages
  logparser-cli file.hdf --failures                 # Show only failures/warnings
  logparser-cli file.hdf --recommendations          # Top 20 issues (colored text)
  logparser-cli file.hdf --recommendations --json   # Top 20 as JSON
  logparser-cli file.hdf --gui                      # Launch GUI (requires PySide6)
""",
    )
    parser.add_argument("files", nargs="+", type=Path,
                        help="Path(s) to .hdf log file(s). Multiple files are merged by timestamp.")
    parser.add_argument("--csv", type=Path, help="Export to CSV file")
    parser.add_argument("--filter", type=str, help="Filter by protocol (NR_RRC, LTE_RRC, NR_NAS, LTE_NAS)")
    parser.add_argument("--failures", action="store_true", help="Show only failures/warnings")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show decoded IE text")
    parser.add_argument("--recommendations", action="store_true",
                        help="Print Top 20 protocol issues with 3GPP parameter suggestions")
    parser.add_argument("--json", action="store_true",
                        help="Output recommendations as JSON (use with --recommendations)")
    parser.add_argument("--json-export", type=Path, metavar="OUT.json",
                        help="Export full session (messages + PHY/MAC data) to JSON")
    parser.add_argument("--report", type=Path, metavar="OUT.html",
                        help="Export Top-20 issues report (.html or .pdf)")
    parser.add_argument("--train-model", action="store_true",
                        help="Train ML anomaly model from provided session files")
    parser.add_argument("--dir", type=Path, metavar="DIR",
                        help="Batch mode: process all .hdf/.pcap files in DIR")

    args = parser.parse_args()

    if args.gui:
        from logparser.app import main as gui_main
        sys.argv = [sys.argv[0], str(args.file)]
        gui_main()
        return

    # Batch directory mode
    if getattr(args, "dir", None):
        _batch_dir(args)
        return

    # ML model training mode
    if getattr(args, "train_model", False):
        _train_ml_model(args)
        return

    for f in args.files:
        if not f.exists():
            print(f"Error: File not found: {f}", file=sys.stderr)
            sys.exit(1)

    from logparser.pipeline import load_file, load_files
    from logparser.core.enums import Severity

    if len(args.files) == 1:
        print(f"Loading {args.files[0].name}...", file=sys.stderr)
        session = load_file(args.files[0], progress_callback=_progress)
    else:
        names = ", ".join(f.name for f in args.files)
        print(f"Loading {len(args.files)} files: {names}...", file=sys.stderr)
        session = load_files(args.files, progress_callback=_progress)
    print(file=sys.stderr)  # Newline after progress

    # Recommendations output
    if args.recommendations:
        if args.json and not args.recommendations:
            print("Error: --json requires --recommendations", file=sys.stderr)
            sys.exit(1)
        from logparser.analysis.recommendations import analyze_session
        recs = analyze_session(session)
        if args.json:
            _print_recommendations_json(recs)
        else:
            _print_recommendations_text(recs, session)
        return

    # HTML/PDF report
    if getattr(args, "report", None):
        from logparser.analysis.recommendations import analyze_session
        from logparser.export.report_export import export_html_report, export_pdf_report
        recs = analyze_session(session)
        output = args.report
        if str(output).endswith(".pdf"):
            export_pdf_report(session, recs, output)
        else:
            if not str(output).endswith(".html"):
                output = output.with_suffix(".html")
            export_html_report(session, recs, output)
        print(f"Report saved to {output}")
        return

    # JSON full export
    if getattr(args, "json_export", None):
        from logparser.export.json_export import export_json
        export_json(session, args.json_export)
        print(f"Exported {len(session.messages)} messages to {args.json_export}")
        return

    # CSV export
    if args.csv:
        from logparser.export.csv_export import export_csv
        export_csv(session, args.csv)
        print(f"Exported {len(session.messages)} messages to {args.csv}")
        return

    # Filter
    messages = session.messages
    if args.filter:
        from logparser.core.enums import Protocol
        try:
            proto = Protocol[args.filter.upper()]
            messages = [m for m in messages if m.protocol == proto]
        except KeyError:
            print(f"Unknown protocol: {args.filter}", file=sys.stderr)
            print(f"Available: {', '.join(p.name for p in Protocol)}", file=sys.stderr)
            sys.exit(1)

    if args.failures:
        messages = [m for m in messages if m.severity in (Severity.FAILURE, Severity.WARNING)]

    # Print summary
    decoded = sum(1 for m in session.messages if m.decoded_tree is not None)
    total = len(session.messages)
    failures = sum(1 for m in session.messages if m.severity == Severity.FAILURE)
    warnings = sum(1 for m in session.messages if m.severity == Severity.WARNING)

    print(f"{'='*80}")
    print(f" {session.filename} — {total} messages, {100*decoded/max(1,total):.1f}% decoded")
    print(f" Failures: {failures} | Warnings: {warnings}")
    print(f"{'='*80}")
    print()

    # Print messages
    print(f"{'#':<5} {'Time':<13} {'Proto':<9} {'Dir':<4} {'Channel':<12} {'Summary'}")
    print(f"{'-'*5} {'-'*13} {'-'*9} {'-'*4} {'-'*12} {'-'*40}")

    for msg in messages:
        severity_marker = ""
        if msg.severity == Severity.FAILURE:
            severity_marker = " [FAIL]"
        elif msg.severity == Severity.WARNING:
            severity_marker = " [WARN]"

        ts = msg.timestamp.strftime("%H:%M:%S.%f")[:-3]
        print(
            f"{msg.index:<5} {ts:<13} {msg.protocol.name:<9} "
            f"{msg.direction.value:<4} {msg.channel:<12} "
            f"{msg.summary}{severity_marker}"
        )

        if args.verbose and msg.decoded_text:
            # Print first few lines of decoded text
            lines = msg.decoded_text.split("\n")[:10]
            for line in lines:
                print(f"      {line}")
            if len(msg.decoded_text.split("\n")) > 10:
                print(f"      ... ({len(msg.decoded_text)} chars total)")
            print()

    print(f"\n{'='*80}")
    print(f" Showing {len(messages)}/{total} messages")
    print(f"{'='*80}")


def _print_recommendations_text(recs, session) -> None:
    """Print Top 20 recommendations as formatted text with ANSI colors."""
    use_color = sys.stdout.isatty()
    RED = "\033[91m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    CYAN = "\033[96m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f"{BOLD} TOP {len(recs)} PROTOCOL ISSUES — {session.filename}{RESET}")
    print(f"{BOLD}{'='*80}{RESET}\n")

    if not recs:
        print(f"  {CYAN}No protocol issues detected.{RESET}\n")
        return

    for r in recs:
        color = RED if r.severity == "Critical" else (YELLOW if r.severity == "Major" else "")
        print(f"{color}{BOLD}#{r.rank:2d} [{r.severity.upper():8s}] [{r.category}] {r.issue}{RESET}")
        print(f"    Count: {r.count}  |  Parameters: {CYAN}{r.parameter}{RESET}")
        print(f"    Root Cause: {r.root_cause[:120]}{'...' if len(r.root_cause) > 120 else ''}")
        print(f"    Fix:")
        for line in r.recommendation.strip().split("\n"):
            print(f"      {line.strip()}")
        print()

    print(f"{BOLD}{'='*80}{RESET}")
    critical = sum(1 for r in recs if r.severity == "Critical")
    major = sum(1 for r in recs if r.severity == "Major")
    print(f" {RED}{critical} Critical{RESET}  {YELLOW}{major} Major{RESET}  {len(recs) - critical - major} Minor")
    print(f"{BOLD}{'='*80}{RESET}\n")


def _print_recommendations_json(recs) -> None:
    """Print recommendations as JSON."""
    import json
    output = []
    for r in recs:
        output.append({
            "rank": r.rank,
            "category": r.category,
            "issue": r.issue,
            "severity": r.severity,
            "count": r.count,
            "msg_indices": r.msg_indices[:20],
            "root_cause": r.root_cause,
            "recommendation": r.recommendation,
            "parameter": r.parameter,
        })
    print(json.dumps(output, indent=2))


def _train_ml_model(args):
    """Train ML anomaly detection model from provided session files."""
    from logparser.pipeline import load_file

    files = args.files
    if len(files) < 3:
        print("Error: Need at least 3 session files for training", file=sys.stderr)
        print("Usage: logparser-cli file1.hdf file2.hdf file3.hdf --train-model", file=sys.stderr)
        sys.exit(1)

    print(f"Training ML anomaly model from {len(files)} sessions...", file=sys.stderr)

    sessions = []
    for f in files:
        print(f"  Loading {f.name}...", file=sys.stderr, end=" ")
        try:
            session = load_file(f)
            sessions.append(session)
            print(f"{len(session.messages)} msgs ✓", file=sys.stderr)
        except Exception as e:
            print(f"SKIP ({e})", file=sys.stderr)

    if len(sessions) < 3:
        print(f"Error: Only {len(sessions)} sessions loaded (need ≥ 3)", file=sys.stderr)
        sys.exit(1)

    try:
        from logparser.analysis.ml_anomaly import train_model
        result = train_model(sessions)
        print(f"\n✓ Model trained on {result['n_sessions']} sessions", file=sys.stderr)
        print(f"  Features: {result['n_features']}", file=sys.stderr)
        print(f"  Saved to: {result['model_path']}", file=sys.stderr)
        print(f"\nML anomaly detection will now run automatically on future analyses.")
    except ImportError:
        print("Error: scikit-learn required for ML training", file=sys.stderr)
        print("Install with: pip install scikit-learn", file=sys.stderr)
        sys.exit(1)


def _batch_dir(args):
    """Process all supported files in a directory."""
    from logparser.pipeline import load_file
    from logparser.analysis.recommendations import analyze_session
    import json

    dir_path = args.dir
    if not dir_path.is_dir():
        print(f"Error: Not a directory: {dir_path}", file=sys.stderr)
        sys.exit(1)

    # Find all supported files
    extensions = (".hdf", ".pcap", ".pcapng")
    files = sorted(f for f in dir_path.rglob("*") if f.suffix.lower() in extensions and f.stat().st_size > 1000)

    if not files:
        print(f"No supported files found in {dir_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Batch processing {len(files)} files in {dir_path}...", file=sys.stderr)
    print()

    results = []
    for i, filepath in enumerate(files):
        print(f"[{i+1}/{len(files)}] {filepath.name}...", file=sys.stderr, end=" ")
        try:
            session = load_file(filepath)
            recs = analyze_session(session)
            critical = sum(1 for r in recs if r.severity == "Critical")
            major = sum(1 for r in recs if r.severity == "Major")
            print(f"{len(session.messages)} msgs, {len(recs)} issues ({critical}C/{major}M)", file=sys.stderr)
            results.append({
                "file": filepath.name,
                "messages": len(session.messages),
                "issues": len(recs),
                "critical": critical,
                "major": major,
                "top_issue": recs[0].issue if recs else "None",
            })
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            results.append({"file": filepath.name, "error": str(e)})

    # Output as JSON
    if getattr(args, "json", False):
        print(json.dumps(results, indent=2))
    else:
        print()
        print(f"{'File':<50} {'Msgs':>6} {'Issues':>7} {'Critical':>9}")
        print("-" * 80)
        for r in results:
            if "error" in r:
                print(f"{r['file']:<50} {'ERROR':<6} {r['error'][:30]}")
            else:
                print(f"{r['file']:<50} {r['messages']:>6} {r['issues']:>7} {r['critical']:>9}")


def _progress(current: int, total: int):
    pct = 100 * current / max(1, total)
    bar_len = 40
    filled = int(bar_len * current / max(1, total))
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r  [{bar}] {pct:.0f}% ({current}/{total})", end="", file=sys.stderr)


if __name__ == "__main__":
    main()
