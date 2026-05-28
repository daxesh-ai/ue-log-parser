"""HTML/PDF Top-20 Protocol Issues Report.

Generates a self-contained HTML report with inline CSS (dark-mode).
PDF requires: pip install weasyprint
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from logparser.core.session import LogSession


_SEVERITY_COLORS = {
    "Critical": "#f44336",
    "Major":    "#ff9800",
    "Minor":    "#ffc107",
}

_CATEGORY_COLORS = {
    "RRC":   "#42a5f5",
    "NAS":   "#ab47bc",
    "HO":    "#66bb6a",
    "Voice": "#26c6da",
    "CA":    "#ffa726",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Menlo', 'Consolas', monospace; background: #121212; color: #ddd; padding: 24px; }
h1 { font-size: 22px; color: #fff; margin-bottom: 4px; }
.subtitle { color: #888; font-size: 12px; margin-bottom: 20px; }
.summary-row { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
.badge { padding: 8px 16px; border-radius: 6px; font-size: 14px; font-weight: bold; color: #fff; }
.badge.critical { background: #c62828; }
.badge.major    { background: #e65100; }
.badge.minor    { background: #f9a825; color: #111; }
.badge.ok       { background: #2e7d32; }
.meta-table { border-collapse: collapse; margin-bottom: 24px; font-size: 12px; }
.meta-table td { padding: 4px 16px 4px 0; color: #aaa; }
.meta-table td:first-child { color: #666; width: 160px; }
table.issues { width: 100%; border-collapse: collapse; margin-bottom: 32px; font-size: 12px; }
table.issues th { background: #1e1e1e; color: #888; text-align: left; padding: 8px 10px;
                  border-bottom: 1px solid #333; font-weight: normal; text-transform: uppercase; font-size: 10px; }
table.issues td { padding: 8px 10px; border-bottom: 1px solid #222; vertical-align: top; }
table.issues tr:hover td { background: #1a1a1a; }
.rank { color: #555; width: 32px; }
.sev { font-weight: bold; font-size: 11px; }
.cat { font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 3px; background: #2a2a2a; }
.param { color: #80cbc4; font-size: 10px; }
.count { color: #888; }
details { margin-top: 4px; }
details summary { cursor: pointer; color: #42a5f5; font-size: 11px; user-select: none; }
details summary:hover { color: #90caf9; }
.detail-box { background: #1a1a1a; border-left: 3px solid #333; padding: 10px 14px;
              margin-top: 6px; border-radius: 0 4px 4px 0; font-size: 11px; line-height: 1.6; }
.detail-box .label { color: #666; font-size: 10px; text-transform: uppercase; margin-bottom: 4px; margin-top: 10px; }
.detail-box .label:first-child { margin-top: 0; }
.detail-box pre { white-space: pre-wrap; color: #bbb; }
footer { color: #444; font-size: 10px; margin-top: 40px; border-top: 1px solid #222; padding-top: 12px; }
"""


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def export_html_report(
    session: LogSession,
    recs: list,
    output_path: Path,
) -> None:
    """Write a self-contained HTML report to output_path."""
    html = _build_html(session, recs)
    output_path.write_text(html, encoding="utf-8")


def export_pdf_report(
    session: LogSession,
    recs: list,
    output_path: Path,
) -> None:
    """Write a PDF report using weasyprint."""
    try:
        import weasyprint
    except ImportError:
        raise RuntimeError(
            "PDF export requires weasyprint.\n"
            "Install with:  pip3 install weasyprint"
        )
    html = _build_html(session, recs)
    weasyprint.HTML(string=html).write_pdf(str(output_path))


def _build_html(session: LogSession, recs: list) -> str:
    critical = sum(1 for r in recs if r.severity == "Critical")
    major    = sum(1 for r in recs if r.severity == "Major")
    minor    = sum(1 for r in recs if r.severity == "Minor")
    total    = len(recs)
    decoded  = sum(1 for m in session.messages if m.decoded_tree is not None)
    pct      = 100 * decoded // max(1, len(session.messages))
    source_files = getattr(session, "source_files", [])
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── header ─────────────────────────────────────────────────────────────
    file_display = session.filename
    if source_files:
        file_display += f" ({len(source_files)} files merged)"

    meta_rows = [
        ("File", _html_escape(file_display)),
        ("Messages", f"{len(session.messages):,}"),
        ("Decoded", f"{decoded:,} ({pct}%)"),
        ("PHY Samples", f"{len(getattr(session, 'phy_measurements', [])):,}"),
        ("MAC DL Samples", f"{len(getattr(session, 'mac_dl_samples', [])):,}"),
        ("Generated", gen_time),
    ]
    harq = getattr(session, "harq_samples", [])
    if harq:
        ack = sum(s.ack_count for s in harq)
        nack = sum(s.nack_count for s in harq)
        bler = nack / (ack + nack) * 100 if (ack + nack) > 0 else 0
        meta_rows.append(("DL HARQ BLER", f"{bler:.2f}%"))

    meta_html = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in meta_rows
    )

    # ── summary badges ──────────────────────────────────────────────────────
    if total == 0:
        badges = '<span class="badge ok">No Issues Detected</span>'
    else:
        badges = ""
        if critical:
            badges += f'<span class="badge critical">{critical} Critical</span>'
        if major:
            badges += f'<span class="badge major">{major} Major</span>'
        if minor:
            badges += f'<span class="badge minor">{minor} Minor</span>'

    # ── issues table ────────────────────────────────────────────────────────
    rows_html = ""
    for r in recs:
        sev_color = _SEVERITY_COLORS.get(r.severity, "#888")
        cat_color = _CATEGORY_COLORS.get(r.category, "#555")
        sev_html = f'<span class="sev" style="color:{sev_color}">{r.severity}</span>'
        cat_html = f'<span class="cat" style="color:{cat_color}">{r.category}</span>'
        param_html = f'<span class="param">{_html_escape(r.parameter)}</span>'
        detail = (
            f'<details><summary>Details</summary>'
            f'<div class="detail-box">'
            f'<div class="label">Root Cause</div>'
            f'<pre>{_html_escape(r.root_cause)}</pre>'
            f'<div class="label">Recommendation</div>'
            f'<pre>{_html_escape(r.recommendation)}</pre>'
            f'<div class="label">3GPP Parameters</div>'
            f'<pre style="color:#80cbc4">{_html_escape(r.parameter)}</pre>'
            f'</div></details>'
        )
        rows_html += (
            f"<tr>"
            f"<td class='rank'>#{r.rank}</td>"
            f"<td>{cat_html}</td>"
            f"<td>{sev_html}</td>"
            f"<td>{_html_escape(r.issue)}{detail}</td>"
            f"<td class='count'>{r.count:,}</td>"
            f"<td>{param_html}</td>"
            f"</tr>"
        )

    if not rows_html:
        rows_html = (
            "<tr><td colspan='6' style='text-align:center;color:#555;padding:24px'>"
            "No protocol issues detected</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Protocol Analysis Report — {_html_escape(session.filename)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>Protocol Analysis Report</h1>
<p class="subtitle">5G/4G Log Parser — QCAT-style Protocol Analyzer</p>

<table class="meta-table"><tbody>{meta_html}</tbody></table>

<div class="summary-row">{badges}</div>

<table class="issues">
<thead><tr>
  <th>#</th><th>Category</th><th>Severity</th>
  <th>Issue</th><th>Count</th><th>3GPP Parameter</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>

<footer>Generated {gen_time} by 5G/4G Log Parser &mdash;
{total} issue{'s' if total != 1 else ''} found in {len(session.messages):,} messages</footer>
</body>
</html>"""
