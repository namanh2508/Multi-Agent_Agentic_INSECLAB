import json
import html
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import EvalReport, Finding
from core.enums import ASICategory, Severity


def _h(text: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


class ReportGenerator:
    """Generates evaluation reports in multiple formats."""

    def __init__(self, template_dir: Path | None = None):
        self.template_dir = template_dir or Path(__file__).parent.parent / "templates"

        if self.template_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(),
            )
        else:
            self.env = None

    def generate(
        self,
        report: EvalReport,
        output_format: str = "json",
        output_path: Path | str | None = None,
    ) -> str:
        """Generate a report.

        Args:
            report: The evaluation report
            output_format: Format ('json', 'markdown', 'html')
            output_path: Optional path to write the report

        Returns:
            Report content as string
        """
        if output_format == "json":
            content = self._generate_json(report)
        elif output_format == "markdown":
            content = self._generate_markdown(report)
        elif output_format == "html":
            content = self._generate_html(report)
        else:
            content = self._generate_json(report)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")

        return content

    def _generate_json(self, report: EvalReport) -> str:
        return json.dumps(report.model_dump(), indent=2, default=str)

    def _generate_markdown(self, report: EvalReport) -> str:
        lines = [
            f"# Security Evaluation Report",
            "",
            f"**Target ID**: {report.target_id}",
            f"**Generated**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S') if report.timestamp else 'N/A'}",
            "",
            "## Summary",
            "",
            f"- **Total Cases**: {report.total_cases}",
            f"- **Vulnerabilities Found**: {len(report.findings)}",
            "",
            "### By Category",
            "",
        ]

        for category in ASICategory:
            summary = report.category_summary.get(category)
            if summary:
                lines.append(f"**{category.value} ({category.display_name})**")
                lines.append(f"- Total: {summary.total_cases}")
                lines.append(f"- Vulnerable: {summary.vulnerable_count}")
                if summary.by_severity:
                    lines.append("- By Severity:")
                    for sev, count in summary.by_severity.items():
                        lines.append(f"  - {sev.value}: {count}")
                lines.append("")

        if report.findings:
            lines.extend([
                "## Findings",
                "",
            ])

            for i, finding in enumerate(report.findings, 1):
                lines.extend([
                    f"### {i}. {finding.category.value} - {finding.severity.value.upper()}",
                    "",
                    f"**Case ID**: {finding.attack_case_id}",
                    f"**Confidence**: {finding.confidence:.1%}",
                    f"**Vulnerable**: {finding.is_vulnerable}",
                    "",
                    f"**Explanation**: {finding.explanation}",
                    "",
                ])

                if finding.evidence:
                    lines.append("**Evidence**:")
                    for evidence in finding.evidence:
                        lines.append(f"- {evidence}")
                    lines.append("")

        return "\n".join(lines)

    def _generate_html(self, report: EvalReport) -> str:
        summary = report.get_summary()
        vulnerability_count = len(report.findings)

        metadata = report.metadata or {}
        target_profile = _h(metadata.get("target_profile", "unknown"))
        judge_provider = _h(metadata.get("judge_provider", "unknown"))
        model = _h(metadata.get("model", "unknown"))
        total_executed = metadata.get("total_executed", report.total_cases)
        report_id = _h(report.target_id)
        timestamp_str = report.timestamp.strftime('%Y-%m-%d %H:%M:%S') if report.timestamp else 'N/A'

        stats_total = _h(str(total_executed))
        stats_vuln = _h(str(vulnerability_count))
        stats_asi01 = _h(str(summary["categories"].get("ASI01", 0)))
        stats_asi02 = _h(str(summary["categories"].get("ASI02", 0)))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Evaluation Report - {report_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #f9fafb;
            color: #1f2937;
        }}
        .header {{
            background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
            color: white;
            padding: 2rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .stat-label {{
            color: #6b7280;
            font-size: 0.875rem;
        }}
        .finding {{
            background: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid #3b82f6;
        }}
        .severity-critical {{ border-left-color: #dc2626; }}
        .severity-high {{ border-left-color: #ea580c; }}
        .severity-medium {{ border-left-color: #ca8a04; }}
        .severity-low {{ border-left-color: #65a30d; }}
        .severity-info {{ border-left-color: #6b7280; }}
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #fef2f2; color: #dc2626; }}
        .badge-high {{ background: #fff7ed; color: #ea580c; }}
        .badge-medium {{ background: #fefce8; color: #ca8a04; }}
        .badge-low {{ background: #f7fee7; color: #65a30d; }}
        .badge-info {{ background: #f3f4f6; color: #6b7280; }}
        .evidence {{
            background: #f3f4f6;
            padding: 1rem;
            border-radius: 0.25rem;
            font-family: monospace;
            font-size: 0.875rem;
            white-space: pre-wrap;
        }}
        .metadata {{
            background: white;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            font-size: 0.875rem;
        }}
        .metadata-item {{
            display: inline-block;
            margin-right: 1.5rem;
        }}
        .metadata-label {{
            font-weight: 600;
            color: #374151;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Evaluation Report</h1>
        <p>Target: <strong>{report_id}</strong></p>
        <p>Generated: {timestamp_str}</p>
    </div>

    <div class="metadata">
        <div class="metadata-item"><span class="metadata-label">Target Profile:</span> {target_profile}</div>
        <div class="metadata-item"><span class="metadata-label">Model:</span> {model}</div>
        <div class="metadata-item"><span class="metadata-label">Judge Provider:</span> {judge_provider}</div>
        <div class="metadata-item"><span class="metadata-label">Total Executed:</span> {total_executed}</div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{stats_total}</div>
            <div class="stat-label">Total Cases</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats_vuln}</div>
            <div class="stat-label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats_asi01}</div>
            <div class="stat-label">Goal Hijacks (ASI01)</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats_asi02}</div>
            <div class="stat-label">Tool Misuses (ASI02)</div>
        </div>
    </div>
"""

        for finding in report.findings:
            severity_cls = _h(finding.severity.value)
            severity_class = f"severity-{severity_cls}"
            badge_class = f"badge-{severity_cls}"
            cat_val = _h(finding.category.value)
            cat_name = _h(finding.category.display_name)
            case_id = _h(finding.attack_case_id)
            conf = f"{finding.confidence:.1%}"
            explanation = _h(finding.explanation)

            html += f"""
    <div class="finding {severity_class}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <span class="severity-badge {badge_class}">{severity_cls}</span>
            <span style="color: #6b7280; font-size: 0.875rem;">Confidence: {conf}</span>
        </div>
        <h3 style="margin: 0 0 0.5rem 0;">
            <span style="color: #6b7280;">OWASP </span>{cat_val}
            <span style="color: #374151; font-size: 0.9em;">{cat_name}</span>
        </h3>
        <p style="color: #4b5563; margin: 0 0 1rem 0;">Case: {case_id}</p>
        <p>{explanation}</p>
"""
            if finding.evidence:
                html += """
        <h4 style="margin-bottom: 0.5rem;">Evidence:</h4>
        <div class="evidence">
"""
                for ev in finding.evidence:
                    ev_esc = _h(ev)
                    html += f"- {ev_esc}\n"
                html += """
        </div>
"""
            html += """
    </div>
"""

        html += """
</body>
</html>
"""
        return html
