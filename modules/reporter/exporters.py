"""
JSON and Markdown Report Exporters
JSON  — machine-readable, for SIEM/ticketing integration
Markdown — developer-friendly, for GitHub issues / wikis / Jira
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from loguru import logger

from modules.reporter.collector import ReportCollector


OUTPUT_DIR = Path("reports/output")


class JSONReportExporter:
    """
    Exports all findings as structured JSON.
    Useful for feeding into SIEM systems, Jira, or custom dashboards.
    """

    def __init__(self, scan_id: str, output_dir: Optional[Path] = None):
        self.scan_id    = scan_id
        self.output_dir = output_dir or OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self) -> Path:
        collector   = ReportCollector(self.scan_id)
        report_data = await collector.collect()

        # Build clean JSON structure
        export = {
            "report_metadata": {
                "report_id":         report_data["report_id"],
                "generated_at":      report_data["generated_at_iso"],
                "framework_version": report_data["framework_version"],
            },
            "scan": {
                "scan_id":    report_data["scan_id"],
                "scan_type":  report_data["scan_type"],
                "status":     report_data["scan_status"],
                "started_at": report_data["scan_started"],
                "finished_at":report_data["scan_finished"],
                "duration":   report_data["scan_duration"],
            },
            "target": {
                "name":        report_data["target_name"],
                "url":         report_data["target_url"],
                "description": report_data["target_description"],
            },
            "summary": {
                "overall_risk":   report_data["overall_risk"],
                "total_findings": report_data["total_findings"],
                "critical":       report_data["stats"]["critical"],
                "high":           report_data["stats"]["high"],
                "medium":         report_data["stats"]["medium"],
                "low":            report_data["stats"]["low"],
                "info":           report_data["stats"]["info"],
                "avg_cvss":       report_data["stats"]["avg_cvss"],
                "max_cvss":       report_data["stats"]["max_cvss"],
                "affected_urls":  report_data["stats"]["affected_urls"],
            },
            "owasp_coverage": report_data["owasp_coverage"],
            "findings": report_data["all_findings"],
        }

        filename = (
            f"WAPT-{self.scan_id[:8].upper()}-"
            f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        output_path = self.output_dir / filename
        output_path.write_text(
            json.dumps(export, indent=2, default=str),
            encoding="utf-8"
        )

        logger.success(f"[Reporter] JSON report saved: {output_path}")
        return output_path


class MarkdownReportExporter:
    """
    Exports findings as Markdown.
    Paste into GitHub issues, Confluence, Jira, or Notion.
    """

    def __init__(self, scan_id: str, output_dir: Optional[Path] = None):
        self.scan_id    = scan_id
        self.output_dir = output_dir or OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self) -> Path:
        collector   = ReportCollector(self.scan_id)
        d           = await collector.collect()

        lines = []

        # Header
        lines += [
            f"# Penetration Test Report — {d['report_id']}",
            f"",
            f"> **Target:** {d['target_name']} ({d['target_url']})  ",
            f"> **Scan Date:** {d['scan_started']}  ",
            f"> **Overall Risk:** {d['overall_risk']}  ",
            f"> **Generated:** {d['generated_at']}",
            f"",
        ]

        # Executive Summary
        lines += [
            f"## Executive Summary",
            f"",
            f"| Metric         | Value |",
            f"|----------------|-------|",
            f"| Total Findings | {d['total_findings']} |",
            f"| Critical       | {d['stats']['critical']} |",
            f"| High           | {d['stats']['high']} |",
            f"| Medium         | {d['stats']['medium']} |",
            f"| Low            | {d['stats']['low']} |",
            f"| Info           | {d['stats']['info']} |",
            f"| Max CVSS       | {d['stats']['max_cvss']} |",
            f"| Avg CVSS       | {d['stats']['avg_cvss']} |",
            f"| Overall Risk   | **{d['overall_risk']}** |",
            f"",
        ]

        # OWASP Coverage
        if d["owasp_coverage"]:
            lines += [
                "## OWASP Top 10 Coverage",
                "",
                "| Category | Findings | Severity |",
                "|----------|----------|----------|",
            ]
            for item in d["owasp_coverage"]:
                lines.append(
                    f"| {item['category']} | {item['count']} | {item['severity'].upper()} |"
                )
            lines.append("")

        # Vulnerability Findings
        lines += ["## Vulnerability Findings", ""]
        severity_order = ["critical", "high", "medium", "low"]

        for sev in severity_order:
            sev_findings = [
                f for f in d["vuln_findings"]
                if f["severity"] == sev
            ]
            if not sev_findings:
                continue

            emoji = {
                "critical": "🔴",
                "high":     "🟠",
                "medium":   "🟡",
                "low":      "🔵",
            }.get(sev, "⚪")

            lines += [
                f"### {emoji} {sev.upper()} ({len(sev_findings)} findings)",
                "",
            ]

            for i, f in enumerate(sev_findings, 1):
                lines += [
                    f"#### {i}. {f['title']}",
                    f"",
                    f"| Field      | Value |",
                    f"|------------|-------|",
                    f"| **Severity** | {f['severity'].upper()} |",
                    f"| **CVSS**   | {f['cvss_score']} |",
                    f"| **URL**    | `{f['url']}` |",
                ]
                if f.get("parameter"):
                    lines.append(f"| **Parameter** | `{f['parameter']}` |")
                if f.get("owasp"):
                    lines.append(f"| **OWASP**  | {f['owasp']} |")
                lines.append("")

                if f.get("description"):
                    lines += [
                        "**Description**",
                        "",
                        f.get("description", ""),
                        "",
                    ]

                if f.get("payload_used"):
                    lines += [
                        "**Payload Used**",
                        "",
                        f"```",
                        f.get("payload_used", ""),
                        f"```",
                        "",
                    ]

                if f.get("evidence"):
                    lines += [
                        "**Evidence**",
                        "",
                        f"```",
                        str(f.get("evidence", ""))[:500],
                        f"```",
                        "",
                    ]

                if f.get("remediation"):
                    lines += [
                        "**Remediation**",
                        "",
                        f"> {f.get('remediation', '').replace(chr(10), chr(10) + '> ')}",
                        "",
                    ]

                if f.get("references"):
                    lines += ["**References**", ""]
                    for ref in f["references"]:
                        lines.append(f"- {ref}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # Informational findings summary table
        if d["info_findings"]:
            lines += [
                "## Informational Findings",
                "",
                "| Title | Type | URL |",
                "|-------|------|-----|",
            ]
            for f in d["info_findings"]:
                url_short = f["url"][:60] + "…" if len(f["url"]) > 60 else f["url"]
                lines.append(
                    f"| {f['title']} | `{f['vuln_type']}` | {url_short} |"
                )
            lines.append("")

        # Remediation priority table
        lines += [
            "## Remediation Priority",
            "",
            "| # | Finding | Severity | CVSS | Parameter |",
            "|---|---------|----------|------|-----------|",
        ]
        for i, f in enumerate(d["vuln_findings"], 1):
            lines.append(
                f"| {i} | {f['title']} | {f['severity'].upper()} | "
                f"{f['cvss_score'] or '—'} | `{f.get('parameter') or '—'}` |"
            )
        lines.append("")

        # Footer
        lines += [
            "---",
            f"*Generated by WAPT Framework v{d['framework_version']} "
            f"— {d['generated_at']} — {d['report_id']}*",
        ]

        # Write file
        filename = (
            f"WAPT-{self.scan_id[:8].upper()}-"
            f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        )
        output_path = self.output_dir / filename
        output_path.write_text("\n".join(lines), encoding="utf-8")

        logger.success(f"[Reporter] Markdown report saved: {output_path}")
        return output_path
    
    