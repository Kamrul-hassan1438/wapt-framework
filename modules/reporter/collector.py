"""
Report Data Collector
Pulls all scan findings from the database, computes statistics,
CVSS distributions, and builds a structured report data object
that all exporters (HTML, PDF, JSON, Markdown) consume.
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import Counter
from sqlalchemy import select
from loguru import logger

from db.database import AsyncSessionLocal
from db.models import Scan, Finding, Target, Severity, ScanStatus


# CVSS score → severity label mapping
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    if score >= 0.1:  return "low"
    return "info"


# Severity display order (most critical first)
SEVERITY_ORDER = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}

# Severity colours for charts and badges
SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high":     "#e74c3c",
    "medium":   "#e67e22",
    "low":      "#f1c40f",
    "info":     "#3498db",
}

# OWASP Top 10 2021 mapping
OWASP_MAP = {
    "sqli":                     "A03:2021 – Injection",
    "xss":                      "A03:2021 – Injection",
    "csrf_missing_token":       "A01:2021 – Broken Access Control",
    "idor":                     "A01:2021 – Broken Access Control",
    "default_credentials":      "A07:2021 – Identification and Authentication Failures",
    "no_account_lockout":       "A07:2021 – Identification and Authentication Failures",
    "username_enumeration":     "A07:2021 – Identification and Authentication Failures",
    "jwt_vulnerability":        "A07:2021 – Identification and Authentication Failures",
    "missing_security_header":  "A05:2021 – Security Misconfiguration",
    "weak_security_header":     "A05:2021 – Security Misconfiguration",
    "verbose_error_disclosure": "A05:2021 – Security Misconfiguration",
    "debug_endpoint_exposed":   "A05:2021 – Security Misconfiguration",
    "directory_listing":        "A05:2021 – Security Misconfiguration",
    "http_trace_enabled":       "A05:2021 – Security Misconfiguration",
    "exposed_service":          "A05:2021 – Security Misconfiguration",
    "info_disclosure_header":   "A05:2021 – Security Misconfiguration",
    "exposed_env_file":         "A02:2021 – Cryptographic Failures",
    "exposed_git":              "A02:2021 – Cryptographic Failures",
    "no_https_redirect":        "A02:2021 – Cryptographic Failures",
    "insecure_cookie":          "A02:2021 – Cryptographic Failures",
    "password_over_http":       "A02:2021 – Cryptographic Failures",
    "dns_zone_transfer":        "A05:2021 – Security Misconfiguration",
    "subdomain_takeover":       "A05:2021 – Security Misconfiguration",
    "domain_expired":           "A05:2021 – Security Misconfiguration",
    "secret_in_js":             "A02:2021 – Cryptographic Failures",
}


class ReportCollector:
    """
    Fetches scan data from the database and computes all
    statistics needed to render a complete pentest report.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def collect(self) -> Dict[str, Any]:
        """
        Main entry point — returns a fully populated report_data dict.
        This dict is passed directly to all report templates.
        """
        async with AsyncSessionLocal() as session:
            # Load scan record
            scan = await session.get(Scan, self.scan_id)
            if not scan:
                raise ValueError(f"Scan {self.scan_id} not found")

            # Load target
            target = await session.get(Target, scan.target_id)

            # Load all findings
            result = await session.execute(
                select(Finding)
                .where(Finding.scan_id == self.scan_id)
                .order_by(Finding.severity)
            )
            findings = result.scalars().all()

        # Build report data structure
        findings_list = [self._finding_to_dict(f) for f in findings]

        # Filter out false positives for the main report
        real_findings = [
            f for f in findings_list
            if not f["is_false_positive"]
        ]

        # Separate by type
        vuln_findings  = [f for f in real_findings if f["severity"] != "info"]
        info_findings  = [f for f in real_findings if f["severity"] == "info"]

        # Compute statistics
        stats = self._compute_stats(real_findings)

        # Duration
        duration_str = "N/A"
        if scan.started_at and scan.finished_at:
            delta = scan.finished_at - scan.started_at
            minutes, seconds = divmod(int(delta.total_seconds()), 60)
            duration_str = f"{minutes}m {seconds}s"

        report_data = {
            # Metadata
            "report_id":        f"WAPT-{self.scan_id[:8].upper()}",
            "generated_at":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "generated_at_iso": datetime.now(timezone.utc).isoformat(),
            "framework_version":"0.1.0",

            # Scan info
            "scan_id":          self.scan_id,
            "scan_type":        scan.scan_type.value if scan.scan_type else "unknown",
            "scan_status":      scan.status.value if scan.status else "unknown",
            "scan_started":     scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "N/A",
            "scan_finished":    scan.finished_at.strftime("%Y-%m-%d %H:%M UTC") if scan.finished_at else "N/A",
            "scan_duration":    duration_str,
            "modules_run":      scan.modules_run or [],

            # Target info
            "target_name":      target.name if target else "Unknown",
            "target_url":       target.url  if target else "Unknown",
            "target_description": target.description or "",
            "scope_notes":      target.scope_notes or "",

            # Findings
            "all_findings":     real_findings,
            "vuln_findings":    vuln_findings,
            "info_findings":    info_findings,
            "total_findings":   len(real_findings),

            # Statistics
            "stats":            stats,

            # Risk rating
            "overall_risk":     self._compute_overall_risk(stats),
            "risk_color":       self._risk_color(self._compute_overall_risk(stats)),

            # OWASP mapping
            "owasp_coverage":   self._compute_owasp_coverage(real_findings),

            # Colors (used in templates)
            "severity_colors":  SEVERITY_COLORS,
        }

        logger.success(
            f"[Report] Collected {len(real_findings)} findings for scan {self.scan_id}"
        )
        return report_data

    def _finding_to_dict(self, f: Finding) -> Dict[str, Any]:
        """Convert a Finding ORM object to a plain dict for templates."""
        return {
            "id":               f.id,
            "title":            f.title,
            "severity":         f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "severity_color":   SEVERITY_COLORS.get(
                                    f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                                    "#888"
                                ),
            "cvss_score":       f.cvss_score or 0.0,
            "vuln_type":        f.vuln_type,
            "url":              f.url,
            "parameter":        f.parameter,
            "payload_used":     f.payload_used,
            "evidence":         f.evidence,
            "description":      f.description,
            "remediation":      f.remediation,
            "references":       f.references or [],
            "is_false_positive":f.is_false_positive,
            "confirmed":        f.confirmed,
            "created_at":       f.created_at.strftime("%Y-%m-%d %H:%M") if f.created_at else "",
            "owasp":            OWASP_MAP.get(f.vuln_type, ""),
        }

    def _compute_stats(self, findings: List[Dict]) -> Dict[str, Any]:
        """Compute severity counts, CVSS averages, and type distributions."""
        counts = Counter(f["severity"] for f in findings)

        # Findings by type (top 10)
        type_counts = Counter(f["vuln_type"] for f in findings)

        # CVSS scores for average calculation
        cvss_scores = [f["cvss_score"] for f in findings if f["cvss_score"] > 0]
        avg_cvss    = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0
        max_cvss    = max(cvss_scores) if cvss_scores else 0.0

        # Affected URLs
        affected_urls = list({f["url"] for f in findings})

        return {
            "critical":      counts.get("critical", 0),
            "high":          counts.get("high",     0),
            "medium":        counts.get("medium",   0),
            "low":           counts.get("low",      0),
            "info":          counts.get("info",     0),
            "total":         len(findings),
            "confirmed":     sum(1 for f in findings if f["confirmed"]),
            "avg_cvss":      avg_cvss,
            "max_cvss":      round(max_cvss, 1),
            "affected_urls": len(affected_urls),
            "top_types":     type_counts.most_common(8),
            # Chart data (percentages for donut chart)
            "chart_data":    self._chart_data(counts, len(findings)),
        }

    def _chart_data(
        self, counts: Counter, total: int
    ) -> List[Dict]:
        """Build chart slice data for the severity donut chart."""
        if total == 0:
            return []
        data = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = counts.get(sev, 0)
            if count > 0:
                data.append({
                    "severity":   sev,
                    "count":      count,
                    "percentage": round(count / total * 100, 1),
                    "color":      SEVERITY_COLORS[sev],
                })
        return data

    def _compute_overall_risk(self, stats: Dict) -> str:
        """Compute an overall risk rating for the target."""
        if stats["critical"] > 0:
            return "CRITICAL"
        if stats["high"] > 3:
            return "HIGH"
        if stats["high"] > 0:
            return "HIGH"
        if stats["medium"] > 5:
            return "MEDIUM"
        if stats["medium"] > 0:
            return "MEDIUM"
        if stats["low"] > 0:
            return "LOW"
        return "INFORMATIONAL"

    def _risk_color(self, risk: str) -> str:
        return {
            "CRITICAL":      "#c0392b",
            "HIGH":          "#e74c3c",
            "MEDIUM":        "#e67e22",
            "LOW":           "#f1c40f",
            "INFORMATIONAL": "#3498db",
        }.get(risk, "#888")

    def _compute_owasp_coverage(
        self, findings: List[Dict]
    ) -> List[Dict]:
        """
        Group findings by OWASP Top 10 category.
        Returns a sorted list of OWASP categories found.
        """
        owasp_groups: Dict[str, List] = {}
        for f in findings:
            category = f.get("owasp", "")
            if category:
                owasp_groups.setdefault(category, [])
                owasp_groups[category].append(f)

        return [
            {
                "category": cat,
                "count":    len(items),
                "severity": max(items, key=lambda x: -SEVERITY_ORDER.get(
                                x["severity"], 99))["severity"],
            }
            for cat, items in sorted(owasp_groups.items())
        ]

        