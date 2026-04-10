"""
WHOIS Lookup Module
Retrieves domain registration data — ownership, registrar,
creation/expiry dates, and name servers.
An expiring domain is a critical finding — it can be sniped.
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from loguru import logger
import whois
from core.engine import BaseModule


class WHOISModule(BaseModule):
    name = "whois"
    description = "Domain registration and ownership lookup"

    # Warn if domain expires within this many days
    EXPIRY_WARNING_DAYS = 90

    async def run(self) -> List[dict]:
        findings = []
        domain = self._extract_domain()
        if not domain:
            return findings

        logger.info(f"[WHOIS] Looking up: {domain}")

        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._do_whois, domain)
        except Exception as e:
            logger.warning(f"[WHOIS] Lookup failed: {e}")
            return findings

        if not data:
            logger.warning("[WHOIS] No WHOIS data returned")
            return findings

        # Package the general WHOIS info
        findings.append(self._make_info_finding(domain, data))

        # Check for domain expiry risk
        expiry_finding = self._check_expiry(domain, data)
        if expiry_finding:
            findings.append(expiry_finding)

        # Check for privacy protection (no privacy = registrant info exposed)
        privacy_finding = self._check_privacy(domain, data)
        if privacy_finding:
            findings.append(privacy_finding)

        return findings

    def _extract_domain(self) -> Optional[str]:
        from urllib.parse import urlparse
        return urlparse(self.engine.target_url).hostname

    def _do_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Run the WHOIS query synchronously in a thread pool."""
        try:
            result = whois.whois(domain)
            return {
                "domain_name":    self._clean(result.domain_name),
                "registrar":      self._clean(result.registrar),
                "creation_date":  self._clean_date(result.creation_date),
                "expiration_date":self._clean_date(result.expiration_date),
                "updated_date":   self._clean_date(result.updated_date),
                "name_servers":   self._clean_list(result.name_servers),
                "status":         self._clean_list(result.status),
                "emails":         self._clean_list(result.emails),
                "org":            self._clean(result.org),
                "country":        self._clean(result.country),
                "dnssec":         self._clean(result.dnssec),
            }
        except Exception as e:
            logger.debug(f"[WHOIS] Raw error: {e}")
            return None

    def _clean(self, val) -> str:
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _clean_list(self, val) -> List[str]:
        if isinstance(val, list):
            return [str(v) for v in val if v]
        return [str(val)] if val else []

    def _clean_date(self, val) -> Optional[str]:
        if isinstance(val, list):
            val = val[0]
        if isinstance(val, datetime):
            return val.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(val) if val else None

    def _make_info_finding(self, domain: str, data: Dict) -> dict:
        lines = [f"WHOIS data for {domain}:\n"]
        fields = [
            ("Domain",      data.get("domain_name")),
            ("Registrar",   data.get("registrar")),
            ("Created",     data.get("creation_date")),
            ("Expires",     data.get("expiration_date")),
            ("Updated",     data.get("updated_date")),
            ("Org",         data.get("org")),
            ("Country",     data.get("country")),
            ("DNSSEC",      data.get("dnssec")),
            ("Name Servers",", ".join(data.get("name_servers", []))),
            ("Status",      ", ".join(data.get("status", [])[:3])),
            ("Contact Email",", ".join(data.get("emails", []))),
        ]
        for label, value in fields:
            if value:
                lines.append(f"  {label:<16}: {value}")

        return {
            "title": f"WHOIS Information — {domain}",
            "severity": "info",
            "vuln_type": "recon_whois",
            "url": self.engine.target_url,
            "description": "\n".join(lines),
            "evidence": str(data),
            "remediation": "Review for exposed contact data. Use WHOIS privacy protection.",
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    def _check_expiry(self, domain: str, data: Dict) -> Optional[dict]:
        """Warn if the domain expires soon — an expiring domain can be sniped."""
        expiry_str = data.get("expiration_date")
        if not expiry_str:
            return None

        try:
            from dateutil import parser as dateparser
            expiry = dateparser.parse(expiry_str.replace(" UTC", ""))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                return {
                    "title": f"CRITICAL: Domain {domain} Has EXPIRED",
                    "severity": "critical",
                    "vuln_type": "domain_expired",
                    "url": self.engine.target_url,
                    "description": (
                        f"The domain {domain} expired on {expiry_str}. "
                        f"Anyone can now register this domain and impersonate your organization, "
                        f"intercept email, or serve malware to users who visit it."
                    ),
                    "evidence": f"Expiration date: {expiry_str}",
                    "remediation": "Renew the domain immediately through your registrar.",
                    "cvss_score": 9.8,
                    "references": [],
                    "parameter": None, "payload_used": None,
                    "confirmed": True, "is_false_positive": False,
                }
            elif days_left <= self.EXPIRY_WARNING_DAYS:
                severity = "high" if days_left <= 30 else "medium"
                return {
                    "title": f"Domain Expiry Warning — {days_left} Days Remaining",
                    "severity": severity,
                    "vuln_type": "domain_expiry_soon",
                    "url": self.engine.target_url,
                    "description": (
                        f"The domain {domain} expires in {days_left} days ({expiry_str}). "
                        f"If not renewed, the domain can be registered by attackers who could "
                        f"serve malicious content, intercept email, or conduct phishing campaigns."
                    ),
                    "evidence": f"Expiration date: {expiry_str} ({days_left} days left)",
                    "remediation": (
                        "Renew the domain before expiry. Enable auto-renewal with your registrar. "
                        "Set calendar reminders 90, 30, and 7 days before expiry."
                    ),
                    "cvss_score": 7.5 if days_left <= 30 else 5.0,
                    "references": [],
                    "parameter": None, "payload_used": None,
                    "confirmed": True, "is_false_positive": False,
                }
        except Exception as e:
            logger.debug(f"[WHOIS] Could not parse expiry date: {e}")
        return None

    def _check_privacy(self, domain: str, data: Dict) -> Optional[dict]:
        """Check if registrant contact info is publicly exposed."""
        emails = data.get("emails", [])
        org = data.get("org", "")

        privacy_keywords = ["privacy", "redacted", "whoisproxy", "protect", "private"]
        is_protected = any(
            kw in str(emails).lower() or kw in org.lower()
            for kw in privacy_keywords
        )

        if emails and not is_protected:
            return {
                "title": "Registrant Contact Information Publicly Exposed",
                "severity": "low",
                "vuln_type": "whois_privacy",
                "url": self.engine.target_url,
                "description": (
                    f"The WHOIS record for {domain} exposes registrant contact details "
                    f"including email addresses: {', '.join(emails[:3])}. "
                    f"This information can be used for social engineering, spear phishing, "
                    f"and targeted attacks against domain administrators."
                ),
                "evidence": f"Exposed emails: {', '.join(emails)}",
                "remediation": (
                    "Enable WHOIS privacy protection with your domain registrar. "
                    "Most registrars offer this for free or a small annual fee."
                ),
                "cvss_score": 2.6,
                "references": [],
                "parameter": None, "payload_used": None,
                "confirmed": True, "is_false_positive": False,
            }
        return None