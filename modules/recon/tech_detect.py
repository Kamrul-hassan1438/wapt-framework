"""
Technology Detection Module
Fingerprints the web stack by inspecting HTTP headers,
cookies, and response body patterns against a signature database.
"""
import re
import yaml
import httpx
from pathlib import Path
from typing import List, Dict, Any, Optional
from loguru import logger
from core.engine import BaseModule


class TechDetectModule(BaseModule):
    """
    Identifies the technologies powering the target:
    web server, backend language, framework, CMS, CDN, WAF.
    This intelligence shapes which vulnerability modules to prioritize.
    """
    name = "tech_detect"
    description = "Technology fingerprinting via headers, cookies, and body patterns"

    def __init__(self, engine):
        super().__init__(engine)
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Dict]:
        path = Path("payloads/tech_signatures.yaml")
        if not path.exists():
            logger.warning("[TechDetect] Signature file not found")
            return []
        data = yaml.safe_load(path.read_text())
        return data.get("signatures", [])

    async def run(self) -> List[dict]:
        findings = []
        target = self.engine.target_url
        logger.info(f"[TechDetect] Fingerprinting: {target}")

        # Fetch the target page
        response_data = await self._fetch_target(target)
        if not response_data:
            logger.warning("[TechDetect] Could not fetch target — skipping")
            return findings

        headers    = response_data["headers"]
        cookies    = response_data["cookies"]
        body       = response_data["body"]
        status     = response_data["status_code"]
        final_url  = response_data["final_url"]

        logger.debug(f"[TechDetect] Response: HTTP {status}, body length: {len(body)}")

        # Run detection against all signatures
        detected = self._match_signatures(headers, cookies, body)

        # Categorize by type
        categorized: Dict[str, List[str]] = {}
        for tech in detected:
            cat = tech["category"]
            categorized.setdefault(cat, [])
            categorized[cat].append(f"{tech['name']} (confidence: {tech['confidence']}%)")

        if detected:
            findings.append(self._make_tech_finding(target, categorized, headers, status))
            logger.success(f"[TechDetect] Identified {len(detected)} technologies")

            # Check for WAF detection — affects how we run later modules
            waf_techs = [t for t in detected if t["category"] == "waf"]
            if waf_techs:
                waf_names = [t["name"] for t in waf_techs]
                findings.append(self._make_waf_finding(target, waf_names))

            # Check for information leakage in headers
            header_findings = self._check_header_leakage(headers, target)
            findings.extend(header_findings)

        else:
            logger.info("[TechDetect] No technologies identified from signatures")

        # Check robots.txt and sitemap for extra recon
        robot_finding = await self._check_robots(target)
        if robot_finding:
            findings.append(robot_finding)

        return findings

    async def _fetch_target(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch the target URL and return response data."""
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.config.scan.user_agents[0]}
            ) as client:
                resp = await client.get(url)
                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "cookies": {k: v for k, v in resp.cookies.items()},
                    "body": resp.text[:50000],  # limit body size
                    "final_url": str(resp.url),
                }
        except Exception as e:
            logger.error(f"[TechDetect] Fetch failed: {e}")
            return None

    def _match_signatures(
        self,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body: str
    ) -> List[Dict]:
        """
        Match response data against all signatures.
        Returns a list of matched technology dicts.
        """
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for sig in self.signatures:
            matched = False

            # Check header patterns
            for header_name, patterns in sig.get("headers", {}).items():
                header_val = headers_lower.get(header_name.lower(), "")
                for pattern in patterns:
                    if re.search(pattern, header_val, re.IGNORECASE):
                        matched = True
                        break
                if matched:
                    break

            # Check cookie names
            if not matched:
                for cookie_pattern in sig.get("cookies", []):
                    for cookie_name in cookies:
                        if re.search(cookie_pattern, cookie_name, re.IGNORECASE):
                            matched = True
                            break
                    if matched:
                        break

            # Check body patterns
            if not matched:
                for pattern in sig.get("body_patterns", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        matched = True
                        break

            if matched:
                detected.append({
                    "name": sig["name"],
                    "category": sig["category"],
                    "confidence": sig["confidence"],
                })

        return detected

    def _check_header_leakage(self, headers: Dict[str, str], url: str) -> List[dict]:
        """
        Check for version disclosure in HTTP headers.
        Revealing software versions makes targeted exploitation trivial.
        """
        findings = []
        version_pattern = re.compile(r"\d+\.\d+[\.\d]*")

        sensitive_headers = {
            "server": "Web server identity and version",
            "x-powered-by": "Backend language/framework and version",
            "x-aspnet-version": "ASP.NET version number",
            "x-generator": "CMS or generator identity",
            "x-drupal-cache": "Drupal CMS disclosure",
        }

        for header_name, description in sensitive_headers.items():
            value = headers.get(header_name, "")
            if not value:
                continue

            if version_pattern.search(value):
                findings.append({
                    "title": f"Version Disclosure via HTTP Header: {header_name}",
                    "severity": "low",
                    "vuln_type": "info_disclosure_header",
                    "url": url,
                    "parameter": header_name,
                    "description": (
                        f"The response header '{header_name}' reveals version information: '{value}'. "
                        f"This is: {description}. Attackers use version numbers to look up "
                        f"known CVEs and public exploits for the exact version in use."
                    ),
                    "evidence": f"{header_name}: {value}",
                    "remediation": (
                        f"Remove or suppress the '{header_name}' header. In Apache: "
                        f"'ServerTokens Prod'. In Nginx: 'server_tokens off'. "
                        f"In PHP: set 'expose_php = Off' in php.ini."
                    ),
                    "cvss_score": 3.7,
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                    ],
                    "payload_used": None,
                    "confirmed": True,
                    "is_false_positive": False,
                })

        return findings

    def _make_waf_finding(self, url: str, waf_names: List[str]) -> dict:
        return {
            "title": f"WAF Detected: {', '.join(waf_names)}",
            "severity": "info",
            "vuln_type": "recon_waf",
            "url": url,
            "description": (
                f"A Web Application Firewall (WAF) was detected: {', '.join(waf_names)}. "
                f"Subsequent vulnerability modules will note this — some payloads may need "
                f"encoding or evasion techniques to bypass WAF rules."
            ),
            "evidence": f"WAF signatures matched: {waf_names}",
            "remediation": "WAF is a positive security control. Ensure it is properly configured.",
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_tech_finding(
        self,
        url: str,
        categorized: Dict[str, List[str]],
        headers: Dict[str, str],
        status: int
    ) -> dict:
        lines = [f"Technologies identified on {url}:\n"]
        for cat, techs in categorized.items():
            lines.append(f"  [{cat.upper()}]")
            for t in techs:
                lines.append(f"    → {t}")

        return {
            "title": "Technology Stack Identified",
            "severity": "info",
            "vuln_type": "recon_tech",
            "url": url,
            "description": "\n".join(lines),
            "evidence": str(categorized),
            "remediation": (
                "Review identified technologies for known CVEs. Keep all components "
                "up to date. Remove unnecessary version headers."
            ),
            "cvss_score": 0.0,
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/"
            ],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    async def _check_robots(self, base_url: str) -> Optional[dict]:
        """
        Fetch robots.txt — often reveals hidden endpoints,
        admin panels, and directories the site owner wants to hide from crawlers
        (but which are still publicly accessible).
        """
        robots_url = base_url.rstrip("/") + "/robots.txt"
        try:
            async with httpx.AsyncClient(timeout=8, verify=False) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200 and "user-agent" in resp.text.lower():
                    disallowed = [
                        line.split(":", 1)[1].strip()
                        for line in resp.text.splitlines()
                        if line.lower().startswith("disallow:") and len(line.split(":", 1)) > 1
                    ]
                    if disallowed:
                        return {
                            "title": "Sensitive Paths Exposed in robots.txt",
                            "severity": "info",
                            "vuln_type": "recon_robots",
                            "url": robots_url,
                            "description": (
                                f"robots.txt was found at {robots_url} and contains "
                                f"{len(disallowed)} Disallow entries. These entries hint at "
                                f"sensitive paths the site owner wants hidden, but they remain "
                                f"publicly accessible and provide a roadmap for attackers."
                            ),
                            "evidence": "Disallowed paths:\n" + "\n".join(f"  {p}" for p in disallowed[:30]),
                            "remediation": (
                                "Do not rely on robots.txt to protect sensitive content — "
                                "it is publicly readable by everyone including attackers. "
                                "Protect sensitive paths with authentication and authorization."
                            ),
                            "cvss_score": 2.0,
                            "references": [
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"
                            ],
                            "parameter": None,
                            "payload_used": None,
                            "confirmed": True,
                            "is_false_positive": False,
                        }
        except Exception as e:
            logger.debug(f"[TechDetect] robots.txt fetch failed: {e}")
        return None