"""
Directory & File Bruteforce Module
Discovers hidden paths, admin panels, backup files, and sensitive
endpoints that aren't linked from the main site.

Uses async HTTP with a semaphore-controlled concurrency pool.
Every 404 is discarded; interesting status codes are recorded.
"""
import asyncio
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin
import httpx
from loguru import logger

from core.engine import BaseModule


# Status codes we consider "interesting" (not hard 404)
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Severity map based on what the path contains
SENSITIVE_PATH_PATTERNS = {
    # Pattern → (severity, cvss, category)
    ".env":          ("critical", 9.8, "exposed_env_file"),
    ".git":          ("critical", 9.1, "exposed_git"),
    "wp-config":     ("critical", 9.8, "exposed_config"),
    "database.sql":  ("critical", 9.8, "exposed_database_dump"),
    "backup":        ("high",     7.5, "exposed_backup"),
    "dump.sql":      ("critical", 9.8, "exposed_database_dump"),
    "phpinfo":       ("high",     7.2, "php_info_disclosure"),
    "adminer":       ("high",     8.1, "exposed_db_admin"),
    "phpmyadmin":    ("high",     8.1, "exposed_db_admin"),
    "wp-admin":      ("medium",   5.3, "exposed_admin_panel"),
    "admin":         ("medium",   5.3, "exposed_admin_panel"),
    "swagger":       ("medium",   5.3, "exposed_api_docs"),
    "graphql":       ("medium",   5.0, "exposed_api_endpoint"),
    "debug":         ("medium",   5.3, "exposed_debug_endpoint"),
    ".htpasswd":     ("critical", 9.1, "exposed_credentials"),
    "server-status": ("medium",   5.3, "apache_status_exposed"),
    "actuator":      ("high",     7.5, "spring_actuator_exposed"),
}

# 401/403 responses are interesting — path exists but is protected
AUTH_REQUIRED_CATEGORIES = {
    "admin": "Protected admin panel found",
    "api":   "Protected API endpoint found",
    "login": "Login endpoint discovered",
}


class DirBruteModule(BaseModule):
    """
    Discovers hidden directories and files through HTTP bruteforcing.
    Uses smart filtering to reduce false positives:
      - Detects custom 404 pages by fingerprinting a known-bad URL
      - Tracks content-length to spot "soft 404" pages
      - Groups findings by severity
    """
    name = "dir_brute"
    description = "Directory and file discovery via wordlist bruteforcing"

    # Concurrent requests — high enough for speed, low enough to be polite
    CONCURRENCY = 30

    def __init__(self, engine, wordlists: Optional[List[str]] = None):
        super().__init__(engine)
        self.wordlists = wordlists or [
            "payloads/wordlists/directories.txt",
            "payloads/wordlists/files.txt",
        ]

    async def run(self) -> List[dict]:
        findings = []
        base_url = self.engine.target_url.rstrip("/")
        logger.info(f"[DirBrute] Starting discovery on: {base_url}")

        # Load all wordlists and combine
        paths = await self._load_wordlists()
        if not paths:
            logger.error("[DirBrute] No wordlist paths loaded — aborting")
            return findings

        logger.info(f"[DirBrute] Loaded {len(paths)} unique paths to test")

        # Fingerprint the 404 page to detect custom error pages (soft 404s)
        fake_404_fingerprint = await self._get_404_fingerprint(base_url)
        logger.debug(f"[DirBrute] 404 fingerprint hash: {fake_404_fingerprint[:8]}...")

        # Run the bruteforce
        discovered = await self._bruteforce(base_url, paths, fake_404_fingerprint)
        logger.success(f"[DirBrute] Discovery complete — {len(discovered)} paths found")

        if not discovered:
            return findings

        # Build findings from discovered paths
        path_findings = self._build_findings(base_url, discovered)
        findings.extend(path_findings)

        # Always add a summary finding with the full list
        findings.append(self._make_summary_finding(base_url, discovered))

        return findings

    async def _load_wordlists(self) -> List[str]:
        """Load and deduplicate all configured wordlists."""
        all_paths: Set[str] = set()
        for wl_path in self.wordlists:
            path = Path(wl_path)
            if not path.exists():
                logger.warning(f"[DirBrute] Wordlist not found: {wl_path}")
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    all_paths.add(line.lstrip("/"))
        return sorted(all_paths)

    async def _get_404_fingerprint(self, base_url: str) -> str:
        """
        Fetch a deliberately nonexistent path and fingerprint its response.
        Used to detect custom 404 pages that return HTTP 200 (soft 404s).
        """
        fake_url = f"{base_url}/wapt-definitely-does-not-exist-{id(self)}"
        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(fake_url)
                # Hash the body to fingerprint the 404 page
                return hashlib.md5(resp.text.encode()).hexdigest()
        except Exception:
            return "no-fingerprint"

    async def _bruteforce(
        self,
        base_url: str,
        paths: List[str],
        fake_404_hash: str,
    ) -> List[Dict]:
        """
        Probe each path concurrently. Filter out real 404s and soft 404s.
        Returns a list of interesting response dicts.
        """
        sem = asyncio.Semaphore(self.CONCURRENCY)
        discovered = []
        checked = 0
        total = len(paths)

        async def check_path(path: str):
            nonlocal checked
            async with sem:
                url = f"{base_url}/{path}"
                try:
                    async with httpx.AsyncClient(
                        timeout=self.engine.timeout,
                        follow_redirects=False,  # don't follow — we want the raw status
                        verify=False,
                        headers={
                            "User-Agent": self.config.scan.user_agents[0],
                        }
                    ) as client:
                        resp = await client.get(url)
                        checked += 1

                        # Progress log every 100 requests
                        if checked % 100 == 0:
                            logger.debug(f"[DirBrute] Progress: {checked}/{total}")

                        # Skip hard 404s
                        if resp.status_code == 404:
                            return

                        # Skip if not an interesting status code
                        if resp.status_code not in INTERESTING_CODES:
                            return

                        # Detect soft 404 — custom 404 page served with HTTP 200
                        if resp.status_code == 200:
                            body_hash = hashlib.md5(resp.text.encode()).hexdigest()
                            if body_hash == fake_404_hash:
                                return  # Soft 404 — skip it

                        content_type = resp.headers.get("content-type", "")
                        content_length = len(resp.content)

                        discovered.append({
                            "path":           path,
                            "url":            url,
                            "status_code":    resp.status_code,
                            "content_length": content_length,
                            "content_type":   content_type,
                            "redirect_to":    resp.headers.get("location", ""),
                            "server":         resp.headers.get("server", ""),
                        })
                        logger.debug(
                            f"[DirBrute] [{resp.status_code}] {path} "
                            f"({content_length} bytes)"
                        )

                except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
                    pass
                except Exception as e:
                    logger.debug(f"[DirBrute] Error on {path}: {e}")

        await asyncio.gather(*[check_path(p) for p in paths])
        return discovered

    def _build_findings(
        self,
        base_url: str,
        discovered: List[Dict],
    ) -> List[dict]:
        """
        For each discovered path, check if it matches a sensitive pattern
        and generate an appropriately severity-rated finding.
        """
        findings = []
        reported_patterns: Set[str] = set()  # avoid duplicate findings

        for item in discovered:
            path_lower = item["path"].lower()
            status = item["status_code"]

            # Check sensitive pattern matches
            for pattern, (severity, cvss, vuln_type) in SENSITIVE_PATH_PATTERNS.items():
                if pattern in path_lower and pattern not in reported_patterns:
                    reported_patterns.add(pattern)

                    status_context = self._status_context(status, item.get("redirect_to", ""))
                    findings.append({
                        "title": f"Sensitive Path Discovered: /{item['path']}",
                        "severity": severity,
                        "vuln_type": vuln_type,
                        "url": item["url"],
                        "parameter": None,
                        "description": (
                            f"The path '/{item['path']}' was discovered on {base_url}. "
                            f"HTTP {status} — {status_context}. "
                            f"This type of path ({pattern}) typically indicates: "
                            f"{self._pattern_description(pattern)}"
                        ),
                        "evidence": (
                            f"URL: {item['url']} | "
                            f"Status: {status} | "
                            f"Size: {item['content_length']} bytes | "
                            f"Type: {item['content_type']}"
                        ),
                        "remediation": self._pattern_remediation(pattern),
                        "cvss_score": cvss,
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                        ],
                        "payload_used": None,
                        "confirmed": status == 200,
                        "is_false_positive": False,
                    })
                    break  # One finding per discovered path

            # Flag 401/403 on interesting paths (exists but protected)
            if status in (401, 403):
                for keyword, desc in AUTH_REQUIRED_CATEGORIES.items():
                    if keyword in path_lower:
                        findings.append({
                            "title": f"{desc}: /{item['path']}",
                            "severity": "low",
                            "vuln_type": "protected_endpoint_found",
                            "url": item["url"],
                            "parameter": None,
                            "description": (
                                f"HTTP {status} returned for '/{item['path']}'. "
                                f"The path exists and access is restricted. "
                                f"This endpoint should be investigated for authentication bypass."
                            ),
                            "evidence": (
                                f"URL: {item['url']} | Status: {status} | "
                                f"Size: {item['content_length']} bytes"
                            ),
                            "remediation": (
                                "Ensure this endpoint is protected by strong authentication. "
                                "Test for authentication bypass (default credentials, "
                                "JWT manipulation, IDOR)."
                            ),
                            "cvss_score": 3.1,
                            "references": [],
                            "payload_used": None,
                            "confirmed": True,
                            "is_false_positive": False,
                        })
                        break

        return findings

    def _status_context(self, status: int, redirect: str) -> str:
        contexts = {
            200: "content returned — path is publicly accessible",
            301: f"permanent redirect → {redirect}",
            302: f"temporary redirect → {redirect}",
            401: "authentication required (path exists)",
            403: "access forbidden (path exists but blocked)",
            405: "method not allowed (endpoint exists)",
            500: "server error (path triggered an exception — may indicate vulnerability)",
        }
        return contexts.get(status, f"HTTP {status}")

    def _pattern_description(self, pattern: str) -> str:
        descriptions = {
            ".env":         "Environment config with database URLs, API keys, and secrets.",
            ".git":         "Git repository — full source code history may be downloadable.",
            "wp-config":    "WordPress config containing database credentials.",
            "database.sql": "Database dump — may contain all user data and hashed passwords.",
            "backup":       "Backup archive — may contain full application source and database.",
            "phpinfo":      "PHP configuration dump exposing server internals.",
            "adminer":      "Database administration interface exposed to the public.",
            "phpmyadmin":   "MySQL web admin tool — frequent brute force and CVE target.",
            "wp-admin":     "WordPress admin panel.",
            "swagger":      "API documentation — reveals all endpoints and parameters.",
            ".htpasswd":    "Apache password file — contains hashed user credentials.",
            "server-status":"Apache server status page — reveals internal requests and IPs.",
            "graphql":      "GraphQL endpoint — may allow introspection and data extraction.",
        }
        return descriptions.get(pattern, "Sensitive or administrative resource.")

    def _pattern_remediation(self, pattern: str) -> str:
        remediations = {
            ".env":         "Immediately remove .env from the web root. Add to .gitignore. Rotate all secrets.",
            ".git":         "Block access to .git/ via web server config. Never deploy with .git in web root.",
            "wp-config":    "Move wp-config.php above the web root or block via .htaccess.",
            "database.sql": "Remove database dumps from the web server. Store backups offline.",
            "backup":       "Remove backups from publicly accessible directories. Store off-server.",
            "phpinfo":      "Remove phpinfo() calls from production. Never expose php info pages.",
            "adminer":      "Remove Adminer from production. Use IP whitelist or VPN if needed.",
            "phpmyadmin":   "Block phpMyAdmin behind a VPN or IP whitelist. Never expose publicly.",
            ".htpasswd":    "Block .htpasswd via web server config. Rotate all credentials immediately.",
            "server-status":"Restrict server-status to localhost: 'Allow from 127.0.0.1'.",
            "swagger":      "Restrict Swagger UI to internal networks in production.",
            "graphql":      "Disable GraphQL introspection in production.",
        }
        return remediations.get(
            pattern,
            "Review if this path should be publicly accessible. Apply authentication if needed."
        )

    def _make_summary_finding(self, base_url: str, discovered: List[Dict]) -> dict:
        lines = [f"Directory scan found {len(discovered)} accessible paths:\n"]
        lines.append(f"  {'STATUS':<8} {'SIZE':<10} {'PATH'}")
        lines.append(f"  {'-'*60}")
        for item in sorted(discovered, key=lambda x: x["status_code"]):
            lines.append(
                f"  {item['status_code']:<8} "
                f"{str(item['content_length']) + ' B':<10} "
                f"/{item['path']}"
            )
        return {
            "title": f"Directory Scan Results — {len(discovered)} Paths Discovered",
            "severity": "info",
            "vuln_type": "dir_scan_results",
            "url": base_url,
            "description": "\n".join(lines),
            "evidence": str([item["url"] for item in discovered]),
            "remediation": "Review all discovered paths for unintended public exposure.",
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

        