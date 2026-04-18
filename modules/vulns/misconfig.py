"""
Security Misconfiguration Module
Tests for:
  1. Dangerous HTTP methods (PUT, DELETE, TRACE on production endpoints)
  2. Verbose error messages that expose stack traces
  3. Debug endpoints and development interfaces
  4. Directory listing
  5. Default/example pages left on the server
"""
import asyncio
import re
from typing import List, Dict, Optional
import httpx
from loguru import logger
from core.engine import BaseModule


# Paths that should never be on a production server
DEBUG_PATHS = [
    # Framework debug endpoints
    "/_debug",
    "/debug",
    "/console",
    "/__debug__",
    "/django-admin/",
    "/_profiler",
    "/telescope",         # Laravel Telescope
    "/horizon",           # Laravel Horizon
    "/actuator",          # Spring Boot Actuator
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/metrics",
    # PHP specific
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/?phpinfo=1",
    # Error triggers
    "/undefined_route_wapt_test",
    "/404test_wapt",
]

# Dangerous HTTP methods — PUT/DELETE should not be enabled on web apps
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]

# Stack trace patterns — indicate verbose error mode is on
STACK_TRACE_PATTERNS = [
    # Python / Django
    r"Traceback \(most recent call last\)",
    r"django\.core\.exceptions",
    r"File \".+\.py\", line \d+",
    # Java / Spring
    r"java\.lang\.\w+Exception",
    r"at org\.springframework",
    r"at com\.sun\.",
    r"javax\.servlet\.ServletException",
    # PHP
    r"Fatal error:.*in .+ on line \d+",
    r"Warning:.*in .+ on line \d+",
    r"Parse error:",
    r"Stack trace:",
    # Ruby on Rails
    r"ActionController::RoutingError",
    r"app/controllers/.+\.rb:\d+",
    # Node.js
    r"at Object\.<anonymous> \(.+\.js:\d+:\d+\)",
    r"Error: Cannot find module",
    # ASP.NET
    r"Server Error in '/' Application",
    r"System\.Web\.\w+Exception",
    # Generic
    r"Internal Server Error",
    r"SQL syntax.*near",
    r"SQLSTATE\[\w+\]",
]

# Signs of directory listing
DIRECTORY_LISTING_PATTERNS = [
    r"Index of /",
    r"Directory Listing",
    r"Parent Directory",
    r"\[DIR\]",
    r"<title>Index of",
]


class MisconfigModule(BaseModule):
    name = "misconfig"
    description = "Security misconfiguration — methods, errors, debug endpoints, dir listing"

    async def run(self) -> List[dict]:
        findings = []
        target = self.engine.target_url
        logger.info(f"[Misconfig] Testing security misconfiguration on: {target}")

        # Run all checks concurrently
        results = await asyncio.gather(
            self._test_http_methods(target),
            self._test_verbose_errors(target),
            self._test_debug_endpoints(target),
            self._test_directory_listing(target),
            self._test_default_pages(target),
            return_exceptions=True
        )

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"[Misconfig] Check failed: {result}")

        logger.success(f"[Misconfig] Complete — {len(findings)} misconfiguration findings")
        return findings

    async def _test_http_methods(self, base_url: str) -> List[dict]:
        """
        Check which HTTP methods the server accepts.
        TRACE enables cross-site tracing (XST). 
        PUT/DELETE can allow file upload or deletion if misconfigured.
        """
        findings = []
        logger.debug("[Misconfig] Testing HTTP methods with OPTIONS")

        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                verify=False,
            ) as client:
                # OPTIONS returns all allowed methods
                resp = await client.options(base_url)
                allow_header = resp.headers.get("allow", "") + \
                               resp.headers.get("Access-Control-Allow-Methods", "")

                dangerous_found = [
                    m for m in DANGEROUS_METHODS
                    if m in allow_header.upper()
                ]

                if "TRACE" in dangerous_found:
                    # Verify TRACE actually works
                    trace_resp = await client.request("TRACE", base_url)
                    if trace_resp.status_code == 200:
                        findings.append({
                            "title":    "HTTP TRACE Method Enabled — Cross-Site Tracing (XST)",
                            "severity": "medium",
                            "vuln_type": "http_trace_enabled",
                            "url":      base_url,
                            "parameter": None,
                            "payload_used": "TRACE /",
                            "description": (
                                "The HTTP TRACE method is enabled. TRACE echoes back the "
                                "full HTTP request including headers. Combined with XSS, "
                                "it enables Cross-Site Tracing (XST) which can bypass "
                                "HttpOnly cookie protections."
                            ),
                            "evidence": f"TRACE returned HTTP {trace_resp.status_code}",
                            "remediation": (
                                "Disable TRACE in your web server. "
                                "Apache: 'TraceEnable Off'. "
                                "Nginx: 'if ($request_method = TRACE) { return 405; }'"
                            ),
                            "cvss_score": 5.8,
                            "references": [
                                "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
                            ],
                            "confirmed": True,
                            "is_false_positive": False,
                        })

                for method in ["PUT", "DELETE"]:
                    if method in dangerous_found:
                        findings.append({
                            "title":    f"Dangerous HTTP Method Enabled: {method}",
                            "severity": "medium",
                            "vuln_type": f"dangerous_http_method_{method.lower()}",
                            "url":      base_url,
                            "parameter": None,
                            "payload_used": f"{method} /",
                            "description": (
                                f"The {method} HTTP method is advertised by the server "
                                f"(OPTIONS Allow header). "
                                f"{'PUT can allow file upload to the server.' if method == 'PUT' else ''}"
                                f"{'DELETE can allow file deletion.' if method == 'DELETE' else ''}"
                            ),
                            "evidence": f"OPTIONS Allow: {allow_header[:200]}",
                            "remediation": (
                                f"Disable {method} in your web server configuration unless "
                                f"explicitly required by your API design."
                            ),
                            "cvss_score": 5.0,
                            "references": [],
                            "confirmed": False,
                            "is_false_positive": False,
                        })

        except Exception as e:
            logger.debug(f"[Misconfig] HTTP method test failed: {e}")

        return findings

    async def _test_verbose_errors(self, base_url: str) -> List[dict]:
        """
        Trigger error conditions and check if stack traces or
        internal details are leaked in the response.
        """
        findings = []
        error_triggers = [
            f"{base_url}/wapt-error-trigger-999999",
            f"{base_url}/?id=',1,1)--",
            f"{base_url}/?debug=1",
            f"{base_url}/?test[]=array_trigger",
        ]

        for url in error_triggers:
            try:
                async with httpx.AsyncClient(
                    timeout=8,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    if resp.status_code in (200, 500):
                        for pattern in STACK_TRACE_PATTERNS:
                            match = re.search(pattern, resp.text, re.IGNORECASE)
                            if match:
                                snippet = resp.text[
                                    max(0, match.start()-50): match.end()+200
                                ].strip()
                                findings.append({
                                    "title":    "Verbose Error Messages Expose Stack Trace",
                                    "severity": "medium",
                                    "vuln_type": "verbose_error_disclosure",
                                    "url":      url,
                                    "parameter": None,
                                    "payload_used": url,
                                    "description": (
                                        "The application returns detailed error messages including "
                                        "stack traces, file paths, and internal logic. "
                                        "This exposes the technology stack, file structure, "
                                        "and code logic to attackers."
                                    ),
                                    "evidence": snippet[:500],
                                    "remediation": (
                                        "Configure the application to show generic error pages "
                                        "in production. Log full errors internally but never "
                                        "display them to users.\n"
                                        "Django: DEBUG=False | Flask: app.debug=False | "
                                        "Spring: server.error.include-stacktrace=never"
                                    ),
                                    "cvss_score": 5.3,
                                    "references": [
                                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/13-Test_for_Error_Handling"
                                    ],
                                    "confirmed": True,
                                    "is_false_positive": False,
                                })
                                return findings  # one finding is enough
            except Exception:
                continue

        return findings

    async def _test_debug_endpoints(self, base_url: str) -> List[dict]:
        """Check for exposed debug, admin, and monitoring endpoints."""
        findings = []
        sem = asyncio.Semaphore(10)

        async def check_debug_path(path: str):
            async with sem:
                url = base_url.rstrip("/") + path
                try:
                    async with httpx.AsyncClient(
                        timeout=6,
                        follow_redirects=False,
                        verify=False,
                    ) as client:
                        resp = await client.get(url)
                        if resp.status_code in (200, 302):
                            severity = "high" if any(
                                kw in path for kw in
                                ["actuator/env", "actuator/beans", "console",
                                 "phpinfo", "debug", "_profiler"]
                            ) else "medium"

                            findings.append({
                                "title":    f"Debug/Admin Endpoint Exposed: {path}",
                                "severity": severity,
                                "vuln_type": "debug_endpoint_exposed",
                                "url":      url,
                                "parameter": None,
                                "payload_used": None,
                                "description": (
                                    f"The endpoint '{path}' returned HTTP {resp.status_code}. "
                                    f"Debug and monitoring endpoints expose internal application "
                                    f"state, configuration, environment variables, and "
                                    f"potentially allow command execution."
                                ),
                                "evidence": (
                                    f"HTTP {resp.status_code} from {url}\n"
                                    f"Content-Length: {resp.headers.get('content-length', 'unknown')}"
                                ),
                                "remediation": (
                                    f"Remove or restrict '{path}' in production. "
                                    "Protect behind VPN or IP whitelist. "
                                    "Disable framework debug mode."
                                ),
                                "cvss_score": 7.5 if severity == "high" else 5.3,
                                "references": [
                                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                                ],
                                "confirmed": True,
                                "is_false_positive": False,
                            })
                except Exception:
                    pass

        await asyncio.gather(*[check_debug_path(p) for p in DEBUG_PATHS])
        return findings

    async def _test_directory_listing(self, base_url: str) -> List[dict]:
        """Check if directory listing is enabled on common directories."""
        findings = []
        dirs_to_check = [
            "/uploads/", "/files/", "/images/", "/assets/",
            "/static/", "/media/", "/backup/", "/logs/",
        ]

        for dir_path in dirs_to_check:
            url = base_url.rstrip("/") + dir_path
            try:
                async with httpx.AsyncClient(
                    timeout=6,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        for pattern in DIRECTORY_LISTING_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                findings.append({
                                    "title":    f"Directory Listing Enabled: {dir_path}",
                                    "severity": "medium",
                                    "vuln_type": "directory_listing",
                                    "url":      url,
                                    "parameter": None,
                                    "payload_used": None,
                                    "description": (
                                        f"Directory listing is enabled at '{dir_path}'. "
                                        f"Attackers can browse all files in this directory, "
                                        f"potentially discovering backup files, config files, "
                                        f"source code, or sensitive documents."
                                    ),
                                    "evidence": f"Directory listing detected at {url}",
                                    "remediation": (
                                        "Disable directory listing in your web server. "
                                        "Apache: 'Options -Indexes' in .htaccess. "
                                        "Nginx: Remove 'autoindex on' from config."
                                    ),
                                    "cvss_score": 5.3,
                                    "references": [],
                                    "confirmed": True,
                                    "is_false_positive": False,
                                })
                                break
            except Exception:
                continue

        return findings

    async def _test_default_pages(self, base_url: str) -> List[dict]:
        """Check for default installation pages left on the server."""
        findings = []
        default_page_patterns = {
            "Apache default page":     r"It works!|Apache2? Ubuntu Default Page",
            "Nginx welcome page":      r"Welcome to nginx",
            "IIS default page":        r"Internet Information Services|IIS Windows Server",
            "XAMPP/WAMP default":      r"XAMPP|Welcome to XAMPP",
            "cPanel default":          r"cPanel|Parallels Plesk",
            "Laravel welcome page":    r"Laravel.*framework",
            "Django debug page":       r"Django version|Using the URLconf",
            "Spring Boot Whitelabel":  r"Whitelabel Error Page",
        }

        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(base_url)
                for page_name, pattern in default_page_patterns.items():
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "title":    f"Default Page Detected: {page_name}",
                            "severity": "low",
                            "vuln_type": "default_page",
                            "url":      base_url,
                            "parameter": None,
                            "payload_used": None,
                            "description": (
                                f"The server appears to be serving a default page: {page_name}. "
                                f"This confirms the server technology and may indicate "
                                f"an incomplete installation or misconfigured deployment."
                            ),
                            "evidence": f"{page_name} pattern detected on {base_url}",
                            "remediation": (
                                "Remove default pages and replace with your application. "
                                "Ensure the deployment process replaces all placeholder content."
                            ),
                            "cvss_score": 2.6,
                            "references": [],
                            "confirmed": True,
                            "is_false_positive": False,
                        })
        except Exception as e:
            logger.debug(f"[Misconfig] Default page check failed: {e}")

        return findings
    
    