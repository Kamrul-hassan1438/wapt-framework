"""
HTTP Header Security Analyzer
Checks for missing, misconfigured, or insecure HTTP response headers.
Each missing security header is a distinct finding with severity and remediation.
"""
import httpx
from typing import List, Dict, Optional, Tuple
from loguru import logger
from core.engine import BaseModule


# Full definition of every security header we check
# Format: header_name → (severity, cvss, title, description, remediation, references)
SECURITY_HEADERS: Dict[str, Tuple] = {
    "Strict-Transport-Security": (
        "high", 7.4,
        "Missing HSTS Header",
        (
            "HTTP Strict Transport Security (HSTS) is not set. Without it, browsers may "
            "connect over plain HTTP, making users vulnerable to SSL stripping attacks "
            "where an attacker downgrades the connection to HTTP and intercepts all traffic."
        ),
        (
            "Add: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. "
            "'max-age=31536000' = 1 year. 'includeSubDomains' applies to all subdomains. "
            "'preload' submits the domain to browser preload lists for the strongest protection."
        ),
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
         "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    ),
    "Content-Security-Policy": (
        "high", 6.1,
        "Missing Content-Security-Policy (CSP) Header",
        (
            "No Content Security Policy is defined. CSP is the primary browser defense against "
            "Cross-Site Scripting (XSS). Without CSP, injected scripts execute freely in the "
            "browser, enabling session hijacking, credential theft, and malware distribution."
        ),
        (
            "Start with a restrictive policy: "
            "'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'; "
            "object-src \\'none\\'; frame-ancestors \\'none\\''. "
            "Use a CSP nonce for inline scripts. Avoid 'unsafe-inline' and 'unsafe-eval'."
        ),
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
         "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]
    ),
    "X-Frame-Options": (
        "medium", 4.3,
        "Missing X-Frame-Options Header",
        (
            "X-Frame-Options is not set. This allows the page to be embedded in an iframe "
            "on any domain, enabling Clickjacking attacks where an attacker overlays a "
            "transparent iframe over a deceptive page to trick users into clicking hidden buttons."
        ),
        (
            "Add: 'X-Frame-Options: DENY' (recommended) or 'SAMEORIGIN'. "
            "Alternatively, use CSP: 'frame-ancestors \\'none\\'' which supersedes X-Frame-Options "
            "in modern browsers. Use both for maximum compatibility."
        ),
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
         "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"]
    ),
    "X-Content-Type-Options": (
        "low", 3.1,
        "Missing X-Content-Type-Options Header",
        (
            "X-Content-Type-Options is not set to 'nosniff'. Browsers perform MIME type sniffing "
            "to guess the content type of responses. Attackers can exploit this to serve a file "
            "as text/html that the browser executes as JavaScript, enabling XSS."
        ),
        "Add: 'X-Content-Type-Options: nosniff'. This is a one-line fix.",
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
    ),
    "Referrer-Policy": (
        "low", 3.1,
        "Missing or Weak Referrer-Policy Header",
        (
            "No Referrer-Policy header is set. By default, browsers include the full URL "
            "in the Referer header when navigating, potentially leaking sensitive path "
            "information, session tokens, or internal URLs to third-party services."
        ),
        "Add: 'Referrer-Policy: strict-origin-when-cross-origin' as a balanced default.",
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
    ),
    "Permissions-Policy": (
        "low", 2.6,
        "Missing Permissions-Policy Header",
        (
            "No Permissions-Policy (formerly Feature-Policy) header is set. "
            "This header restricts which browser features (camera, microphone, geolocation, "
            "payment) pages and iframes can use. Without it, malicious iframes or injected "
            "scripts may access powerful browser APIs."
        ),
        (
            "Add: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' "
            "to disable unused browser features by default."
        ),
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"]
    ),
    "Cross-Origin-Opener-Policy": (
        "info", 0.0,
        "Missing Cross-Origin-Opener-Policy (COOP) Header",
        (
            "Cross-Origin-Opener-Policy is not set. Without it, cross-origin pages can obtain "
            "a reference to this page via window.opener, enabling cross-window attacks."
        ),
        "Add: 'Cross-Origin-Opener-Policy: same-origin'.",
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"]
    ),
}

# Headers that SHOULD NOT be present (they expose info)
FORBIDDEN_HEADERS = {
    "X-Powered-By":    ("low", 3.1, "X-Powered-By header discloses backend technology"),
    "Server":          ("low", 3.1, "Server header discloses web server version"),
    "X-AspNet-Version":("low", 3.7, "X-AspNet-Version header discloses ASP.NET version"),
    "X-Generator":     ("low", 2.6, "X-Generator header discloses CMS identity"),
}


class HeaderAnalyzerModule(BaseModule):
    """
    Audits HTTP response headers for security misconfigurations.
    Missing security headers and information-leaking headers are both checked.
    """
    name = "header_analyzer"
    description = "HTTP security header audit — missing protections and info disclosure"

    async def run(self) -> List[dict]:
        findings = []
        target = self.engine.target_url
        logger.info(f"[Headers] Analyzing security headers for: {target}")

        # Fetch response headers
        headers = await self._fetch_headers(target)
        if headers is None:
            logger.warning("[Headers] Could not fetch target headers")
            return findings

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing security headers
        for header_name, (severity, cvss, title, description, remediation, refs) in SECURITY_HEADERS.items():
            if header_name.lower() not in headers_lower:
                findings.append({
                    "title": title,
                    "severity": severity,
                    "vuln_type": "missing_security_header",
                    "url": target,
                    "parameter": header_name,
                    "description": description,
                    "evidence": f"Header '{header_name}' was not present in the response.",
                    "remediation": remediation,
                    "cvss_score": cvss,
                    "references": refs,
                    "payload_used": None,
                    "confirmed": True,
                    "is_false_positive": False,
                })
                logger.debug(f"[Headers] MISSING: {header_name}")
            else:
                # Header present — check for weak values
                header_val = headers_lower[header_name.lower()]
                weak_finding = self._check_weak_value(header_name, header_val, target)
                if weak_finding:
                    findings.append(weak_finding)
                logger.debug(f"[Headers] OK: {header_name}: {header_val[:60]}")

        # Check for information-leaking headers that should be removed
        for header_name, (severity, cvss, description) in FORBIDDEN_HEADERS.items():
            value = headers_lower.get(header_name.lower())
            if value:
                findings.append({
                    "title": f"Information Disclosure: {header_name}",
                    "severity": severity,
                    "vuln_type": "info_disclosure_header",
                    "url": target,
                    "parameter": header_name,
                    "description": (
                        f"{description}. Value found: '{value}'. "
                        f"This reveals the software stack to attackers, making it easier "
                        f"to find and exploit known vulnerabilities for this exact version."
                    ),
                    "evidence": f"{header_name}: {value}",
                    "remediation": (
                        f"Remove the '{header_name}' header from all responses. "
                        f"In Apache: 'ServerTokens Prod'. In Nginx: 'server_tokens off'. "
                        f"In PHP: 'expose_php = Off'. In IIS: use URL Rewrite to remove headers."
                    ),
                    "cvss_score": cvss,
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                    ],
                    "payload_used": None,
                    "confirmed": True,
                    "is_false_positive": False,
                })

        # Check cookie security flags
        cookie_findings = self._check_cookies(headers, target)
        findings.extend(cookie_findings)

        # Check for HTTPS redirect
        http_finding = await self._check_http_redirect(target)
        if http_finding:
            findings.append(http_finding)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

        logger.success(f"[Headers] Audit complete — {len(findings)} findings")
        return findings

    async def _fetch_headers(self, url: str) -> Optional[Dict[str, str]]:
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                resp = await client.get(url)
                return dict(resp.headers)
        except Exception as e:
            logger.error(f"[Headers] Fetch error: {e}")
            return None

    def _check_weak_value(self, header_name: str, value: str, url: str) -> Optional[dict]:
        """Check known headers for insecure values even when the header is present."""
        value_lower = value.lower()

        if header_name == "Strict-Transport-Security":
            import re
            match = re.search(r"max-age=(\d+)", value_lower)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:
                    return {
                        "title": "Weak HSTS max-age (Less Than 1 Year)",
                        "severity": "low",
                        "vuln_type": "weak_security_header",
                        "url": url,
                        "parameter": header_name,
                        "description": (
                            f"HSTS is set but max-age={max_age} seconds ({max_age // 86400} days) "
                            f"is less than the recommended 1 year (31536000 seconds). "
                            f"Short durations mean users are unprotected after the header expires."
                        ),
                        "evidence": f"Strict-Transport-Security: {value}",
                        "remediation": "Set max-age to at least 31536000 (one year).",
                        "cvss_score": 2.6,
                        "references": [],
                        "payload_used": None,
                        "confirmed": True,
                        "is_false_positive": False,
                    }

        if header_name == "Content-Security-Policy":
            dangerous_values = ["unsafe-inline", "unsafe-eval", "*"]
            for dangerous in dangerous_values:
                if dangerous in value_lower:
                    return {
                        "title": f"Weak CSP — '{dangerous}' Directive Allows XSS",
                        "severity": "medium",
                        "vuln_type": "weak_csp",
                        "url": url,
                        "parameter": header_name,
                        "description": (
                            f"The Content-Security-Policy header contains '{dangerous}'. "
                            f"'unsafe-inline' allows inline scripts, bypassing XSS protection. "
                            f"'unsafe-eval' allows eval(), a common XSS vector. "
                            f"'*' allows loading resources from any origin."
                        ),
                        "evidence": f"Content-Security-Policy: {value[:200]}",
                        "remediation": (
                            f"Remove '{dangerous}' from the CSP. Use nonces or hashes for "
                            f"legitimate inline scripts instead of 'unsafe-inline'."
                        ),
                        "cvss_score": 5.4,
                        "references": [
                            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                        ],
                        "payload_used": None,
                        "confirmed": True,
                        "is_false_positive": False,
                    }
        return None

    def _check_cookies(self, headers: Dict[str, str], url: str) -> List[dict]:
        """
        Check Set-Cookie headers for missing security flags:
        HttpOnly, Secure, SameSite.
        """
        findings = []
        set_cookie_headers = [
            v for k, v in headers.items()
            if k.lower() == "set-cookie"
        ]

        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split("=")[0].strip()
            cookie_lower = cookie_str.lower()

            is_https = url.startswith("https://")

            if "httponly" not in cookie_lower:
                findings.append({
                    "title": f"Cookie Missing HttpOnly Flag: {cookie_name}",
                    "severity": "medium",
                    "vuln_type": "insecure_cookie",
                    "url": url,
                    "parameter": cookie_name,
                    "description": (
                        f"The cookie '{cookie_name}' is missing the HttpOnly flag. "
                        f"Without HttpOnly, JavaScript running in the browser (including from XSS) "
                        f"can read this cookie via document.cookie, enabling session hijacking."
                    ),
                    "evidence": cookie_str[:200],
                    "remediation": f"Add 'HttpOnly' attribute: Set-Cookie: {cookie_name}=...; HttpOnly",
                    "cvss_score": 5.4,
                    "references": ["https://owasp.org/www-community/HttpOnly"],
                    "payload_used": None, "confirmed": True, "is_false_positive": False,
                })

            if is_https and "secure" not in cookie_lower:
                findings.append({
                    "title": f"Cookie Missing Secure Flag: {cookie_name}",
                    "severity": "medium",
                    "vuln_type": "insecure_cookie",
                    "url": url,
                    "parameter": cookie_name,
                    "description": (
                        f"The cookie '{cookie_name}' is missing the Secure flag on an HTTPS site. "
                        f"Without Secure, the cookie can be transmitted over plain HTTP, "
                        f"exposing it to network interception (man-in-the-middle attacks)."
                    ),
                    "evidence": cookie_str[:200],
                    "remediation": f"Add 'Secure' attribute: Set-Cookie: {cookie_name}=...; Secure",
                    "cvss_score": 5.9,
                    "references": [],
                    "payload_used": None, "confirmed": True, "is_false_positive": False,
                })

            if "samesite" not in cookie_lower:
                findings.append({
                    "title": f"Cookie Missing SameSite Attribute: {cookie_name}",
                    "severity": "low",
                    "vuln_type": "insecure_cookie",
                    "url": url,
                    "parameter": cookie_name,
                    "description": (
                        f"The cookie '{cookie_name}' has no SameSite attribute. "
                        f"Without SameSite, the cookie is sent in all cross-site requests, "
                        f"making it vulnerable to Cross-Site Request Forgery (CSRF) attacks."
                    ),
                    "evidence": cookie_str[:200],
                    "remediation": "Add 'SameSite=Lax' (balanced) or 'SameSite=Strict' (most secure).",
                    "cvss_score": 3.5,
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                    "payload_used": None, "confirmed": True, "is_false_positive": False,
                })

        return findings

    async def _check_http_redirect(self, url: str) -> Optional[dict]:
        """Check if the HTTP version redirects to HTTPS."""
        if not url.startswith("https://"):
            return None
        http_url = "http://" + url[8:]
        try:
            async with httpx.AsyncClient(
                timeout=8,
                follow_redirects=False,
                verify=False
            ) as client:
                resp = await client.get(http_url)
                if resp.status_code not in (301, 302, 307, 308):
                    return {
                        "title": "HTTP Does Not Redirect to HTTPS",
                        "severity": "high",
                        "vuln_type": "no_https_redirect",
                        "url": http_url,
                        "description": (
                            f"Accessing {http_url} returned HTTP {resp.status_code} instead of "
                            f"redirecting to HTTPS. Users who type the URL without 'https://' "
                            f"will communicate over plain HTTP, exposing all data in transit."
                        ),
                        "evidence": f"HTTP {resp.status_code} from {http_url}",
                        "remediation": (
                            "Add a permanent redirect from HTTP to HTTPS. "
                            "In Nginx: 'return 301 https://$host$request_uri;'. "
                            "In Apache: 'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]'"
                        ),
                        "cvss_score": 6.5,
                        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                        "payload_used": None, "confirmed": True, "is_false_positive": False,
                    }
        except Exception:
            pass
        return None