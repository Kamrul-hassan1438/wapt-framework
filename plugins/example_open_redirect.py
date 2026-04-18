"""
Example Plugin: Open Redirect Detector
Tests for open redirect vulnerabilities in URL parameters.

This plugin demonstrates the full plugin API.
Copy and adapt it to build your own plugins.
"""
import httpx
from typing import List
from plugins.base import WAPTPlugin


class OpenRedirectPlugin(WAPTPlugin):
    """
    Detects open redirect vulnerabilities.
    Open redirects allow attackers to craft trusted-looking
    URLs that redirect victims to malicious sites.
    """
    name        = "open_redirect"
    version     = "1.0.0"
    author      = "WAPT Framework"
    description = "Open redirect detection in URL and form parameters"
    category    = "vuln"
    tests_for   = ["open_redirect"]

    # Payloads — external URLs to inject as redirect targets
    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "\\\\evil.com",
        "/\\evil.com",
        "https:evil.com",
        "%2F%2Fevil.com",
        "https%3A%2F%2Fevil.com",
    ]

    # Parameters commonly used for redirects
    REDIRECT_PARAMS = [
        "redirect", "redirect_uri", "redirect_url",
        "return", "return_url", "returnTo",
        "next", "next_url", "goto", "url",
        "dest", "destination", "continue",
        "forward", "target", "callback",
        "ref", "referrer",
    ]

    async def run(self) -> List[dict]:
        findings = []
        registry = getattr(self.engine, "input_registry", None)
        if not registry:
            return findings

        base_url = self.engine.target_url

        # Test URL parameters
        for param_info in registry.get("url_params", []):
            param = param_info.get("param", "")
            if param.lower() not in [p.lower() for p in self.REDIRECT_PARAMS]:
                continue

            for payload in self.REDIRECT_PAYLOADS:
                test_url = f"{param_info['base_url']}?{param}={payload}"
                finding  = await self._test_redirect(test_url, param, payload)
                if finding:
                    findings.append(finding)
                    break  # one confirmed finding per parameter

        # Test all pages for redirect params in their URL
        for page_url in registry.get("all_pages", [])[:50]:
            for redirect_param in self.REDIRECT_PARAMS:
                for payload in self.REDIRECT_PAYLOADS[:3]:
                    if "?" in page_url:
                        test_url = f"{page_url}&{redirect_param}={payload}"
                    else:
                        test_url = f"{page_url}?{redirect_param}={payload}"

                    finding = await self._test_redirect(test_url, redirect_param, payload)
                    if finding:
                        findings.append(finding)
                        break

        return findings

    async def _test_redirect(
        self, url: str, param: str, payload: str
    ):
        """
        Send the request without following redirects.
        Check if the Location header points to our payload.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": self.config.scan.user_agents[0]},
            ) as client:
                resp = await client.get(url)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    # Check if redirect goes to our payload domain
                    if "evil.com" in location or location.startswith("//evil.com"):
                        return self.make_finding(
                            title=f"Open Redirect — Parameter '{param}'",
                            severity="medium",
                            vuln_type="open_redirect",
                            url=url,
                            parameter=param,
                            payload_used=payload,
                            description=(
                                f"The parameter '{param}' accepts an external URL and "
                                f"redirects the user to it without validation. "
                                f"Attackers craft legitimate-looking URLs "
                                f"(e.g., {self.engine.target_url}?{param}=https://phishing.com) "
                                f"to bypass link-trust filters and redirect victims to "
                                f"malicious sites for phishing or malware delivery."
                            ),
                            evidence=(
                                f"Request:  GET {url}\n"
                                f"Response: HTTP {resp.status_code}\n"
                                f"Location: {location}"
                            ),
                            remediation=(
                                "1. Maintain a whitelist of allowed redirect destinations.\n"
                                "2. Use relative paths instead of absolute URLs.\n"
                                "3. Validate the 'Host' portion of any redirect URL.\n"
                                "4. Use indirect references: map keys to URLs server-side.\n\n"
                                "Example:\n"
                                "  WRONG:  redirect(request.args['url'])\n"
                                "  CORRECT: redirect(SAFE_URLS.get(request.args['key'], '/'))"
                            ),
                            cvss_score=6.1,
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/601.html",
                            ],
                        )
        except Exception:
            pass
        return None