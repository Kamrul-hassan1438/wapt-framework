"""
Cross-Site Scripting (XSS) Testing Module
Tests for Reflected, Stored, and DOM-based XSS.

Approach:
  1. Canary injection  — inject a unique marker, check if it appears unescaped
  2. Payload injection — escalate to actual script tags for confirmation
  3. Context detection — identify where in the HTML the value lands
                         (attribute, tag body, JS string) for accurate reporting
"""
import asyncio
import uuid
import re
from typing import List, Dict, Optional, Tuple
import yaml
import httpx
from loguru import logger
from core.engine import BaseModule


# HTML context detection patterns
# We check WHERE in the page the reflected value appears to assess exploitability
CONTEXT_PATTERNS = {
    "html_attribute": r'=\s*["\'][^"\']*{canary}',
    "html_tag_body":  r'>[^<]*{canary}[^<]*<',
    "js_string":      r'["\'][^"\']*{canary}[^"\']*["\']',
    "js_variable":    r'var\s+\w+\s*=\s*[^;]*{canary}',
    "url_param":      r'(?:href|src|action)\s*=\s*["\'][^"\']*{canary}',
}


class XSSModule(BaseModule):
    """
    Comprehensive XSS scanner that tests all form inputs and
    URL parameters with canary + payload escalation.
    """
    name = "xss"
    description = "XSS testing — reflected, stored, DOM-based"

    def __init__(self, engine):
        super().__init__(engine)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> Dict:
        try:
            with open("payloads/xss.yaml") as f:
                return yaml.safe_load(f)
        except Exception:
            return {
                "reflected": {
                    "basic": [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>",
                    ],
                    "filter_evasion": [],
                    "attribute_injection": [],
                },
                "canary": "wapt_xss_canary_{id}",
            }

    async def run(self) -> List[dict]:
        findings = []
        registry = getattr(self.engine, "input_registry", None)
        if not registry:
            logger.warning("[XSS] No input registry — run scanner phase first")
            registry = {"forms": [], "url_params": []}

        logger.info(
            f"[XSS] Testing {len(registry['forms'])} forms and "
            f"{len(registry['url_params'])} URL params"
        )

        # Test forms
        for form in registry["forms"]:
            form_findings = await self._test_form(form)
            findings.extend(form_findings)

        # Test URL parameters
        for param_info in registry["url_params"]:
            param_findings = await self._test_url_param(param_info)
            findings.extend(param_findings)

        logger.success(f"[XSS] Complete — {len(findings)} XSS findings")
        return findings

    async def _test_form(self, form: Dict) -> List[dict]:
        findings = []
        text_inputs = form.get("text_inputs", [])
        if not text_inputs:
            return findings

        for target_input in text_inputs:
            param_name = target_input["name"]
            logger.debug(f"[XSS] Testing form param: {param_name}")

            # Step 1: Canary test — does this parameter reflect in the response?
            canary, reflects, context = await self._canary_test(
                form["action"], form["method"],
                form["all_inputs"], param_name
            )
            if not reflects:
                continue  # No reflection — skip payload escalation

            logger.debug(
                f"[XSS] Reflection confirmed for '{param_name}' "
                f"(context: {context})"
            )

            # Step 2: Payload escalation — try actual XSS payloads
            finding = await self._test_payloads(
                form["action"], form["method"],
                form["all_inputs"], param_name, context,
                is_url_param=False
            )
            if finding:
                findings.append(finding)

        return findings

    async def _test_url_param(self, param_info: Dict) -> List[dict]:
        findings = []
        base_url = param_info["base_url"]
        param    = param_info["param"]

        logger.debug(f"[XSS] Testing URL param: {param} on {base_url}")

        # Canary test
        canary = f"wapt{uuid.uuid4().hex[:8]}"
        url    = f"{base_url}?{param}={canary}"

        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                reflects = canary in resp.text
                context  = self._detect_context(resp.text, canary) if reflects else "none"
        except Exception:
            return findings

        if not reflects:
            return findings

        # Payload escalation for URL params
        for payload in self._get_payloads_for_context(context):
            try:
                test_url = f"{base_url}?{param}={payload}"
                async with httpx.AsyncClient(
                    timeout=self.engine.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(test_url)
                    executed, evidence = self._check_payload_executed(resp.text, payload)
                    if executed:
                        findings.append(self._make_xss_finding(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            xss_type="Reflected",
                            context=context,
                            evidence=evidence,
                        ))
                        return findings
            except Exception:
                continue

        return findings

    async def _canary_test(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        target_param: str,
    ) -> Tuple[str, bool, str]:
        """
        Inject a unique alphanumeric canary string.
        If it appears unescaped in the response, the parameter reflects.
        Returns (canary, reflects, context).
        """
        canary = f"wapt{uuid.uuid4().hex[:10]}"
        data   = self._build_data(all_inputs, target_param, canary)

        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.config.scan.user_agents[0]},
            ) as client:
                if method == "POST":
                    resp = await client.post(url, data=data)
                else:
                    resp = await client.get(url, params=data)

                reflects = canary in resp.text
                context  = self._detect_context(resp.text, canary) if reflects else "none"
                return canary, reflects, context

        except Exception as e:
            logger.debug(f"[XSS] Canary test failed: {e}")
            return canary, False, "none"

    async def _test_payloads(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        target_param: str,
        context: str,
        is_url_param: bool,
    ) -> Optional[dict]:
        """
        Try payloads appropriate for the detected reflection context.
        Returns the first confirmed finding.
        """
        payloads = self._get_payloads_for_context(context)

        for payload in payloads:
            data = self._build_data(all_inputs, target_param, payload)
            try:
                async with httpx.AsyncClient(
                    timeout=self.engine.timeout,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": self.config.scan.user_agents[0]},
                ) as client:
                    if method == "POST":
                        resp = await client.post(url, data=data)
                    else:
                        resp = await client.get(url, params=data)

                    executed, evidence = self._check_payload_executed(resp.text, payload)
                    if executed:
                        xss_type = "Stored" if method == "POST" else "Reflected"
                        logger.warning(
                            f"[XSS] {xss_type} XSS confirmed! "
                            f"Param: {target_param} | Context: {context}"
                        )
                        return self._make_xss_finding(
                            url=url,
                            parameter=target_param,
                            payload=payload,
                            xss_type=xss_type,
                            context=context,
                            evidence=evidence,
                        )
            except Exception as e:
                logger.debug(f"[XSS] Payload test error: {e}")
                continue

        return None

    def _detect_context(self, html: str, canary: str) -> str:
        """
        Determine where in the HTML the canary appears.
        Context shapes which payloads are most likely to succeed.
        """
        for context_name, pattern in CONTEXT_PATTERNS.items():
            if re.search(pattern.format(canary=re.escape(canary)), html, re.IGNORECASE):
                return context_name
        return "html_tag_body"  # default — most common

    def _get_payloads_for_context(self, context: str) -> List[str]:
        """Select the most relevant payloads for the detected HTML context."""
        reflected = self.payloads.get("reflected", {})
        basic     = reflected.get("basic", [])
        attr      = reflected.get("attribute_injection", [])
        evasion   = reflected.get("filter_evasion", [])

        context_payloads = {
            "html_tag_body":  basic + evasion,
            "html_attribute": attr + basic,
            "js_string":      [
                "';alert(1);//",
                "\";alert(1);//",
                "</script><script>alert(1)</script>",
            ] + basic,
            "url_param":      [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ] + basic,
            "none":           basic[:5],
        }
        return context_payloads.get(context, basic)[:12]

    def _check_payload_executed(
        self, html: str, payload: str
    ) -> Tuple[bool, str]:
        """
        Check if the payload appears unescaped in the HTML response.
        We look for unescaped tag/attribute indicators.
        """
        # Check for unescaped script tag
        if "<script>" in html.lower() and "alert" in html.lower():
            idx = html.lower().find("<script>")
            evidence = html[max(0, idx-20):idx+100]
            return True, evidence

        # Check for unescaped event handler
        event_patterns = [
            r'on\w+\s*=\s*["\']?alert',
            r'onerror\s*=\s*["\']?alert',
            r'onload\s*=\s*["\']?alert',
        ]
        for pattern in event_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                return True, html[start:match.end() + 50]

        # Check for SVG onload
        if re.search(r'<svg[^>]*onload\s*=', html, re.IGNORECASE):
            return True, "SVG onload handler present unescaped"

        return False, ""

    def _build_data(
        self,
        all_inputs: List[Dict],
        target_param: str,
        payload: str
    ) -> Dict[str, str]:
        data = {}
        for inp in all_inputs:
            if inp["name"] == target_param:
                data[inp["name"]] = payload
            else:
                safe = {
                    "password": "SafePass123!",
                    "email": "test@test.com",
                    "number": "1",
                    "hidden": inp.get("value", ""),
                }
                data[inp["name"]] = safe.get(inp.get("type", "text"), inp.get("value", "test"))
        return data

    def _make_xss_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        xss_type: str,
        context: str,
        evidence: str,
    ) -> dict:
        return {
            "title":        f"{xss_type} XSS — {parameter} (context: {context})",
            "severity":     "high",
            "vuln_type":    "xss",
            "url":          url,
            "parameter":    parameter,
            "payload_used": payload,
            "description": (
                f"{xss_type} Cross-Site Scripting was confirmed in parameter '{parameter}'. "
                f"The payload executed in the '{context}' HTML context.\n\n"
                f"An attacker can use this to:\n"
                f"  • Steal session cookies and hijack user accounts\n"
                f"  • Perform actions on behalf of the victim (CSRF via XSS)\n"
                f"  • Redirect users to phishing sites\n"
                f"  • Log keystrokes and capture credentials\n"
                f"  • Install browser-based malware"
            ),
            "evidence":    evidence[:500],
            "remediation": (
                "1. Encode all output based on context:\n"
                "   • HTML body:       HTML-encode (&lt; &gt; &amp; &quot;)\n"
                "   • HTML attribute:  Attribute-encode\n"
                "   • JavaScript:      JS-encode (\\uXXXX)\n"
                "   • URL:             URL-encode (%XX)\n"
                "2. Use framework auto-escaping (Django templates, React JSX).\n"
                "3. Implement a Content Security Policy (CSP).\n"
                "4. Set HttpOnly on session cookies.\n"
                "5. Validate and sanitize input on the server side."
            ),
            "cvss_score":   8.2,
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            "confirmed":        True,
            "is_false_positive": False,
        }
    
    