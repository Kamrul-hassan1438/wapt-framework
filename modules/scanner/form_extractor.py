"""
Form & Parameter Extractor
Builds a structured, deduplicated registry of every testable input
discovered during crawling. This registry is consumed by Phase 4
vulnerability modules (SQLi, XSS, CSRF, etc.).

Stored on the engine so Phase 4 modules can access it directly:
  engine.input_registry
"""
from typing import List, Dict, Set, Any, Optional
from urllib.parse import urlparse, parse_qs
from loguru import logger
from core.engine import BaseModule


class FormExtractorModule(BaseModule):
    """
    Post-processes crawler results into a clean input registry.
    Must run AFTER WebCrawlerModule in the pipeline.
    """
    name = "form_extractor"
    description = "Builds a structured input registry from crawler results for Phase 4"

    async def run(self) -> List[dict]:
        findings = []

        # Get crawler module results from the engine's module context
        crawler = self._get_crawler_module()
        if not crawler:
            logger.warning("[FormExtractor] No crawler data found — run crawler first")
            return findings

        registry = self._build_registry(crawler)

        # Attach registry to engine for Phase 4 modules
        self.engine.input_registry = registry

        logger.success(
            f"[FormExtractor] Registry built: "
            f"{len(registry['forms'])} forms, "
            f"{len(registry['url_params'])} URL parameter sets"
        )

        # Check for forms missing CSRF tokens — a quick win finding
        csrf_findings = self._check_csrf_protection(registry, crawler)
        findings.extend(csrf_findings)

        # Password fields sent over HTTP (not HTTPS)
        http_password_findings = self._check_password_over_http(registry)
        findings.extend(http_password_findings)

        # Autocomplete on sensitive fields
        autocomplete_findings = self._check_autocomplete(crawler)
        findings.extend(autocomplete_findings)

        return findings

    def _get_crawler_module(self):
        """
        Retrieve the WebCrawlerModule instance from the engine's
        module history (stored after Phase 3 crawler runs).
        """
        return getattr(self.engine, "_crawler_instance", None)

    def _build_registry(self, crawler) -> Dict[str, Any]:
        """Build a clean, deduplicated registry of all testable inputs."""
        forms = []
        seen_actions: Set[str] = set()

        for form in crawler.found_forms:
            # Deduplicate forms by action URL + method
            key = f"{form['method']}:{form['action']}"
            if key in seen_actions:
                continue
            seen_actions.add(key)

            # Separate inputs by type
            text_inputs     = [i for i in form["inputs"] if i["type"] in
                                ("text", "search", "url", "tel", "email", "number", "textarea")]
            password_inputs = [i for i in form["inputs"] if i["type"] == "password"]
            hidden_inputs   = [i for i in form["inputs"] if i["type"] == "hidden"]
            file_inputs     = [i for i in form["inputs"] if i["type"] == "file"]

            forms.append({
                "action":          form["action"],
                "method":          form["method"],
                "page_url":        form["page_url"],
                "enctype":         form["enctype"],
                "text_inputs":     text_inputs,
                "password_inputs": password_inputs,
                "hidden_inputs":   hidden_inputs,
                "file_inputs":     file_inputs,
                "all_inputs":      form["inputs"],
                "has_csrf_token":  form["has_csrf_token"],
                "is_login_form":   self._is_login_form(form),
                "is_search_form":  self._is_search_form(form),
                "is_upload_form":  len(file_inputs) > 0,
            })

        url_params = []
        for param_url in crawler.found_params:
            parsed = urlparse(param_url)
            url_params.append({
                "base_url":  f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                "param":     parsed.query.rstrip("="),
                "full_url":  param_url,
            })

        return {
            "forms":      forms,
            "url_params": url_params,
            "js_files":   list(crawler.found_js_urls),
            "all_pages":  list(crawler.visited_urls),
        }

    def _is_login_form(self, form: Dict) -> bool:
        keywords = {"login", "signin", "sign_in", "username", "email", "password"}
        input_names = {i["name"].lower() for i in form["inputs"]}
        action_lower = form["action"].lower()
        return bool(
            input_names & keywords
            or any(kw in action_lower for kw in ["login", "signin", "auth"])
        )

    def _is_search_form(self, form: Dict) -> bool:
        keywords = {"search", "query", "q", "s", "keyword", "keywords", "term"}
        input_names = {i["name"].lower() for i in form["inputs"]}
        return bool(input_names & keywords)

    def _check_csrf_protection(self, registry: Dict, crawler) -> List[dict]:
        """Flag POST forms that lack CSRF tokens — these are CSRF vulnerable."""
        findings = []
        vulnerable_forms = [
            f for f in registry["forms"]
            if f["method"] == "POST"
            and not f["has_csrf_token"]
            and not f["is_login_form"]  # login forms use credentials as protection
        ]

        if not vulnerable_forms:
            return findings

        form_list = "\n".join(
            f"  POST {f['action']} (from {f['page_url']})"
            for f in vulnerable_forms[:10]
        )
        findings.append({
            "title": f"CSRF Protection Missing on {len(vulnerable_forms)} POST Form(s)",
            "severity": "high",
            "vuln_type": "csrf_missing_token",
            "url": self.engine.target_url,
            "parameter": None,
            "description": (
                f"{len(vulnerable_forms)} POST forms were found without CSRF tokens. "
                f"An attacker can craft a page that silently submits these forms in a "
                f"victim's browser, performing actions on their behalf (change password, "
                f"transfer funds, modify account settings) without their knowledge.\n\n"
                f"Affected forms:\n{form_list}"
            ),
            "evidence": form_list,
            "remediation": (
                "Add a CSRF token to every state-changing form. "
                "Use framework built-ins: Django's {% csrf_token %}, "
                "Laravel's @csrf, Rails' form_authenticity_token. "
                "Validate the token server-side on every POST/PUT/DELETE request."
            ),
            "cvss_score": 8.8,
            "references": [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        })
        return findings

    def _check_password_over_http(self, registry: Dict) -> List[dict]:
        """Flag login/password forms served over plain HTTP."""
        findings = []
        http_password_forms = [
            f for f in registry["forms"]
            if f["password_inputs"]
            and f["action"].startswith("http://")
        ]
        if http_password_forms:
            findings.append({
                "title": "Password Form Submits Over Unencrypted HTTP",
                "severity": "critical",
                "vuln_type": "password_over_http",
                "url": self.engine.target_url,
                "parameter": "password",
                "description": (
                    f"{len(http_password_forms)} form(s) with password fields submit "
                    f"to HTTP (not HTTPS) URLs. Passwords are transmitted in plaintext "
                    f"and can be intercepted by anyone on the network path."
                ),
                "evidence": str([f["action"] for f in http_password_forms]),
                "remediation": (
                    "Force all form submissions to HTTPS. "
                    "Redirect all HTTP traffic to HTTPS at the server level. "
                    "Obtain a free TLS certificate via Let's Encrypt if needed."
                ),
                "cvss_score": 9.1,
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/"
                ],
                "payload_used": None,
                "confirmed": True,
                "is_false_positive": False,
            })
        return findings

    def _check_autocomplete(self, crawler) -> List[dict]:
        """
        Flag password/sensitive fields without autocomplete=off.
        Browsers may cache sensitive field values locally.
        """
        findings = []
        flagged = []
        for form in crawler.found_forms:
            for inp in form["inputs"]:
                if inp["type"] in ("password", "credit-card") and not inp.get("autocomplete"):
                    flagged.append({
                        "form_url": form["action"],
                        "field":    inp["name"]
                    })
        if flagged:
            findings.append({
                "title": f"Autocomplete Enabled on Sensitive Fields ({len(flagged)} Found)",
                "severity": "low",
                "vuln_type": "autocomplete_on_sensitive",
                "url": self.engine.target_url,
                "parameter": None,
                "description": (
                    "Sensitive input fields (password, credit card) do not set "
                    "autocomplete='off'. Browsers may cache these values, exposing "
                    "them to other users on shared computers."
                ),
                "evidence": str(flagged[:5]),
                "remediation": "Add autocomplete='off' to all password and sensitive input fields.",
                "cvss_score": 2.6,
                "references": [],
                "payload_used": None,
                "confirmed": True,
                "is_false_positive": False,
            })
        return findings
    
    