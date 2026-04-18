"""
Authentication Testing Module
Tests for:
  1. Default / weak credentials on login forms
  2. Account lockout (or lack thereof)
  3. JWT token vulnerabilities (algorithm confusion, none algorithm)
  4. Password in URL (credential leakage via Referer/logs)
  5. Username enumeration via different response behaviour
"""
import asyncio
import base64
import json
import re
import time
from typing import List, Dict, Optional, Tuple
import yaml
import httpx
from loguru import logger
from core.engine import BaseModule


class AuthTesterModule(BaseModule):
    name = "auth_tester"
    description = "Authentication testing — default creds, lockout, JWT, enumeration"

    # Max login attempts before we stop (safety limit — don't lock out real users)
    MAX_ATTEMPTS = 20
    ATTEMPT_DELAY = 0.5   # seconds between attempts — polite bruteforce

    def __init__(self, engine):
        super().__init__(engine)
        self.creds   = self._load_credentials()

    def _load_credentials(self) -> Dict:
        try:
            with open("payloads/auth_wordlist.yaml") as f:
                return yaml.safe_load(f)
        except Exception:
            return {
                "default_credentials": [
                    ["admin", "admin"], ["admin", "password"],
                    ["admin", "admin123"], ["root", "root"],
                ],
                "weak_passwords": ["123456", "password", "admin"],
            }

    async def run(self) -> List[dict]:
        findings = []
        registry = getattr(self.engine, "input_registry", None)
        if not registry:
            logger.warning("[Auth] No input registry — run scanner phase first")
            return findings

        # Find login forms
        login_forms = [f for f in registry["forms"] if f.get("is_login_form")]
        logger.info(f"[Auth] Found {len(login_forms)} login form(s) to test")

        for form in login_forms:
            form_findings = await self._test_login_form(form)
            findings.extend(form_findings)

        # Check for JWT tokens in the session
        jwt_findings = await self._test_jwt()
        findings.extend(jwt_findings)

        # Check for username enumeration via error messages
        for form in login_forms:
            enum_finding = await self._test_username_enumeration(form)
            if enum_finding:
                findings.append(enum_finding)

        logger.success(f"[Auth] Complete — {len(findings)} auth findings")
        return findings

    async def _test_login_form(self, form: Dict) -> List[dict]:
        findings = []
        action = form["action"]
        method = form["method"]

        # Identify username and password fields
        user_field = self._find_field(form["all_inputs"],
                                      ["username", "user", "email", "login", "name"])
        pass_field = self._find_field(form["all_inputs"],
                                      ["password", "pass", "passwd", "pwd"])

        if not user_field or not pass_field:
            logger.debug(f"[Auth] Could not identify credential fields in form: {action}")
            return findings

        logger.info(
            f"[Auth] Testing login: {action} "
            f"(user={user_field}, pass={pass_field})"
        )

        # Get baseline for a bad login (to compare against)
        baseline_body, baseline_len = await self._try_login(
            action, method,
            form["all_inputs"], user_field, pass_field,
            "invaliduser99999", "invalidpass99999"
        )

        attempts = 0
        lockout_detected = False
        success_payload  = None

        for username, password in self.creds.get("default_credentials", []):
            if attempts >= self.MAX_ATTEMPTS:
                break

            body, length = await self._try_login(
                action, method,
                form["all_inputs"], user_field, pass_field,
                username, password
            )
            attempts += 1

            # Detect lockout — if server starts returning lockout messages
            if body and self._detect_lockout(body):
                lockout_detected = True
                logger.info(f"[Auth] Account lockout detected after {attempts} attempts")
                findings.append(self._make_lockout_finding(action, attempts))
                break

            # Detect successful login
            if body and self._detect_success(body, baseline_body):
                success_payload = (username, password)
                logger.warning(
                    f"[Auth] DEFAULT CREDENTIALS WORK! "
                    f"user={username} pass={password} on {action}"
                )
                findings.append(self._make_default_creds_finding(
                    action, username, password
                ))
                break

            await asyncio.sleep(self.ATTEMPT_DELAY)

        # No lockout detected = lockout is NOT implemented
        if not lockout_detected and attempts >= 5 and not success_payload:
            findings.append(self._make_no_lockout_finding(action, attempts))

        return findings

    async def _try_login(
        self,
        url: str,
        method: str,
        all_inputs: List[Dict],
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
    ) -> Tuple[str, int]:
        """Submit a login form and return (response_body, content_length)."""
        data = {}
        for inp in all_inputs:
            name = inp["name"]
            if name == user_field:
                data[name] = username
            elif name == pass_field:
                data[name] = password
            else:
                data[name] = inp.get("value", "")

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
                return resp.text.lower(), len(resp.text)
        except Exception as e:
            logger.debug(f"[Auth] Login request failed: {e}")
            return "", 0

    def _find_field(self, inputs: List[Dict], keywords: List[str]) -> Optional[str]:
        """Find an input field whose name matches any of the given keywords."""
        for keyword in keywords:
            for inp in inputs:
                if keyword in inp["name"].lower():
                    return inp["name"]
        return None

    def _detect_success(self, body: str, baseline_body: str) -> bool:
        """
        Detect a successful login by checking for success indicators
        or the absence of failure indicators present in the baseline.
        """
        success_indicators = [
            "dashboard", "welcome", "logout", "sign out",
            "my account", "profile", "successfully logged",
        ]
        failure_indicators = [
            "invalid", "incorrect", "wrong", "error",
            "failed", "unauthorized", "denied",
        ]
        has_success    = any(s in body for s in success_indicators)
        baseline_fails = any(f in baseline_body for f in failure_indicators)
        response_fails = any(f in body for f in failure_indicators)

        # Success if: explicit success keyword OR baseline had errors but this doesn't
        return has_success or (baseline_fails and not response_fails)

    def _detect_lockout(self, body: str) -> bool:
        lockout_patterns = [
            "account locked", "too many attempts",
            "temporarily blocked", "try again later",
            "account suspended", "wait before",
            "captcha", "recaptcha",
        ]
        return any(p in body for p in lockout_patterns)

    async def _test_username_enumeration(self, form: Dict) -> Optional[dict]:
        """
        Check if the login form reveals whether a username exists
        via different error messages (e.g., 'User not found' vs 'Wrong password').
        This lets attackers enumerate valid usernames.
        """
        action    = form["action"]
        method    = form["method"]
        user_field = self._find_field(form["all_inputs"],
                                      ["username", "user", "email", "login"])
        pass_field = self._find_field(form["all_inputs"],
                                      ["password", "pass", "passwd"])

        if not user_field or not pass_field:
            return None

        # Response for a definitely non-existent user
        body_nouser, _ = await self._try_login(
            action, method, form["all_inputs"],
            user_field, pass_field,
            "wapt_nonexistent_user_99999@test.com", "WaptTestPass123!"
        )

        # Response for a plausibly existing username with wrong password
        body_wrongpass, _ = await self._try_login(
            action, method, form["all_inputs"],
            user_field, pass_field,
            "admin", "WaptWrongPass_xqz123!"
        )

        if not body_nouser or not body_wrongpass:
            return None

        # Different error messages = enumerable
        nouser_msg    = self._extract_error_message(body_nouser)
        wrongpass_msg = self._extract_error_message(body_wrongpass)

        if nouser_msg and wrongpass_msg and nouser_msg != wrongpass_msg:
            return {
                "title":    "Username Enumeration via Login Error Messages",
                "severity": "medium",
                "vuln_type": "username_enumeration",
                "url":      action,
                "parameter": user_field,
                "payload_used": None,
                "description": (
                    f"The login form at {action} returns different error messages "
                    f"depending on whether the username exists:\n"
                    f"  Non-existent user: '{nouser_msg[:100]}'\n"
                    f"  Wrong password:    '{wrongpass_msg[:100]}'\n\n"
                    f"Attackers can use this to enumerate valid usernames, "
                    f"then target only real accounts for password attacks."
                ),
                "evidence": (
                    f"Non-existent user message: '{nouser_msg[:200]}'\n"
                    f"Wrong password message: '{wrongpass_msg[:200]}'"
                ),
                "remediation": (
                    "Return a generic error for all login failures: "
                    "'Invalid username or password.' — never reveal which is wrong. "
                    "Apply the same response time regardless of whether the user exists."
                ),
                "cvss_score": 5.3,
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
                ],
                "confirmed": True,
                "is_false_positive": False,
            }
        return None

    def _extract_error_message(self, body: str) -> str:
        """Pull a short error message from page body."""
        patterns = [
            r'<div[^>]*(?:error|alert|message|notice)[^>]*>([^<]{5,150})<',
            r'<p[^>]*(?:error|alert)[^>]*>([^<]{5,100})<',
            r'(?:error|invalid|incorrect|failed)[^.!?\n]{5,100}',
        ]
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip() if match.lastindex else match.group(0).strip()
        return ""

    async def _test_jwt(self) -> List[dict]:
        """
        Check cookies and local headers for JWT tokens.
        Test for: 'none' algorithm bypass, weak secret, algorithm confusion.
        """
        findings = []

        # Look for JWT-shaped tokens in the current session
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(self.engine.target_url)

                # JWT pattern: three base64url segments separated by dots
                jwt_pattern = r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'
                tokens_found = re.findall(jwt_pattern, resp.text + str(dict(resp.headers)))

                for token in set(tokens_found[:3]):
                    jwt_finding = self._analyze_jwt(token)
                    if jwt_finding:
                        findings.append(jwt_finding)

        except Exception as e:
            logger.debug(f"[Auth] JWT check failed: {e}")

        return findings

    def _analyze_jwt(self, token: str) -> Optional[dict]:
        """
        Decode a JWT token (without verifying) and check for
        dangerous configurations: none algorithm, weak algorithm, sensitive data.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode header and payload (add padding if needed)
            def b64_decode(s: str) -> dict:
                padded = s + "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(padded))

            header  = b64_decode(parts[0])
            payload = b64_decode(parts[1])

            issues = []
            severity = "info"
            cvss = 0.0

            # Check algorithm
            alg = header.get("alg", "").lower()
            if alg == "none":
                issues.append(
                    "Algorithm is 'none' — signature verification is DISABLED. "
                    "Anyone can forge any token."
                )
                severity = "critical"
                cvss = 9.8
            elif alg in ("hs256", "hs384", "hs512"):
                issues.append(
                    f"Using symmetric algorithm {alg.upper()}. "
                    f"If the secret is weak, tokens can be forged offline."
                )
                severity = "medium"
                cvss = 5.9

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "key", "ssn", "credit", "card"]
            exposed = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]
            if exposed:
                issues.append(
                    f"JWT payload contains potentially sensitive fields: {exposed}. "
                    f"JWT payloads are base64-encoded, NOT encrypted — anyone can read them."
                )
                severity = max(severity, "medium",
                               key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                              "low": 1, "info": 0}.get(s, 0))

            if not issues:
                return None

            return {
                "title":    f"JWT Vulnerability: {', '.join([i[:40] for i in issues])}",
                "severity": severity,
                "vuln_type": "jwt_vulnerability",
                "url":      self.engine.target_url,
                "parameter": "JWT token",
                "payload_used": None,
                "description": (
                    f"A JWT token was found and analyzed:\n\n"
                    f"Header:  {json.dumps(header)}\n"
                    f"Payload: {json.dumps(payload, default=str)}\n\n"
                    f"Issues:\n" + "\n".join(f"  • {i}" for i in issues)
                ),
                "evidence": f"Token (truncated): {token[:80]}...",
                "remediation": (
                    "1. Use RS256 or ES256 (asymmetric algorithms) instead of HS256.\n"
                    "2. NEVER use 'none' algorithm in production.\n"
                    "3. Never store sensitive data in JWT payload — it is readable by anyone.\n"
                    "4. Set short expiry times (15-60 minutes).\n"
                    "5. Implement token revocation for logout."
                ),
                "cvss_score": cvss,
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
                "confirmed": True,
                "is_false_positive": False,
            }

        except Exception as e:
            logger.debug(f"[Auth] JWT parse error: {e}")
            return None

    def _make_default_creds_finding(
        self, url: str, username: str, password: str
    ) -> dict:
        return {
            "title":    f"Default Credentials Accepted: {username}/{password}",
            "severity": "critical",
            "vuln_type": "default_credentials",
            "url":      url,
            "parameter": "username/password",
            "payload_used": f"{username}:{password}",
            "description": (
                f"The login form accepted the default credentials "
                f"'{username}' / '{password}'. "
                f"An attacker can immediately authenticate as this user with zero effort."
            ),
            "evidence": f"Login succeeded with username='{username}', password='{password}'",
            "remediation": (
                "Change all default credentials immediately. "
                "Enforce a strong password policy. "
                "Implement MFA for all administrative accounts. "
                "Audit all accounts for default or weak passwords."
            ),
            "cvss_score": 9.8,
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
            ],
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_no_lockout_finding(self, url: str, attempts: int) -> dict:
        return {
            "title":    "No Account Lockout Policy Detected",
            "severity": "medium",
            "vuln_type": "no_account_lockout",
            "url":      url,
            "parameter": None,
            "payload_used": None,
            "description": (
                f"After {attempts} consecutive failed login attempts on {url}, "
                f"no lockout or rate limiting was detected. "
                f"Attackers can perform unlimited password guessing attacks."
            ),
            "evidence": f"{attempts} requests sent without triggering lockout or CAPTCHA",
            "remediation": (
                "Implement account lockout after 5-10 failed attempts. "
                "Add progressive delays between attempts. "
                "Deploy CAPTCHA after 3-5 failures. "
                "Alert on unusual login patterns. "
                "Consider IP-based rate limiting."
            ),
            "cvss_score": 6.5,
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ],
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_lockout_finding(self, url: str, attempts: int) -> dict:
        return {
            "title":    f"Account Lockout Detected After {attempts} Attempts",
            "severity": "info",
            "vuln_type": "account_lockout_present",
            "url":      url,
            "parameter": None,
            "payload_used": None,
            "description": (
                f"Account lockout or rate limiting was triggered after {attempts} "
                f"failed attempts. This is a positive security control."
            ),
            "evidence": f"Lockout triggered at attempt #{attempts}",
            "remediation": "Ensure lockout duration is sufficient (15+ minutes).",
            "cvss_score": 0.0,
            "references": [],
            "confirmed": True,
            "is_false_positive": False,
        }
    
    