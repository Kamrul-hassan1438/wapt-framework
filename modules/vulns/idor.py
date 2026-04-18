"""
Insecure Direct Object Reference (IDOR) Testing Module
Tests whether changing an object ID in a URL or form parameter
gives access to another user's data.

IDOR is the #1 bug class in bug bounty programs — simple to test, 
often high severity, frequently missed by automated scanners.
"""
import asyncio
import re
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from loguru import logger
from core.engine import BaseModule


# Patterns that suggest a URL segment or parameter is an object ID
ID_PATTERNS = [
    r'/(\d+)(?:/|$|\?)',          # numeric path segment: /users/42
    r'/([a-f0-9]{24})(?:/|$)',    # MongoDB ObjectId: /items/507f1f77bcf86cd
    r'/([a-f0-9\-]{36})(?:/|$)', # UUID: /orders/550e8400-e29b
    r'[?&]id=(\d+)',              # ?id=42
    r'[?&]user_?id=(\d+)',        # ?user_id=42
    r'[?&]order_?id=(\d+)',       # ?order_id=100
    r'[?&]item_?id=(\d+)',        # ?item_id=5
    r'[?&]account=(\d+)',         # ?account=1001
    r'[?&]file=([^&]+)',          # ?file=report.pdf (path traversal adjacent)
    r'[?&]doc(?:ument)?=([^&]+)', # ?document=invoice_123.pdf
]

# Parameter names that commonly control access
SENSITIVE_PARAMS = {
    "id", "user_id", "userid", "account_id", "account",
    "order_id", "invoice_id", "file", "document", "report",
    "customer_id", "profile_id", "record_id", "item_id",
}


class IDORModule(BaseModule):
    name = "idor"
    description = "IDOR testing — object ID manipulation in URLs and parameters"

    async def run(self) -> List[dict]:
        findings = []
        registry = getattr(self.engine, "input_registry", None)
        if not registry:
            logger.warning("[IDOR] No input registry — run scanner phase first")
            return findings

        all_pages = registry.get("all_pages", [])
        logger.info(f"[IDOR] Scanning {len(all_pages)} pages for IDOR candidates")

        # Find all URL patterns that look like they contain object IDs
        candidates = self._find_id_candidates(all_pages)
        logger.info(f"[IDOR] Found {len(candidates)} IDOR candidate patterns")

        # Test each candidate
        for url, original_id, id_type in candidates:
            finding = await self._test_idor(url, original_id, id_type)
            if finding:
                findings.append(finding)

        # Also test URL parameters from the registry
        for param_info in registry.get("url_params", []):
            param = param_info.get("param", "").lower()
            if param in SENSITIVE_PARAMS:
                finding = await self._test_param_idor(param_info)
                if finding:
                    findings.append(finding)

        logger.success(f"[IDOR] Complete — {len(findings)} IDOR findings")
        return findings

    def _find_id_candidates(
        self, pages: List[str]
    ) -> List[Tuple[str, str, str]]:
        """
        Scan all discovered URLs for patterns that suggest object IDs.
        Returns list of (url, original_id, id_type).
        """
        candidates: Set[Tuple[str, str, str]] = set()

        for url in pages:
            for pattern in ID_PATTERNS:
                match = re.search(pattern, url)
                if match:
                    original_id = match.group(1)
                    id_type     = self._classify_id(original_id, pattern)
                    candidates.add((url, original_id, id_type))
                    break  # One candidate per URL

        return list(candidates)

    def _classify_id(self, id_value: str, pattern: str) -> str:
        """Determine the ID type for generating test values."""
        if re.match(r'^\d+$', id_value):
            return "numeric"
        if re.match(r'^[a-f0-9]{24}$', id_value):
            return "mongodb"
        if re.match(r'^[a-f0-9\-]{36}$', id_value):
            return "uuid"
        return "string"

    def _generate_test_ids(self, original_id: str, id_type: str) -> List[str]:
        """
        Generate plausible test IDs based on the original.
        We test adjacent IDs (original±1) and boundary values.
        """
        if id_type == "numeric":
            try:
                n = int(original_id)
                candidates = [n - 1, n + 1, n - 2, n + 2, 1, 2, 100]
                return [str(c) for c in candidates if c > 0 and c != n]
            except ValueError:
                return []

        if id_type == "mongodb":
            # Try incrementing the last byte
            try:
                last_byte  = int(original_id[-2:], 16)
                new_byte   = format((last_byte + 1) % 256, '02x')
                return [original_id[:-2] + new_byte]
            except Exception:
                return []

        # For UUIDs and strings — limited testing
        return []

    async def _test_idor(
        self,
        url: str,
        original_id: str,
        id_type: str,
    ) -> Optional[dict]:
        """
        Fetch the original URL, then fetch the same URL with modified IDs.
        If both return 200 with similar-sized responses, IDOR is likely.
        """
        test_ids = self._generate_test_ids(original_id, id_type)
        if not test_ids:
            return None

        # Baseline — fetch the original URL
        baseline = await self._fetch(url)
        if not baseline or baseline["status"] != 200:
            return None

        baseline_len = baseline["length"]

        for test_id in test_ids[:3]:  # max 3 test IDs per endpoint
            test_url = url.replace(original_id, test_id, 1)
            if test_url == url:
                continue

            result = await self._fetch(test_url)
            if not result:
                continue

            # Successful access to a different object = IDOR
            if (
                result["status"] == 200
                and result["length"] > 100
                and abs(result["length"] - baseline_len) < baseline_len * 0.8
            ):
                logger.warning(
                    f"[IDOR] Potential IDOR: {url} → {test_url} "
                    f"(baseline {baseline_len}B vs test {result['length']}B)"
                )
                return self._make_idor_finding(
                    original_url=url,
                    test_url=test_url,
                    original_id=original_id,
                    test_id=test_id,
                    original_len=baseline_len,
                    test_len=result["length"],
                )

        return None

    async def _test_param_idor(self, param_info: Dict) -> Optional[dict]:
        """Test IDOR on a URL query parameter."""
        base_url    = param_info["base_url"]
        param       = param_info["param"]
        original_id = "1"  # default to test from ID 1

        baseline = await self._fetch(f"{base_url}?{param}=1")
        if not baseline or baseline["status"] != 200:
            return None

        # Try a different ID
        test_id  = "2"
        test_url = f"{base_url}?{param}={test_id}"
        result   = await self._fetch(test_url)

        if (
            result
            and result["status"] == 200
            and result["length"] > 50
            and abs(result["length"] - baseline["length"]) < baseline["length"] * 0.9
        ):
            return self._make_idor_finding(
                original_url=f"{base_url}?{param}=1",
                test_url=test_url,
                original_id=original_id,
                test_id=test_id,
                original_len=baseline["length"],
                test_len=result["length"],
            )
        return None

    async def _fetch(self, url: str) -> Optional[Dict]:
        try:
            async with httpx.AsyncClient(
                timeout=self.engine.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.config.scan.user_agents[0]},
            ) as client:
                resp = await client.get(url)
                return {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "body":   resp.text[:500],
                }
        except Exception:
            return None

    def _make_idor_finding(
        self,
        original_url: str,
        test_url: str,
        original_id: str,
        test_id: str,
        original_len: int,
        test_len: int,
    ) -> dict:
        return {
            "title":    f"Potential IDOR — Object ID Manipulation Succeeds",
            "severity": "high",
            "vuln_type": "idor",
            "url":      original_url,
            "parameter": "id",
            "payload_used": test_id,
            "description": (
                f"Changing the object ID in the URL from '{original_id}' to '{test_id}' "
                f"returned a successful HTTP 200 response with content ({test_len} bytes). "
                f"This suggests an Insecure Direct Object Reference — the application "
                f"may not verify whether the requesting user is authorized to access "
                f"object #{test_id}.\n\n"
                f"An attacker can cycle through IDs to access other users' data:\n"
                f"  profiles, orders, invoices, messages, documents."
            ),
            "evidence": (
                f"Original URL ({original_id}): HTTP 200, {original_len} bytes\n"
                f"Test URL    ({test_id}): HTTP 200, {test_len} bytes\n"
                f"Test URL: {test_url}"
            ),
            "remediation": (
                "1. Implement object-level authorization on EVERY data access:\n"
                "   Check: does the current user OWN or have PERMISSION to access this object?\n"
                "2. Never rely on obscurity (UUIDs instead of integers does NOT fix IDOR).\n"
                "3. Use indirect references: map session-scoped IDs to real IDs server-side.\n"
                "4. Audit all API endpoints that accept user-supplied IDs.\n\n"
                "Example (Python/Django):\n"
                "  WRONG:  Order.objects.get(id=request.GET['id'])\n"
                "  CORRECT: Order.objects.get(id=request.GET['id'], user=request.user)"
            ),
            "cvss_score": 8.1,
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/639.html",
            ],
            "confirmed": False,  # requires manual verification
            "is_false_positive": False,
        }

        