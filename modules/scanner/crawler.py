"""
Web Crawler Module
Recursively spiders the target website to discover:
  - All internal links and pages
  - All HTML forms (inputs for Phase 4 vuln testing)
  - All URL parameters
  - JavaScript files (may reveal hidden endpoints)
  - Comments in HTML (may reveal developer notes, credentials, internal paths)

Respects scope — never follows links outside the target domain.
"""
import asyncio
import re
from collections import deque
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
import httpx
from bs4 import BeautifulSoup
from loguru import logger

from core.engine import BaseModule


class WebCrawlerModule(BaseModule):
    """
    BFS (breadth-first) crawler that maps the full surface area of the target.
    Results feed directly into Phase 4 vulnerability modules.
    """
    name = "crawler"
    description = "Web crawler — discovers pages, forms, parameters, and JavaScript endpoints"

    MAX_PAGES  = 200   # cap to prevent infinite crawling
    MAX_DEPTH  = 5     # max link depth from start URL
    CONCURRENCY = 10   # concurrent page fetches

    def __init__(self, engine):
        super().__init__(engine)
        self.visited_urls:  Set[str]  = set()
        self.found_forms:   List[Dict] = []
        self.found_params:  Set[str]  = set()  # unique "url?param" combos
        self.found_js_urls: Set[str]  = set()
        self.found_emails:  Set[str]  = set()
        self.html_comments: List[str] = []

    async def run(self) -> List[dict]:
        findings = []
        base_url = self.engine.target_url.rstrip("/")
        logger.info(f"[Crawler] Starting BFS crawl from: {base_url}")
        logger.info(f"[Crawler] Max pages: {self.MAX_PAGES} | Max depth: {self.MAX_DEPTH}")

        await self._crawl(base_url)

        pages_count = len(self.visited_urls)
        logger.success(
            f"[Crawler] Done. Pages: {pages_count} | "
            f"Forms: {len(self.found_forms)} | "
            f"JS files: {len(self.found_js_urls)} | "
            f"Emails: {len(self.found_emails)}"
        )

        # --- Surface map finding (always generated) ---
        findings.append(self._make_surface_finding(base_url))

        # --- Forms finding ---
        if self.found_forms:
            findings.append(self._make_forms_finding(base_url))

        # --- Interesting JS files ---
        if self.found_js_urls:
            js_finding = await self._analyze_js_files()
            if js_finding:
                findings.append(js_finding)

        # --- HTML comments that look sensitive ---
        comment_findings = self._analyze_comments()
        findings.extend(comment_findings)

        # --- Exposed email addresses ---
        if self.found_emails:
            findings.append(self._make_email_finding(base_url))

        return findings

    async def _crawl(self, start_url: str) -> None:
        """
        Breadth-first crawl using asyncio.
        Queue entries are (url, depth) tuples.
        """
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        sem = asyncio.Semaphore(self.CONCURRENCY)

        async def fetch_and_parse(url: str, depth: int):
            """Fetch a page, extract links, forms, and metadata."""
            async with sem:
                if url in self.visited_urls:
                    return []
                if len(self.visited_urls) >= self.MAX_PAGES:
                    return []
                if depth > self.MAX_DEPTH:
                    return []

                self.visited_urls.add(url)

                try:
                    async with httpx.AsyncClient(
                        timeout=self.engine.timeout,
                        follow_redirects=True,
                        verify=False,
                        headers={"User-Agent": self.config.scan.user_agents[0]}
                    ) as client:
                        resp = await client.get(url)

                        content_type = resp.headers.get("content-type", "")
                        if "text/html" not in content_type:
                            return []

                        soup = BeautifulSoup(resp.text, "html.parser")
                        new_links = []

                        # Extract all links
                        for tag in soup.find_all(["a", "link"], href=True):
                            href = tag["href"]
                            abs_url = self._normalize_url(href, url)
                            if abs_url and self._is_in_scope(abs_url):
                                clean = self._strip_fragment(abs_url)
                                if clean not in self.visited_urls:
                                    new_links.append((clean, depth + 1))
                                    # Track URL parameters
                                    self._extract_params(clean)

                        # Extract forms
                        for form in soup.find_all("form"):
                            form_data = self._parse_form(form, url)
                            if form_data:
                                self.found_forms.append(form_data)

                        # Extract script src links
                        for script in soup.find_all("script", src=True):
                            src = script["src"]
                            abs_src = self._normalize_url(src, url)
                            if abs_src:
                                self.found_js_urls.add(abs_src)

                        # Extract email addresses from text
                        emails = re.findall(
                            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                            resp.text
                        )
                        for email in emails:
                            self.found_emails.add(email.lower())

                        # Extract HTML comments
                        comments = soup.find_all(
                            string=lambda text: isinstance(text, str)
                            and text.strip().startswith("<!--")
                        )
                        # BeautifulSoup Comment objects
                        from bs4 import Comment
                        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                            stripped = comment.strip()
                            if len(stripped) > 10:
                                self.html_comments.append({
                                    "url": url,
                                    "comment": stripped[:500]
                                })

                        logger.debug(
                            f"[Crawler] [{resp.status_code}] {url} "
                            f"({len(new_links)} links, {len(soup.find_all('form'))} forms)"
                        )
                        return new_links

                except (httpx.TimeoutException, httpx.ConnectError):
                    return []
                except Exception as e:
                    logger.debug(f"[Crawler] Error on {url}: {e}")
                    return []

        # BFS loop
        while queue and len(self.visited_urls) < self.MAX_PAGES:
            # Process a batch of URLs from the queue concurrently
            batch = []
            while queue and len(batch) < self.CONCURRENCY:
                batch.append(queue.popleft())

            results = await asyncio.gather(
                *[fetch_and_parse(url, depth) for url, depth in batch]
            )

            for new_links in results:
                for link, link_depth in new_links:
                    if link not in self.visited_urls:
                        queue.append((link, link_depth))

    def _normalize_url(self, href: str, base: str) -> Optional[str]:
        """Convert relative URLs to absolute. Skip mailto/tel/javascript."""
        if not href or any(href.startswith(p) for p in
                           ["mailto:", "tel:", "javascript:", "#", "data:"]):
            return None
        try:
            return urljoin(base, href).split("#")[0]
        except Exception:
            return None

    def _is_in_scope(self, url: str) -> bool:
        """Only crawl URLs on the same host as the target."""
        return self.engine.scope.is_url_in_scope(url)

    def _strip_fragment(self, url: str) -> str:
        """Remove URL fragments (#section)."""
        return url.split("#")[0]

    def _extract_params(self, url: str) -> None:
        """Track URLs that have query parameters for later testing."""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in params:
                self.found_params.add(f"{base}?{param}=")

    def _parse_form(self, form_tag, page_url: str) -> Optional[Dict]:
        """Extract form metadata: action, method, and all inputs."""
        try:
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper()
            abs_action = urljoin(page_url, action) if action else page_url
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")

            inputs = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                input_type = inp.get("type", "text").lower()
                input_name = inp.get("name", "")
                input_value = inp.get("value", "")
                if input_name:
                    inputs.append({
                        "name":     input_name,
                        "type":     input_type,
                        "value":    input_value,
                        "required": inp.has_attr("required"),
                    })

            return {
                "page_url":  page_url,
                "action":    abs_action,
                "method":    method,
                "enctype":   enctype,
                "inputs":    inputs,
                "has_csrf_token": any(
                    "csrf" in (i["name"] + i.get("value", "")).lower()
                    for i in inputs
                ),
            }
        except Exception as e:
            logger.debug(f"[Crawler] Form parse error: {e}")
            return None

    async def _analyze_js_files(self) -> Optional[dict]:
        """
        Fetch JavaScript files and look for hardcoded secrets,
        API keys, internal endpoints, and sensitive strings.
        """
        secret_patterns = {
            "API Key":       r"(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{10,})['\"]",
            "AWS Key":       r"AKIA[0-9A-Z]{16}",
            "Secret/Token":  r"(?:secret|token|password|passwd|auth)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "Private Key":   r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "Internal URL":  r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s'\"]*",
            "Bearer Token":  r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        }

        all_findings_text = []
        sem = asyncio.Semaphore(5)

        async def check_js(url: str):
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=10, verify=False) as client:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            return
                        for pattern_name, pattern in secret_patterns.items():
                            matches = re.findall(pattern, resp.text, re.IGNORECASE)
                            for match in matches[:3]:  # max 3 per pattern per file
                                all_findings_text.append(
                                    f"  [{pattern_name}] in {url}: "
                                    f"{str(match)[:80]}"
                                )
                except Exception:
                    pass

        await asyncio.gather(*[check_js(url) for url in list(self.found_js_urls)[:20]])

        if all_findings_text:
            return {
                "title": "Sensitive Data Found in JavaScript Files",
                "severity": "high",
                "vuln_type": "secret_in_js",
                "url": self.engine.target_url,
                "description": (
                    f"Potential secrets or sensitive data found in {len(self.found_js_urls)} "
                    f"JavaScript files:\n\n" + "\n".join(all_findings_text)
                ),
                "evidence": "\n".join(all_findings_text[:10]),
                "remediation": (
                    "Remove all hardcoded secrets from JavaScript. "
                    "Use environment variables and server-side token issuance instead. "
                    "Rotate any exposed keys immediately."
                ),
                "cvss_score": 8.1,
                "references": [
                    "https://owasp.org/www-community/vulnerabilities/Insufficiently_Protected_Credentials"
                ],
                "payload_used": None,
                "confirmed": False,
                "is_false_positive": False,
            }
        return None

    def _analyze_comments(self) -> List[dict]:
        """
        Check HTML comments for sensitive information —
        developers often leave credentials, paths, and TODOs in comments.
        """
        findings = []
        sensitive_keywords = [
            "password", "passwd", "secret", "api_key", "apikey", "token",
            "todo", "fixme", "hack", "debug", "temp", "temporary",
            "credential", "auth", "admin", "internal", "staging",
        ]

        flagged = []
        for c in self.html_comments:
            comment_lower = c["comment"].lower()
            if any(kw in comment_lower for kw in sensitive_keywords):
                flagged.append(c)

        if flagged:
            evidence = "\n".join(
                f"  Page: {c['url']}\n  Comment: {c['comment'][:200]}"
                for c in flagged[:5]
            )
            findings.append({
                "title": f"Sensitive Information in HTML Comments ({len(flagged)} Found)",
                "severity": "low",
                "vuln_type": "info_in_html_comments",
                "url": self.engine.target_url,
                "description": (
                    f"HTML comments containing potentially sensitive keywords were found. "
                    f"HTML source is visible to all users — comments are not a safe "
                    f"place to store any internal information."
                ),
                "evidence": evidence,
                "remediation": (
                    "Remove all HTML comments from production code. "
                    "Ensure build pipelines strip comments before deployment."
                ),
                "cvss_score": 2.7,
                "references": [],
                "payload_used": None,
                "confirmed": True,
                "is_false_positive": False,
            })
        return findings

    def _make_email_finding(self, base_url: str) -> dict:
        return {
            "title": f"Email Addresses Exposed on Website ({len(self.found_emails)} Found)",
            "severity": "info",
            "vuln_type": "exposed_email_addresses",
            "url": base_url,
            "description": (
                f"The following email addresses were found in page content:\n"
                + "\n".join(f"  → {e}" for e in sorted(self.found_emails)[:20])
            ),
            "evidence": str(sorted(self.found_emails)[:20]),
            "remediation": (
                "Consider using contact forms instead of exposing email addresses. "
                "Exposed emails are harvested for spam and phishing campaigns."
            ),
            "cvss_score": 1.0,
            "references": [],
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_surface_finding(self, base_url: str) -> dict:
        lines = [f"Attack surface mapped for {base_url}:\n"]
        lines.append(f"  Pages crawled:    {len(self.visited_urls)}")
        lines.append(f"  Forms discovered: {len(self.found_forms)}")
        lines.append(f"  URL parameters:   {len(self.found_params)}")
        lines.append(f"  JS files:         {len(self.found_js_urls)}")
        lines.append(f"  Emails found:     {len(self.found_emails)}")
        lines.append(f"  HTML comments:    {len(self.html_comments)}")

        if self.found_params:
            lines.append(f"\n  Parametrized URLs (first 10):")
            for p in sorted(self.found_params)[:10]:
                lines.append(f"    {p}")

        return {
            "title": f"Web Surface Map — {len(self.visited_urls)} Pages, {len(self.found_forms)} Forms",
            "severity": "info",
            "vuln_type": "crawl_surface_map",
            "url": base_url,
            "description": "\n".join(lines),
            "evidence": (
                f"Pages: {len(self.visited_urls)} | "
                f"Forms: {len(self.found_forms)} | "
                f"Params: {len(self.found_params)}"
            ),
            "remediation": "Review crawled pages for unintended public exposure.",
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_forms_finding(self, base_url: str) -> dict:
        lines = [f"Forms discovered ({len(self.found_forms)} total):\n"]
        for i, form in enumerate(self.found_forms[:15], 1):
            csrf_status = "✓ has CSRF token" if form["has_csrf_token"] else "✗ NO CSRF token"
            lines.append(
                f"  [{i}] {form['method']} {form['action']}\n"
                f"       Inputs: {[inp['name'] for inp in form['inputs']]} | {csrf_status}"
            )
        return {
            "title": f"Forms Discovered — {len(self.found_forms)} Forms for Vulnerability Testing",
            "severity": "info",
            "vuln_type": "crawl_forms",
            "url": base_url,
            "description": "\n".join(lines),
            "evidence": str([
                {"action": f["action"], "method": f["method"], "inputs": f["inputs"]}
                for f in self.found_forms[:10]
            ]),
            "remediation": "Ensure all forms are protected by CSRF tokens and input validation.",
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }
    
    