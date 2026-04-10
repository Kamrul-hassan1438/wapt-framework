"""
Subdomain Enumeration Module
Two techniques:
  1. DNS bruteforce via wordlist
  2. Certificate Transparency log lookup (passive, no traffic to target)
"""
import asyncio
import httpx
from pathlib import Path
from typing import List, Set, Optional
from loguru import logger
import dns.resolver
import dns.exception
from core.engine import BaseModule


class SubdomainModule(BaseModule):
    """
    Discovers subdomains through DNS bruteforcing and
    certificate transparency log querying.
    """
    name = "subdomain"
    description = "Subdomain enumeration via wordlist bruteforce + CT logs"

    # Public CT log APIs (no auth required)
    CT_LOG_APIS = [
        "https://crt.sh/?q={domain}&output=json",
        "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
    ]

    async def run(self) -> List[dict]:
        findings = []
        domain = self._extract_domain()
        if not domain:
            return findings

        logger.info(f"[Subdomain] Starting enumeration for: {domain}")
        discovered: Set[str] = set()

        # --- Technique 1: Certificate Transparency Logs (passive) ---
        logger.info("[Subdomain] Querying Certificate Transparency logs...")
        ct_subdomains = await self._query_ct_logs(domain)
        discovered.update(ct_subdomains)
        logger.info(f"[Subdomain] CT logs returned {len(ct_subdomains)} candidates")

        # --- Technique 2: DNS Wordlist Bruteforce ---
        logger.info("[Subdomain] Starting DNS wordlist bruteforce...")
        wordlist_path = Path("payloads/wordlists/subdomains.txt")
        wordlist_subdomains = await self._dns_bruteforce(domain, wordlist_path)
        discovered.update(wordlist_subdomains)
        logger.info(f"[Subdomain] Wordlist found {len(wordlist_subdomains)} subdomains")

        # --- Verify & resolve each discovered subdomain ---
        if discovered:
            logger.info(f"[Subdomain] Verifying {len(discovered)} candidates...")
            verified = await self._verify_subdomains(domain, discovered)

            if verified:
                findings.append(self._make_subdomain_finding(domain, verified))
                logger.success(f"[Subdomain] {len(verified)} live subdomains confirmed")

                # Check for subdomain takeover candidates
                takeover_findings = await self._check_takeover(verified)
                findings.extend(takeover_findings)
        else:
            logger.info("[Subdomain] No subdomains discovered")

        return findings

    def _extract_domain(self) -> Optional[str]:
        from urllib.parse import urlparse
        parsed = urlparse(self.engine.target_url)
        return parsed.hostname

    async def _query_ct_logs(self, domain: str) -> Set[str]:
        """
        Query crt.sh and CertSpotter for certificate transparency records.
        These logs record every SSL cert ever issued — a goldmine for subdomain discovery.
        """
        subdomains: Set[str] = set()

        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # crt.sh query
            try:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        # Each entry can have multiple names (wildcard certs)
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
                    logger.debug(f"[Subdomain] crt.sh returned {len(data)} certificate entries")
            except Exception as e:
                logger.warning(f"[Subdomain] crt.sh query failed: {e}")

        return subdomains

    async def _dns_bruteforce(self, domain: str, wordlist_path: Path) -> Set[str]:
        """
        For each word in the wordlist, check if <word>.<domain> resolves in DNS.
        Uses a semaphore to control concurrency — prevents overwhelming the DNS server.
        """
        if not wordlist_path.exists():
            logger.warning(f"[Subdomain] Wordlist not found: {wordlist_path}")
            return set()

        words = wordlist_path.read_text().splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
        logger.debug(f"[Subdomain] Wordlist loaded: {len(words)} entries")

        found: Set[str] = set()

        # Semaphore prevents sending 1000 DNS queries at once
        sem = asyncio.Semaphore(50)  # 50 concurrent DNS lookups max

        async def check_subdomain(word: str):
            async with sem:
                fqdn = f"{word}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, self._resolve_host, fqdn
                    )
                    if result:
                        found.add(fqdn)
                        logger.debug(f"[Subdomain] ✓ Found: {fqdn} → {result}")
                except Exception:
                    pass

        await asyncio.gather(*[check_subdomain(w) for w in words])
        return found

    def _resolve_host(self, hostname: str) -> Optional[List[str]]:
        """Resolve a hostname to IP addresses. Returns None if not found."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        try:
            answers = resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except Exception:
            return None

    async def _verify_subdomains(self, domain: str, candidates: Set[str]) -> List[dict]:
        """
        For each candidate subdomain, resolve it and try an HTTP request.
        Returns a list of verified subdomains with their IPs and HTTP status.
        """
        verified = []
        sem = asyncio.Semaphore(20)

        async def verify_one(subdomain: str):
            async with sem:
                loop = asyncio.get_event_loop()
                ips = await loop.run_in_executor(None, self._resolve_host, subdomain)
                if not ips:
                    return

                # Try HTTP and HTTPS
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{subdomain}"
                    try:
                        async with httpx.AsyncClient(
                            timeout=5,
                            follow_redirects=True,
                            verify=False  # pentest targets often have self-signed certs
                        ) as client:
                            resp = await client.get(url)
                            verified.append({
                                "subdomain": subdomain,
                                "ips": ips,
                                "url": url,
                                "status_code": resp.status_code,
                                "server": resp.headers.get("server", "unknown"),
                                "title": self._extract_title(resp.text),
                            })
                            return  # stop at first working scheme
                    except Exception:
                        continue

        await asyncio.gather(*[verify_one(s) for s in candidates])
        return verified

    def _extract_title(self, html: str) -> str:
        """Extract <title> from an HTML page."""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else "No title"

    async def _check_takeover(self, verified: List[dict]) -> List[dict]:
        """
        Check for subdomain takeover vulnerability.
        Happens when a subdomain's DNS points to a cloud service (S3, GitHub Pages,
        Heroku, etc.) that no longer has a matching record — the subdomain is
        claimable by an attacker.
        """
        # Service signatures for dangling CNAME detection
        takeover_signatures = {
            "amazonaws.com": "AWS S3",
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "azurewebsites.net": "Azure",
            "cloudapp.net": "Azure",
            "shopify.com": "Shopify",
            "zendesk.com": "Zendesk",
            "ghost.io": "Ghost",
            "surge.sh": "Surge",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
        }

        # Error strings that indicate a dangling record
        dangling_indicators = [
            "NoSuchBucket",
            "There is no app configured at that hostname",
            "No such app",
            "404 Not Found",
            "Repository not found",
            "Project not found",
            "This page does not exist",
        ]

        findings = []
        for sub_info in verified:
            for signature, service in takeover_signatures.items():
                if any(signature in ip for ip in sub_info.get("ips", [])):
                    # Check if the service returns a "not found" style response
                    content_lower = ""
                    try:
                        async with httpx.AsyncClient(timeout=5, verify=False) as client:
                            resp = await client.get(sub_info["url"])
                            content_lower = resp.text.lower()
                    except Exception:
                        pass

                    if any(ind.lower() in content_lower for ind in dangling_indicators):
                        findings.append({
                            "title": f"Subdomain Takeover Risk: {sub_info['subdomain']}",
                            "severity": "high",
                            "vuln_type": "subdomain_takeover",
                            "url": sub_info["url"],
                            "description": (
                                f"The subdomain {sub_info['subdomain']} has a DNS record pointing "
                                f"to {service} ({signature}), but the corresponding resource does "
                                f"not exist on that service. An attacker could register this resource "
                                f"and serve malicious content under your domain."
                            ),
                            "evidence": f"IPs: {sub_info['ips']} | Service: {service}",
                            "remediation": (
                                f"Either remove the DNS record for {sub_info['subdomain']} if the "
                                f"{service} resource is no longer needed, or re-create the resource "
                                f"on {service} to prevent unauthorized claiming."
                            ),
                            "cvss_score": 8.1,
                            "references": [
                                "https://owasp.org/www-project-web-security-testing-guide/",
                                "https://github.com/EdOverflow/can-i-take-over-xyz"
                            ],
                            "parameter": None,
                            "payload_used": None,
                            "confirmed": False,
                            "is_false_positive": False,
                        })
        return findings

    def _make_subdomain_finding(self, domain: str, verified: List[dict]) -> dict:
        """Package all verified subdomains as a single informational finding."""
        lines = [f"Discovered {len(verified)} live subdomains for {domain}:\n"]
        for s in sorted(verified, key=lambda x: x["subdomain"]):
            lines.append(
                f"  {s['subdomain']:<40} {str(s['ips']):<30} "
                f"HTTP {s['status_code']} | {s['server']} | {s['title']}"
            )

        return {
            "title": f"Subdomain Enumeration Results — {len(verified)} Found",
            "severity": "info",
            "vuln_type": "recon_subdomains",
            "url": self.engine.target_url,
            "description": "\n".join(lines),
            "evidence": str([s["subdomain"] for s in verified]),
            "remediation": (
                "Review all discovered subdomains. Ensure test/dev/staging subdomains "
                "are not publicly accessible without authentication. Remove stale DNS records."
            ),
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }