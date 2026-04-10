"""
DNS Recon Module
Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records.
Attempts DNS zone transfer (AXFR) — a critical misconfiguration to detect.
"""
import asyncio
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from loguru import logger
from core.engine import BaseModule


# Record types we query for every target
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]


class DNSModule(BaseModule):
    """
    Resolves DNS records for the target domain and checks for
    zone transfer vulnerabilities (AXFR).
    """
    name = "dns"
    description = "DNS record enumeration and zone transfer check"

    async def run(self) -> List[dict]:
        findings = []
        domain = self._extract_domain()

        if not domain:
            logger.warning("[DNS] Could not extract domain from target URL")
            return findings

        logger.info(f"[DNS] Enumerating records for: {domain}")

        # Run DNS queries concurrently for all record types
        record_tasks = [
            self._query_record(domain, rtype)
            for rtype in DNS_RECORD_TYPES
        ]
        all_records = await asyncio.gather(*record_tasks, return_exceptions=True)

        # Collect valid results
        dns_data: Dict[str, List[str]] = {}
        for rtype, result in zip(DNS_RECORD_TYPES, all_records):
            if isinstance(result, Exception):
                logger.debug(f"[DNS] {rtype} lookup failed: {result}")
                continue
            if result:
                dns_data[rtype] = result
                logger.debug(f"[DNS] {rtype}: {result}")

        # Log what we found as an informational finding
        if dns_data:
            findings.append(self._make_finding(
                title=f"DNS Records Enumerated for {domain}",
                severity="info",
                vuln_type="recon_dns",
                url=self.engine.target_url,
                description=self._format_dns_records(dns_data),
                evidence=str(dns_data),
                remediation="Ensure no sensitive information is exposed in TXT or other records.",
                cvss_score=0.0,
                references=["https://owasp.org/www-project-web-security-testing-guide/"]
            ))

        # Zone transfer attempt — using NS servers from the records
        ns_servers = dns_data.get("NS", [])
        for ns in ns_servers:
            zone_finding = await self._attempt_zone_transfer(domain, ns.rstrip("."))
            if zone_finding:
                findings.append(zone_finding)

        # Check for email-related misconfigurations in TXT records
        txt_records = dns_data.get("TXT", [])
        spf_finding = self._check_spf(domain, txt_records)
        if spf_finding:
            findings.append(spf_finding)

        logger.success(f"[DNS] Done. {len(dns_data)} record types found, {len(findings)} findings.")
        return findings

    def _extract_domain(self) -> Optional[str]:
        """Pull the bare domain (no port, no scheme) from the target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(self.engine.target_url)
        host = parsed.hostname
        return host

    async def _query_record(self, domain: str, rtype: str) -> List[str]:
        """
        Run a DNS query in a thread pool (dnspython is sync).
        Returns a list of string representations of the answers.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_query, domain, rtype)

    def _sync_query(self, domain: str, rtype: str) -> List[str]:
        """Synchronous DNS query — runs in thread pool."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        try:
            answers = resolver.resolve(domain, rtype)
            results = []
            for rdata in answers:
                results.append(str(rdata))
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception as e:
            raise e

    async def _attempt_zone_transfer(self, domain: str, ns_server: str) -> Optional[dict]:
        """
        Attempt a DNS zone transfer (AXFR) against a nameserver.
        A successful zone transfer is a High severity finding — it leaks
        the entire DNS zone, exposing all subdomains and internal IPs.
        """
        logger.debug(f"[DNS] Attempting zone transfer: {domain} via {ns_server}")
        loop = asyncio.get_event_loop()
        try:
            zone_data = await loop.run_in_executor(
                None, self._sync_zone_transfer, domain, ns_server
            )
            if zone_data:
                logger.warning(f"[DNS] ZONE TRANSFER SUCCEEDED via {ns_server}!")
                return self._make_finding(
                    title="DNS Zone Transfer Allowed (AXFR)",
                    severity="high",
                    vuln_type="dns_zone_transfer",
                    url=self.engine.target_url,
                    description=(
                        f"The nameserver {ns_server} allows unauthenticated DNS zone transfers. "
                        f"This exposes all DNS records for '{domain}', including internal hostnames, "
                        f"mail servers, and IP addresses. Attackers can use this to map the full "
                        f"infrastructure before launching targeted attacks."
                    ),
                    evidence=zone_data[:2000],  # truncate for storage
                    remediation=(
                        "Restrict zone transfers to authorized secondary nameservers only "
                        "using ACLs. In BIND: 'allow-transfer { <trusted-ns-ip>; };'. "
                        "Never allow transfers from 'any'."
                    ),
                    cvss_score=7.5,
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ]
                )
        except Exception as e:
            logger.debug(f"[DNS] Zone transfer failed for {ns_server}: {e}")
        return None

    def _sync_zone_transfer(self, domain: str, ns_server: str) -> Optional[str]:
        """Attempt AXFR synchronously. Returns raw zone text or None."""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=10))
            lines = []
            for name, node in zone.nodes.items():
                lines.append(zone[name].to_text(name))
            return "\n".join(lines)
        except Exception:
            return None

    def _check_spf(self, domain: str, txt_records: List[str]) -> Optional[dict]:
        """
        Check TXT records for SPF configuration issues.
        Missing or misconfigured SPF allows email spoofing.
        """
        spf_records = [r for r in txt_records if "v=spf1" in r.lower()]

        if not spf_records:
            return self._make_finding(
                title="Missing SPF Record — Email Spoofing Risk",
                severity="medium",
                vuln_type="dns_missing_spf",
                url=self.engine.target_url,
                description=(
                    f"No SPF (Sender Policy Framework) TXT record was found for '{domain}'. "
                    f"Without SPF, attackers can send emails appearing to come from this domain, "
                    f"enabling phishing and social engineering attacks."
                ),
                evidence="No TXT records matching 'v=spf1' found.",
                remediation=(
                    "Add an SPF TXT record to your DNS zone. Example: "
                    "'v=spf1 include:_spf.google.com ~all'. "
                    "Also consider DKIM and DMARC records for full email authentication."
                ),
                cvss_score=5.3,
                references=["https://datatracker.ietf.org/doc/html/rfc7208"]
            )

        # Check for overly permissive SPF
        for record in spf_records:
            if "+all" in record:
                return self._make_finding(
                    title="Permissive SPF Record (+all) Detected",
                    severity="high",
                    vuln_type="dns_permissive_spf",
                    url=self.engine.target_url,
                    description=(
                        f"The SPF record for '{domain}' uses '+all' which allows ANY server "
                        f"on the internet to send email on behalf of this domain. "
                        f"This completely defeats the purpose of SPF."
                    ),
                    evidence=record,
                    remediation=(
                        "Change '+all' to '~all' (softfail) or '-all' (hardfail). "
                        "'-all' is the most secure option: it instructs receiving servers "
                        "to reject emails from unlisted senders."
                    ),
                    cvss_score=7.2,
                    references=["https://datatracker.ietf.org/doc/html/rfc7208#section-5.7"]
                )
        return None

    def _format_dns_records(self, dns_data: Dict[str, List[str]]) -> str:
        """Format DNS data into a readable description."""
        lines = ["DNS records discovered:\n"]
        for rtype, records in dns_data.items():
            lines.append(f"  {rtype}:")
            for r in records:
                lines.append(f"    → {r}")
        return "\n".join(lines)

    def _make_finding(
        self,
        title: str,
        severity: str,
        vuln_type: str,
        url: str,
        description: str,
        evidence: str,
        remediation: str,
        cvss_score: float,
        references: List[str],
    ) -> dict:
        """
        Build a standardized finding dict.
        This structure matches the Finding model in db/models.py.
        """
        return {
            "title": title,
            "severity": severity,
            "vuln_type": vuln_type,
            "url": url,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "cvss_score": cvss_score,
            "references": references,
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }