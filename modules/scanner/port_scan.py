"""
Port Scanner Module
Wraps Nmap to discover open ports and identify running services.
Service banners reveal exact software versions — critical for CVE matching.

Requires: nmap installed on the system
  Linux:   sudo apt install nmap
  macOS:   brew install nmap
  Windows: https://nmap.org/download.html
"""
import asyncio
import socket
import subprocess
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from loguru import logger

from core.engine import BaseModule


# Port groups we scan depending on scan intensity
PORT_PROFILES = {
    "quick":    "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,27017",
    "common":   "1-1024",
    "extended": "1-10000",
    "full":     "1-65535",
}

# Well-known service risk map — ports that are interesting from a pentest perspective
RISKY_SERVICES = {
    21:    ("FTP",         "medium", 5.3,
            "FTP transfers credentials and data in plaintext."),
    22:    ("SSH",         "info",   0.0,
            "SSH is present. Check for weak credentials and outdated versions."),
    23:    ("Telnet",      "high",   7.5,
            "Telnet transmits all data including passwords in cleartext."),
    25:    ("SMTP",        "medium", 5.0,
            "SMTP exposed. Check for open relay and version vulnerabilities."),
    53:    ("DNS",         "info",   0.0,
            "DNS service exposed. Checked for zone transfer in recon phase."),
    110:   ("POP3",        "medium", 5.3,
            "POP3 may transmit credentials in plaintext without STARTTLS."),
    143:   ("IMAP",        "medium", 5.3,
            "IMAP may transmit credentials in plaintext without STARTTLS."),
    445:   ("SMB",         "high",   8.1,
            "SMB exposed to internet. High risk of EternalBlue and ransomware."),
    1433:  ("MSSQL",       "high",   7.5,
            "Microsoft SQL Server exposed. Should not be internet-facing."),
    3306:  ("MySQL",       "high",   7.5,
            "MySQL database port exposed to internet — critical risk."),
    3389:  ("RDP",         "high",   7.5,
            "Remote Desktop Protocol exposed. Frequent brute force target."),
    5432:  ("PostgreSQL",  "high",   7.5,
            "PostgreSQL exposed to internet — critical risk."),
    5900:  ("VNC",         "high",   8.0,
            "VNC exposed. Often weakly authenticated or unauthenticated."),
    6379:  ("Redis",       "critical", 9.8,
            "Redis is commonly unauthenticated. Full data access and often RCE."),
    8080:  ("HTTP-Alt",    "info",   0.0,
            "Alternate HTTP port. May expose dev server or admin interface."),
    8443:  ("HTTPS-Alt",   "info",   0.0,
            "Alternate HTTPS port. Check for admin interfaces."),
    9200:  ("Elasticsearch","critical", 9.8,
            "Elasticsearch often has no authentication. Full data access."),
    27017: ("MongoDB",     "critical", 9.8,
            "MongoDB exposed. Often no authentication in default config."),
}


class PortScanModule(BaseModule):
    """
    Discovers open ports and running services on the target host.
    Uses Nmap for reliable SYN scanning with service version detection.
    Falls back to asyncio socket scanning if Nmap is not installed.
    """
    name = "port_scan"
    description = "Port scanning and service fingerprinting via Nmap"

    def __init__(self, engine, profile: str = "quick"):
        super().__init__(engine)
        self.profile = profile
        self.ports = PORT_PROFILES.get(profile, PORT_PROFILES["quick"])

    async def run(self) -> List[dict]:
        findings = []
        host = self._extract_host()
        if not host:
            logger.warning("[PortScan] Could not extract host from target URL")
            return findings

        logger.info(f"[PortScan] Scanning {host} — profile: {self.profile}")

        # Resolve hostname to IP first
        ip = await self._resolve_ip(host)
        if not ip:
            logger.warning(f"[PortScan] Could not resolve {host}")
            return findings

        logger.info(f"[PortScan] Target IP: {ip}")

        # Try Nmap first, fall back to socket scan
        nmap_available = await self._check_nmap()
        if nmap_available:
            logger.info("[PortScan] Nmap detected — using Nmap scanner")
            open_ports = await self._nmap_scan(ip)
        else:
            logger.warning("[PortScan] Nmap not found — using socket fallback scanner")
            open_ports = await self._socket_scan(ip)

        if not open_ports:
            logger.info("[PortScan] No open ports found in scanned range")
            return findings

        logger.success(f"[PortScan] Found {len(open_ports)} open ports")

        # Package all open ports as an informational finding
        findings.append(self._make_ports_summary(host, ip, open_ports))

        # Flag risky services as individual findings
        for port_info in open_ports:
            port_num = port_info["port"]
            risk_finding = self._assess_risk(host, port_num, port_info)
            if risk_finding:
                findings.append(risk_finding)

        return findings

    def _extract_host(self) -> Optional[str]:
        return urlparse(self.engine.target_url).hostname

    async def _resolve_ip(self, host: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, socket.gethostbyname, host
            )
            return result
        except socket.gaierror as e:
            logger.error(f"[PortScan] DNS resolution failed: {e}")
            return None

    async def _check_nmap(self) -> bool:
        """Check whether nmap is installed and accessible.
        
        Uses subprocess.run in executor to work on Windows (asyncio.create_subprocess_exec
        has limitations on Windows).
        """
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, self._sync_check_nmap_available)
            return result
        except Exception as e:
            logger.debug(f"[PortScan] Nmap check failed: {e}")
            return False

    def _sync_check_nmap_available(self) -> bool:
        """Synchronous nmap availability check — runs in thread pool."""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                shell=False
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    async def _nmap_scan(self, ip: str) -> List[Dict[str, Any]]:
        """
        Run Nmap with service version detection (-sV) and default scripts (-sC).
        -T4 = aggressive timing (faster but noisier).
        --open = show only open ports.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_nmap_scan, ip)

    def _sync_nmap_scan(self, ip: str) -> List[Dict[str, Any]]:
        """Synchronous Nmap scan — runs in thread pool."""
        try:
            import nmap
            nm = nmap.PortScanner()
            logger.debug(f"[PortScan] Running: nmap -sV -sC -T4 --open -p {self.ports} {ip}")
            nm.scan(
                hosts=ip,
                ports=self.ports,
                arguments="-sV -T4 --open --version-intensity 5",
            )

            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        if state == "open":
                            svc = nm[host][proto][port]
                            open_ports.append({
                                "port":    port,
                                "proto":   proto,
                                "state":   state,
                                "service": svc.get("name", "unknown"),
                                "product": svc.get("product", ""),
                                "version": svc.get("version", ""),
                                "extrainfo": svc.get("extrainfo", ""),
                                "cpe":     svc.get("cpe", ""),
                            })
            return open_ports

        except ImportError:
            logger.warning("[PortScan] python-nmap not installed — falling back to socket scan")
            return self._sync_socket_scan_ip(ip)
        except Exception as e:
            logger.error(f"[PortScan] Nmap error: {e}")
            return []

    async def _socket_scan(self, ip: str) -> List[Dict[str, Any]]:
        """
        Async TCP socket scanner — fallback when Nmap is unavailable.
        Less accurate than Nmap (no service detection) but requires no dependencies.
        """
        # Parse port range
        ports_to_scan = self._parse_ports(self.ports)
        logger.info(f"[PortScan] Socket scanning {len(ports_to_scan)} ports on {ip}")

        sem = asyncio.Semaphore(200)  # max 200 concurrent connections
        open_ports = []

        async def check_port(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                    writer.close()
                    await writer.wait_closed()

                    # Grab banner if available
                    banner = ""
                    try:
                        banner_data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                        banner = banner_data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass

                    open_ports.append({
                        "port":    port,
                        "proto":   "tcp",
                        "state":   "open",
                        "service": self._guess_service(port),
                        "product": banner[:80] if banner else "",
                        "version": "",
                        "extrainfo": "",
                        "cpe":     "",
                    })
                    logger.debug(f"[PortScan] Port {port}/tcp OPEN")
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        await asyncio.gather(*[check_port(p) for p in ports_to_scan])
        return sorted(open_ports, key=lambda x: x["port"])

    def _sync_socket_scan_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Sync socket scan for use in thread pool."""
        import socket as sock
        ports_to_scan = self._parse_ports(self.ports)
        open_ports = []
        for port in ports_to_scan:
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    open_ports.append({
                        "port": port, "proto": "tcp", "state": "open",
                        "service": self._guess_service(port), "product": "",
                        "version": "", "extrainfo": "", "cpe": "",
                    })
            except Exception:
                pass
        return open_ports

    def _parse_ports(self, ports_str: str) -> List[int]:
        """Convert a port string like '80,443,1-1024' into a list of ints."""
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _guess_service(self, port: int) -> str:
        """Guess service name from well-known port numbers."""
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 1433: "mssql", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
            27017: "mongodb",
        }
        return known.get(port, "unknown")

    def _assess_risk(
        self,
        host: str,
        port: int,
        port_info: Dict[str, Any]
    ) -> Optional[dict]:
        """
        If an open port is in our risky services list, generate a finding.
        Includes the service version in the evidence for CVE research.
        """
        if port not in RISKY_SERVICES:
            return None

        service_name, severity, cvss, risk_desc = RISKY_SERVICES[port]
        version_str = " ".join(filter(None, [
            port_info.get("product", ""),
            port_info.get("version", ""),
            port_info.get("extrainfo", ""),
        ])).strip()

        return {
            "title": f"Risky Service Exposed: {service_name} on port {port}",
            "severity": severity,
            "vuln_type": "exposed_service",
            "url": self.engine.target_url,
            "parameter": f"port:{port}",
            "description": (
                f"{service_name} (port {port}/tcp) is accessible on {host}. "
                f"{risk_desc}"
                + (f" Detected version: {version_str}." if version_str else "")
            ),
            "evidence": (
                f"Port {port}/tcp OPEN | Service: {port_info.get('service')} | "
                f"Product: {version_str or 'unknown'} | CPE: {port_info.get('cpe', 'N/A')}"
            ),
            "remediation": (
                f"If {service_name} on port {port} does not need to be internet-facing, "
                f"block it at the firewall immediately. If it must be exposed, ensure "
                f"it is fully patched, uses strong authentication, and is monitored."
            ),
            "cvss_score": cvss,
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Network_Infrastructure_Configuration/"
            ],
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }

    def _make_ports_summary(
        self,
        host: str,
        ip: str,
        open_ports: List[Dict[str, Any]]
    ) -> dict:
        lines = [f"Open ports on {host} ({ip}):\n"]
        lines.append(f"  {'PORT':<10} {'PROTO':<8} {'SERVICE':<15} {'VERSION'}")
        lines.append(f"  {'-'*55}")
        for p in open_ports:
            version = " ".join(filter(None, [p.get("product"), p.get("version")])) or "-"
            lines.append(
                f"  {str(p['port']) + '/' + p['proto']:<10} "
                f"{p['proto']:<8} "
                f"{p['service']:<15} "
                f"{version[:40]}"
            )

        return {
            "title": f"Port Scan Results — {len(open_ports)} Open Ports on {host}",
            "severity": "info",
            "vuln_type": "port_scan_results",
            "url": self.engine.target_url,
            "description": "\n".join(lines),
            "evidence": str([f"{p['port']}/{p['proto']}" for p in open_ports]),
            "remediation": (
                "Close all ports that do not need to be publicly accessible. "
                "Apply firewall rules at both the OS and network level. "
                "Use a principle of least exposure — if unsure, block it."
            ),
            "cvss_score": 0.0,
            "references": [],
            "parameter": None,
            "payload_used": None,
            "confirmed": True,
            "is_false_positive": False,
        }
    