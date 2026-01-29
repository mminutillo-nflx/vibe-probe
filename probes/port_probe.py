"""Port scanning probe"""

import socket
import asyncio
from typing import Dict, Any, List
from .base_probe import BaseProbe


class PortProbe(BaseProbe):
    """Network port scanning"""

    # Common ports and their services
    COMMON_PORTS = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        27017: "MongoDB",
    }

    async def scan(self) -> Dict[str, Any]:
        """Perform port scan"""
        results = {
            "open_ports": [],
            "findings": []
        }

        # Resolve target to IP
        try:
            ip = socket.gethostbyname(self.target)
            results["ip_address"] = ip
        except socket.gaierror as e:
            results["error"] = f"Could not resolve hostname: {e}"
            return results

        # Scan common ports
        self.logger.info(f"Scanning {len(self.COMMON_PORTS)} common ports...")

        tasks = [self._scan_port(ip, port) for port in self.COMMON_PORTS.keys()]
        scan_results = await asyncio.gather(*tasks)

        for port, service, is_open in scan_results:
            if is_open:
                results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })

        # Analyze findings
        self._analyze_ports(results["open_ports"], results["findings"])

        return results

    async def _scan_port(self, ip: str, port: int) -> tuple:
        """Scan a single port"""
        service = self.COMMON_PORTS.get(port, "unknown")

        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return (port, service, True)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, service, False)

    def _analyze_ports(self, open_ports: List[Dict], findings: List[Dict]):
        """Analyze open ports for security findings"""

        port_numbers = [p["port"] for p in open_ports]

        # Check for dangerous ports
        dangerous_ports = {
            21: ("FTP without encryption", "high", "Use SFTP or FTPS instead"),
            23: ("Telnet - unencrypted remote access", "critical", "Use SSH instead"),
            445: ("SMB exposed", "high", "Restrict SMB access, use VPN"),
            3389: ("RDP exposed to internet", "critical", "Restrict RDP access, use VPN or jump host"),
            5900: ("VNC exposed", "high", "Restrict VNC access, use strong authentication"),
        }

        for port, (desc, severity, recommendation) in dangerous_ports.items():
            if port in port_numbers:
                findings.append(
                    self._create_finding(
                        severity,
                        f"Dangerous port open: {port}",
                        desc,
                        recommendation=recommendation
                    )
                )

        # Check for database ports
        db_ports = {3306, 5432, 1433, 1521, 27017, 6379}
        exposed_dbs = set(port_numbers) & db_ports
        if exposed_dbs:
            findings.append(
                self._create_finding(
                    "critical",
                    "Database ports exposed",
                    f"Database ports exposed to internet: {sorted(exposed_dbs)}",
                    recommendation="Database ports should not be publicly accessible. Use firewall rules or VPN"
                )
            )

        # Check if no common web ports are open
        if 80 not in port_numbers and 443 not in port_numbers and 8080 not in port_numbers:
            findings.append(
                self._create_finding(
                    "info",
                    "No web services detected",
                    "No common web server ports (80, 443, 8080) are open"
                )
            )

        # General finding about open ports
        if open_ports:
            findings.append(
                self._create_finding(
                    "info",
                    f"{len(open_ports)} open ports detected",
                    f"Open ports: {', '.join(str(p['port']) for p in open_ports)}",
                    data=open_ports
                )
            )
