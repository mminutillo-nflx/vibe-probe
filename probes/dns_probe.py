"""DNS reconnaissance probe"""

import dns.resolver
import dns.zone
import dns.query
from typing import Dict, Any, List
from .base_probe import BaseProbe


class DNSProbe(BaseProbe):
    """Comprehensive DNS reconnaissance"""

    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']

    async def scan(self) -> Dict[str, Any]:
        """Perform DNS reconnaissance"""
        results = {
            "records": {},
            "findings": [],
            "nameservers": []
        }

        # Query all record types
        for record_type in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                results["records"][record_type] = records

                # Analyze findings
                self._analyze_records(record_type, records, results["findings"])

            except dns.resolver.NoAnswer:
                results["records"][record_type] = []
            except dns.resolver.NXDOMAIN:
                results["findings"].append(
                    self._create_finding(
                        "critical",
                        "Domain does not exist",
                        f"The domain {self.target} does not exist (NXDOMAIN)",
                        recommendation="Verify the target domain name"
                    )
                )
                break
            except Exception as e:
                self.logger.debug(f"Error querying {record_type} records: {e}")

        # Check for DNS zone transfer vulnerability
        if results["records"].get("NS"):
            results["zone_transfer"] = await self._check_zone_transfer(results["records"]["NS"])

        # Check for DNSSEC
        results["dnssec"] = await self._check_dnssec()

        return results

    def _analyze_records(self, record_type: str, records: List[str], findings: List[Dict]):
        """Analyze DNS records for security findings"""

        if record_type == "TXT":
            for record in records:
                # Check for SPF
                if record.startswith('"v=spf1'):
                    if "~all" in record or "-all" in record:
                        findings.append(
                            self._create_finding(
                                "info",
                                "SPF record configured",
                                f"Domain has SPF configured: {record}"
                            )
                        )
                    else:
                        findings.append(
                            self._create_finding(
                                "medium",
                                "Weak SPF policy",
                                f"SPF record exists but may be too permissive: {record}",
                                recommendation="Consider using '-all' for stricter SPF policy"
                            )
                        )

                # Check for DMARC
                if "_dmarc" in self.target.lower() or "v=DMARC" in record:
                    findings.append(
                        self._create_finding(
                            "info",
                            "DMARC record found",
                            f"Domain has DMARC configured: {record}"
                        )
                    )

        elif record_type == "MX":
            if not records:
                findings.append(
                    self._create_finding(
                        "low",
                        "No MX records",
                        "Domain has no MX records - may not accept email"
                    )
                )

        elif record_type == "CAA":
            if records:
                findings.append(
                    self._create_finding(
                        "info",
                        "CAA records present",
                        "Domain has Certificate Authority Authorization records",
                        data=records
                    )
                )
            else:
                findings.append(
                    self._create_finding(
                        "low",
                        "No CAA records",
                        "Domain lacks CAA records to restrict certificate issuance",
                        recommendation="Consider adding CAA records to prevent unauthorized certificate issuance"
                    )
                )

    async def _check_zone_transfer(self, nameservers: List[str]) -> Dict[str, Any]:
        """Check for DNS zone transfer vulnerability"""
        results = {"vulnerable": False, "details": []}

        for ns in nameservers:
            try:
                # Remove trailing dot and quotes
                ns_clean = ns.strip('."')
                ns_ip = str(dns.resolver.resolve(ns_clean, 'A')[0])

                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target))
                if zone:
                    results["vulnerable"] = True
                    results["details"].append({
                        "nameserver": ns_clean,
                        "ip": ns_ip,
                        "status": "VULNERABLE"
                    })
            except Exception:
                results["details"].append({
                    "nameserver": ns.strip('."'),
                    "status": "protected"
                })

        return results

    async def _check_dnssec(self) -> Dict[str, Any]:
        """Check if DNSSEC is enabled"""
        try:
            answers = dns.resolver.resolve(self.target, 'DNSKEY')
            return {
                "enabled": True,
                "keys": [str(rdata) for rdata in answers]
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"enabled": False}
        except Exception as e:
            return {"enabled": False, "error": str(e)}
