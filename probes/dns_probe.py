"""DNS reconnaissance probe"""

import asyncio
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
        self.logger.info(f"  → Querying DNS records for {self.target}")

        results = {
            "records": {},
            "findings": [],
            "nameservers": []
        }

        # Configure DNS resolver with timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0  # 3 second timeout per query
        resolver.lifetime = 5.0  # 5 second total timeout per record type

        # Query all record types
        for record_type in self.RECORD_TYPES:
            try:
                # Progress indicator
                self.logger.info(f"  → Checking {record_type} records...")

                # Run DNS query in thread pool to avoid blocking (max 8 seconds)
                answers = await asyncio.wait_for(
                    asyncio.to_thread(resolver.resolve, self.target, record_type),
                    timeout=8.0
                )
                records = [str(rdata) for rdata in answers]
                results["records"][record_type] = records

                if records:
                    self.logger.info(f"  ✓ Found {len(records)} {record_type} record(s)")

                # Analyze findings for security issues
                self._analyze_records(record_type, records, results["findings"])

            except asyncio.TimeoutError:
                # Query took too long
                self.logger.warning(f"  ⏱ {record_type} query timed out")
                results["records"][record_type] = []
            except dns.resolver.NoAnswer:
                # Record type exists but no data
                results["records"][record_type] = []
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist
                self.logger.warning(f"  ✗ Domain does not exist (NXDOMAIN)")
                results["findings"].append(
                    self._create_finding(
                        "critical",
                        "Domain does not exist",
                        f"The domain {self.target} does not exist (NXDOMAIN)",
                        recommendation="Verify the target domain name"
                    )
                )
                break
            except dns.exception.Timeout:
                # DNS query timed out
                self.logger.warning(f"  ⏱ {record_type} query timed out")
                results["records"][record_type] = []
            except Exception as e:
                self.logger.debug(f"  ✗ Error querying {record_type} records: {e}")
                results["records"][record_type] = []

        # Test for zone transfer vulnerability
        if results["records"].get("NS"):
            self.logger.info(f"  → Testing zone transfer vulnerability...")
            results["zone_transfer"] = await self._check_zone_transfer(results["records"]["NS"])

        # Check for DNSSEC protection
        self.logger.info(f"  → Checking DNSSEC configuration...")
        results["dnssec"] = await self._check_dnssec()

        self.logger.info(f"  ✓ DNS probe completed")
        return results

    def _analyze_records(self, record_type: str, records: List[str], findings: List[Dict]):
        """Analyze DNS records for security findings"""

        # Check TXT records for email security
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

        for ns in nameservers[:3]:  # Limit to first 3 nameservers to avoid hanging
            try:
                # Remove trailing dot and quotes
                ns_clean = ns.strip('."')

                # Resolve nameserver IP with timeout
                ns_ip = await asyncio.wait_for(
                    asyncio.to_thread(lambda: str(dns.resolver.resolve(ns_clean, 'A')[0])),
                    timeout=5.0
                )

                # Attempt zone transfer with timeout
                zone = await asyncio.wait_for(
                    asyncio.to_thread(
                        lambda: dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target))
                    ),
                    timeout=10.0
                )

                if zone:
                    results["vulnerable"] = True
                    results["details"].append({
                        "nameserver": ns_clean,
                        "ip": ns_ip,
                        "status": "VULNERABLE"
                    })
            except asyncio.TimeoutError:
                results["details"].append({
                    "nameserver": ns.strip('."'),
                    "status": "timeout"
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
            # Query DNSKEY with timeout
            answers = await asyncio.wait_for(
                asyncio.to_thread(dns.resolver.resolve, self.target, 'DNSKEY'),
                timeout=8.0
            )
            return {
                "enabled": True,
                "keys": [str(rdata) for rdata in answers]
            }
        except asyncio.TimeoutError:
            return {"enabled": False, "error": "DNSSEC query timed out"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"enabled": False}
        except Exception as e:
            return {"enabled": False, "error": str(e)}
