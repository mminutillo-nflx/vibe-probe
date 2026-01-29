"""Subdomain enumeration probe"""

import dns.resolver
from typing import Dict, Any
from .base_probe import BaseProbe


class SubdomainProbe(BaseProbe):
    """Subdomain discovery and enumeration"""

    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'admin', 'blog',
        'dev', 'staging', 'test', 'api', 'cdn', 'shop', 'store', 'portal',
        'vpn', 'remote', 'ssh', 'git', 'mysql', 'db', 'webmail', 'forum'
    ]

    async def scan(self) -> Dict[str, Any]:
        """Enumerate subdomains"""
        results = {
            "subdomains": [],
            "findings": []
        }

        # Brute force common subdomains
        for subdomain in self.COMMON_SUBDOMAINS:
            fqdn = f"{subdomain}.{self.target}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                ips = [str(rdata) for rdata in answers]
                results["subdomains"].append({
                    "subdomain": fqdn,
                    "ips": ips
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                self.logger.debug(f"Error resolving {fqdn}: {e}")

        # Analyze findings
        if results["subdomains"]:
            results["findings"].append(
                self._create_finding(
                    "info",
                    f"{len(results['subdomains'])} subdomains discovered",
                    f"Found {len(results['subdomains'])} active subdomains",
                    data=results["subdomains"]
                )
            )

            # Check for interesting subdomains
            interesting = ['dev', 'staging', 'test', 'admin', 'git', 'db']
            found_interesting = [s for s in results["subdomains"]
                               if any(i in s["subdomain"] for i in interesting)]

            if found_interesting:
                results["findings"].append(
                    self._create_finding(
                        "medium",
                        "Potentially sensitive subdomains found",
                        "Found subdomains that may expose sensitive systems",
                        data=found_interesting,
                        recommendation="Ensure these subdomains have proper access controls"
                    )
                )

        return results
