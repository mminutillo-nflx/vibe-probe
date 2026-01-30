"""SSL/TLS certificate probe"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .base_probe import BaseProbe


class SSLProbe(BaseProbe):
    """SSL/TLS certificate analysis"""

    async def scan(self) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        self.logger.info(f"  → Analyzing SSL/TLS certificate for {self.target}")

        results = {
            "certificate": {},
            "findings": [],
            "vulnerabilities": []
        }

        try:
            # Get certificate
            self.logger.info(f"  → Connecting to {self.target}:443...")
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    # Parse certificate
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                    results["certificate"] = {
                        "subject": cert_dict.get("subject"),
                        "issuer": cert_dict.get("issuer"),
                        "version": cert.version.name,
                        "serial_number": str(cert.serial_number),
                        "not_before": cert.not_valid_before_utc.isoformat(),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "san": self._get_san(cert),
                        "key_size": cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None,
                    }

                    # Check SSL/TLS version
                    results["protocol"] = ssock.version()
                    self.logger.info(f"  ✓ Connected using {ssock.version()}")

                    # Analyze certificate
                    self.logger.info(f"  → Analyzing certificate details...")
                    self._analyze_certificate(cert, results["findings"])

                    # Check for known vulnerabilities
                    self.logger.info(f"  → Checking for SSL/TLS vulnerabilities...")
                    self._check_vulnerabilities(ssock, results["vulnerabilities"])

        except socket.timeout:
            results["findings"].append(
                self._create_finding(
                    "medium",
                    "Connection timeout",
                    f"Unable to connect to {self.target}:443 - connection timed out"
                )
            )
        except ssl.SSLError as e:
            results["findings"].append(
                self._create_finding(
                    "high",
                    "SSL/TLS error",
                    f"SSL/TLS error encountered: {str(e)}",
                    recommendation="Check SSL/TLS configuration"
                )
            )
        except Exception as e:
            results["error"] = str(e)
            self.logger.debug(f"SSL probe error: {e}")

        self.logger.info(f"  ✓ SSL probe completed")
        return results

    def _get_san(self, cert) -> list:
        """Extract Subject Alternative Names"""
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [str(name) for name in san_ext.value]
        except x509.ExtensionNotFound:
            return []

    def _analyze_certificate(self, cert, findings: list):
        """Analyze certificate for security issues"""

        # Check expiration
        now = datetime.now()
        days_until_expiry = (cert.not_valid_after_utc.replace(tzinfo=None) - now).days

        if days_until_expiry < 0:
            findings.append(
                self._create_finding(
                    "critical",
                    "Certificate expired",
                    f"Certificate expired {abs(days_until_expiry)} days ago",
                    recommendation="Renew SSL/TLS certificate immediately"
                )
            )
        elif days_until_expiry < 30:
            findings.append(
                self._create_finding(
                    "high",
                    "Certificate expiring soon",
                    f"Certificate expires in {days_until_expiry} days",
                    recommendation="Renew SSL/TLS certificate"
                )
            )

        # Check key size
        try:
            key_size = cert.public_key().key_size
            if key_size < 2048:
                findings.append(
                    self._create_finding(
                        "critical",
                        "Weak key size",
                        f"Certificate uses {key_size}-bit key",
                        recommendation="Use at least 2048-bit RSA or 256-bit ECC keys"
                    )
                )
        except AttributeError:
            pass

        # Check signature algorithm
        sig_alg = cert.signature_algorithm_oid._name
        if 'sha1' in sig_alg.lower():
            findings.append(
                self._create_finding(
                    "high",
                    "Weak signature algorithm",
                    f"Certificate uses SHA-1: {sig_alg}",
                    recommendation="Use SHA-256 or stronger"
                )
            )
        elif 'md5' in sig_alg.lower():
            findings.append(
                self._create_finding(
                    "critical",
                    "Critically weak signature algorithm",
                    f"Certificate uses MD5: {sig_alg}",
                    recommendation="Replace certificate immediately with SHA-256 or stronger"
                )
            )

        # Check if self-signed
        if cert.issuer == cert.subject:
            findings.append(
                self._create_finding(
                    "medium",
                    "Self-signed certificate",
                    "Certificate is self-signed",
                    recommendation="Use certificate from trusted CA for production"
                )
            )

    def _check_vulnerabilities(self, ssock, vulnerabilities: list):
        """Check for known SSL/TLS vulnerabilities"""

        protocol = ssock.version()

        # Check for outdated protocols
        if protocol in ['SSLv2', 'SSLv3']:
            vulnerabilities.append(
                self._create_finding(
                    "critical",
                    f"{protocol} enabled",
                    f"Outdated and vulnerable protocol {protocol} is enabled",
                    recommendation="Disable SSLv2 and SSLv3, use TLS 1.2 or higher"
                )
            )
        elif protocol == 'TLSv1':
            vulnerabilities.append(
                self._create_finding(
                    "high",
                    "TLS 1.0 enabled",
                    "TLS 1.0 is deprecated and should be disabled",
                    recommendation="Use TLS 1.2 or TLS 1.3"
                )
            )
        elif protocol == 'TLSv1.1':
            vulnerabilities.append(
                self._create_finding(
                    "medium",
                    "TLS 1.1 enabled",
                    "TLS 1.1 is deprecated",
                    recommendation="Prefer TLS 1.2 or TLS 1.3"
                )
            )
