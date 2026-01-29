"""Security headers probe"""

import aiohttp
from typing import Dict, Any
from .base_probe import BaseProbe


class SecurityHeadersProbe(BaseProbe):
    """Analyze HTTP security headers"""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'HSTS header missing - site vulnerable to SSL stripping',
            'recommendation': 'Add Strict-Transport-Security header with max-age'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'X-Frame-Options header missing - vulnerable to clickjacking',
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'description': 'X-Content-Type-Options header missing - vulnerable to MIME sniffing',
            'recommendation': 'Add X-Content-Type-Options: nosniff'
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'description': 'CSP header missing - vulnerable to XSS attacks',
            'recommendation': 'Implement Content-Security-Policy header'
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'description': 'X-XSS-Protection header missing',
            'recommendation': 'Add X-XSS-Protection: 1; mode=block (legacy browsers)'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': 'Referrer-Policy header missing',
            'recommendation': 'Add Referrer-Policy to control referrer information'
        },
        'Permissions-Policy': {
            'severity': 'low',
            'description': 'Permissions-Policy header missing',
            'recommendation': 'Add Permissions-Policy to control browser features'
        }
    }

    async def scan(self) -> Dict[str, Any]:
        """Analyze security headers"""
        results = {
            "headers": {},
            "missing_headers": [],
            "findings": [],
            "score": 0
        }

        # Check HTTPS endpoint
        url = f"https://{self.target}"

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True) as response:
                    headers = dict(response.headers)

                    # Check for security headers
                    for header_name, header_info in self.SECURITY_HEADERS.items():
                        if header_name in headers:
                            results["headers"][header_name] = headers[header_name]
                            results["score"] += 1

                            # Analyze header value
                            self._analyze_header(
                                header_name,
                                headers[header_name],
                                results["findings"]
                            )
                        else:
                            results["missing_headers"].append(header_name)
                            results["findings"].append(
                                self._create_finding(
                                    header_info['severity'],
                                    f"Missing security header: {header_name}",
                                    header_info['description'],
                                    recommendation=header_info['recommendation']
                                )
                            )

                    # Calculate overall score (0-100)
                    max_score = len(self.SECURITY_HEADERS)
                    results["score"] = int((results["score"] / max_score) * 100)

                    # Overall assessment
                    if results["score"] >= 80:
                        grade = "A"
                        severity = "info"
                    elif results["score"] >= 60:
                        grade = "B"
                        severity = "low"
                    elif results["score"] >= 40:
                        grade = "C"
                        severity = "medium"
                    else:
                        grade = "F"
                        severity = "high"

                    results["grade"] = grade
                    results["findings"].insert(0,
                        self._create_finding(
                            severity,
                            f"Security headers score: {results['score']}/100 (Grade: {grade})",
                            f"Site implements {results['score']}% of recommended security headers"
                        )
                    )

        except Exception as e:
            results["error"] = str(e)
            self.logger.debug(f"Error analyzing security headers: {e}")

        return results

    def _analyze_header(self, name: str, value: str, findings: list):
        """Analyze specific header values for misconfigurations"""

        if name == 'Strict-Transport-Security':
            # Check max-age value
            if 'max-age=' in value:
                try:
                    max_age = int(value.split('max-age=')[1].split(';')[0])
                    if max_age < 31536000:  # 1 year
                        findings.append(
                            self._create_finding(
                                "medium",
                                "HSTS max-age too short",
                                f"HSTS max-age is {max_age} seconds",
                                recommendation="Use max-age of at least 31536000 (1 year)"
                            )
                        )
                except (ValueError, IndexError):
                    pass

            # Check for includeSubDomains
            if 'includeSubDomains' not in value:
                findings.append(
                    self._create_finding(
                        "low",
                        "HSTS without includeSubDomains",
                        "HSTS header doesn't include subdomains",
                        recommendation="Consider adding 'includeSubDomains' directive"
                    )
                )

        elif name == 'X-Frame-Options':
            if value.upper() not in ['DENY', 'SAMEORIGIN']:
                findings.append(
                    self._create_finding(
                        "medium",
                        "Weak X-Frame-Options value",
                        f"X-Frame-Options is set to '{value}'",
                        recommendation="Use 'DENY' or 'SAMEORIGIN'"
                    )
                )

        elif name == 'Content-Security-Policy':
            # Check for unsafe directives
            if "'unsafe-inline'" in value:
                findings.append(
                    self._create_finding(
                        "medium",
                        "CSP allows unsafe-inline",
                        "Content-Security-Policy allows 'unsafe-inline' which weakens XSS protection",
                        recommendation="Remove 'unsafe-inline' and use nonces or hashes"
                    )
                )

            if "'unsafe-eval'" in value:
                findings.append(
                    self._create_finding(
                        "medium",
                        "CSP allows unsafe-eval",
                        "Content-Security-Policy allows 'unsafe-eval'",
                        recommendation="Remove 'unsafe-eval' directive"
                    )
                )

        elif name == 'X-XSS-Protection':
            if value == "0":
                findings.append(
                    self._create_finding(
                        "medium",
                        "XSS Protection disabled",
                        "X-XSS-Protection is explicitly disabled",
                        recommendation="Set X-XSS-Protection: 1; mode=block"
                    )
                )
