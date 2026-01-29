"""WHOIS information probe"""

import whois
from typing import Dict, Any
from datetime import datetime, timedelta
from .base_probe import BaseProbe


class WhoisProbe(BaseProbe):
    """WHOIS reconnaissance and analysis"""

    async def scan(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        results = {
            "whois_data": {},
            "findings": []
        }

        try:
            w = whois.whois(self.target)

            # Extract key information
            results["whois_data"] = {
                "registrar": w.registrar,
                "creation_date": self._format_date(w.creation_date),
                "expiration_date": self._format_date(w.expiration_date),
                "updated_date": self._format_date(w.updated_date),
                "nameservers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "registrant": getattr(w, 'registrant', None),
                "org": getattr(w, 'org', None),
                "country": getattr(w, 'country', None),
            }

            # Analyze findings
            self._analyze_whois(results["whois_data"], results["findings"])

        except Exception as e:
            results["error"] = str(e)
            results["findings"].append(
                self._create_finding(
                    "low",
                    "WHOIS lookup failed",
                    f"Unable to retrieve WHOIS information: {str(e)}"
                )
            )

        return results

    def _format_date(self, date):
        """Format date for consistent output"""
        if isinstance(date, list):
            date = date[0]
        if isinstance(date, datetime):
            return date.isoformat()
        return str(date) if date else None

    def _analyze_whois(self, whois_data: Dict, findings: List):
        """Analyze WHOIS data for security findings"""

        # Check domain age
        creation_date = whois_data.get("creation_date")
        if creation_date:
            try:
                created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                age_days = (datetime.now() - created.replace(tzinfo=None)).days

                if age_days < 30:
                    findings.append(
                        self._create_finding(
                            "medium",
                            "Newly registered domain",
                            f"Domain was registered only {age_days} days ago",
                            recommendation="Newly registered domains may be associated with suspicious activity"
                        )
                    )
                elif age_days < 365:
                    findings.append(
                        self._create_finding(
                            "low",
                            "Recently registered domain",
                            f"Domain was registered {age_days} days ago"
                        )
                    )
            except Exception as e:
                self.logger.debug(f"Error parsing creation date: {e}")

        # Check expiration
        expiration_date = whois_data.get("expiration_date")
        if expiration_date:
            try:
                expires = datetime.fromisoformat(expiration_date.replace('Z', '+00:00'))
                days_until_expiry = (expires.replace(tzinfo=None) - datetime.now()).days

                if days_until_expiry < 30:
                    findings.append(
                        self._create_finding(
                            "high",
                            "Domain expiring soon",
                            f"Domain expires in {days_until_expiry} days",
                            recommendation="Renew domain registration"
                        )
                    )
            except Exception as e:
                self.logger.debug(f"Error parsing expiration date: {e}")

        # Check for privacy protection
        emails = whois_data.get("emails", [])
        if any("privacy" in email.lower() or "proxy" in email.lower() for email in emails):
            findings.append(
                self._create_finding(
                    "info",
                    "WHOIS privacy protection enabled",
                    "Domain uses privacy protection service"
                )
            )

        # Check for exposed contact information
        exposed_info = []
        if whois_data.get("registrant"):
            exposed_info.append("registrant name")
        if [e for e in emails if "privacy" not in e.lower() and "proxy" not in e.lower()]:
            exposed_info.append("email addresses")

        if exposed_info:
            findings.append(
                self._create_finding(
                    "low",
                    "Exposed WHOIS information",
                    f"The following information is publicly visible: {', '.join(exposed_info)}",
                    data={"exposed_fields": exposed_info},
                    recommendation="Consider using WHOIS privacy protection"
                )
            )
