"""Report generation module"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any
from jinja2 import Template


class ReportGenerator:
    """Generate comprehensive OSINT reports in multiple formats"""

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    def __init__(self, results: Dict[str, Any], config: Any):
        self.results = results
        self.config = config
        self.organized_findings = self._organize_findings()

    def _organize_findings(self) -> Dict[str, list]:
        """Organize all findings by severity"""
        organized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for probe_name, probe_data in self.results.get("probes", {}).items():
            if probe_data.get("status") == "success":
                data = probe_data.get("data", {})
                findings = data.get("findings", [])

                for finding in findings:
                    severity = finding.get("severity", "info")
                    finding["probe"] = probe_name
                    organized.get(severity, organized["info"]).append(finding)

        return organized

    def _organize_probe_status(self) -> Dict[str, list]:
        """Organize probes by execution status"""
        probe_status = {
            "successful": [],
            "failed": [],
            "skipped": []
        }

        for probe_name, probe_data in self.results.get("probes", {}).items():
            status = probe_data.get("status", "unknown")
            error = probe_data.get("error")

            if status == "success":
                probe_status["successful"].append({
                    "name": probe_name,
                    "status": status
                })
            elif status == "skipped":
                probe_status["skipped"].append({
                    "name": probe_name,
                    "status": status,
                    "reason": error or "Probe was not selected"
                })
            else:
                probe_status["failed"].append({
                    "name": probe_name,
                    "status": status,
                    "error": error or "Unknown error"
                })

        return probe_status

    def _analyze_tech_stack(self) -> Dict[str, Any]:
        """Analyze probe results to determine technology stack"""
        tech_stack = {
            "web_server": {"detected": [], "evidence": [], "unknown": False},
            "backend": {"detected": [], "evidence": [], "unknown": False},
            "frontend": {"detected": [], "evidence": [], "unknown": False},
            "database": {"detected": [], "evidence": [], "unknown": False},
            "cdn": {"detected": [], "evidence": [], "unknown": False},
            "security": {"detected": [], "evidence": [], "unknown": False},
            "ssl_tls": {"detected": [], "evidence": [], "unknown": False},
            "hosting": {"detected": [], "evidence": [], "unknown": False},
            "email": {"detected": [], "evidence": [], "unknown": False},
        }

        # Analyze HTTP probe results
        http_data = self.results.get("probes", {}).get("http", {}).get("data", {})
        if http_data:
            headers = http_data.get("headers", {})

            # Web server detection
            if "server" in headers:
                tech_stack["web_server"]["detected"].append(headers["server"])
                tech_stack["web_server"]["evidence"].append(f"Server header: {headers['server']}")

            # Backend technology hints
            if "x-powered-by" in headers:
                tech_stack["backend"]["detected"].append(headers["x-powered-by"])
                tech_stack["backend"]["evidence"].append(f"X-Powered-By header: {headers['x-powered-by']}")

            # CDN detection
            cdn_headers = ["cf-ray", "x-amz-cf-id", "x-akamai-transformed", "x-fastly-request-id"]
            for cdn_header in cdn_headers:
                if cdn_header in headers:
                    if "cf-ray" in cdn_header:
                        tech_stack["cdn"]["detected"].append("Cloudflare")
                    elif "x-amz-cf-id" in cdn_header:
                        tech_stack["cdn"]["detected"].append("Amazon CloudFront")
                    elif "x-akamai" in cdn_header:
                        tech_stack["cdn"]["detected"].append("Akamai")
                    elif "x-fastly" in cdn_header:
                        tech_stack["cdn"]["detected"].append("Fastly")
                    tech_stack["cdn"]["evidence"].append(f"CDN header detected: {cdn_header}")

        # Analyze SSL probe results
        ssl_data = self.results.get("probes", {}).get("ssl", {}).get("data", {})
        if ssl_data:
            tls_version = ssl_data.get("tls_version")
            cipher = ssl_data.get("cipher")
            issuer = ssl_data.get("issuer")

            if tls_version:
                tech_stack["ssl_tls"]["detected"].append(f"TLS Version: {tls_version}")
                tech_stack["ssl_tls"]["evidence"].append(f"TLS protocol: {tls_version}")

            if cipher:
                tech_stack["ssl_tls"]["detected"].append(f"Cipher: {cipher}")
                tech_stack["ssl_tls"]["evidence"].append(f"Cipher suite: {cipher}")

            if issuer:
                tech_stack["ssl_tls"]["detected"].append(f"Certificate Issuer: {issuer}")
                tech_stack["ssl_tls"]["evidence"].append(f"SSL certificate issued by: {issuer}")

        # Analyze DNS probe results for hosting
        dns_data = self.results.get("probes", {}).get("dns", {}).get("data", {})
        if dns_data:
            a_records = dns_data.get("A", [])
            ns_records = dns_data.get("NS", [])
            mx_records = dns_data.get("MX", [])

            if a_records:
                tech_stack["hosting"]["evidence"].append(f"A records point to: {', '.join(a_records)}")

            if ns_records:
                ns_providers = ', '.join(ns_records)
                tech_stack["hosting"]["detected"].append(f"Nameservers: {ns_providers}")
                tech_stack["hosting"]["evidence"].append(f"DNS managed by: {ns_providers}")

            if mx_records:
                for mx in mx_records:
                    tech_stack["email"]["detected"].append(mx)
                    tech_stack["email"]["evidence"].append(f"MX record: {mx}")

                    # Detect common email providers
                    if "google" in mx.lower():
                        tech_stack["email"]["detected"].append("Google Workspace / Gmail")
                    elif "outlook" in mx.lower() or "office365" in mx.lower():
                        tech_stack["email"]["detected"].append("Microsoft 365")
                    elif "proofpoint" in mx.lower():
                        tech_stack["security"]["detected"].append("Proofpoint Email Security")

        # Analyze security headers
        security_headers_data = self.results.get("probes", {}).get("security_headers", {}).get("data", {})
        if security_headers_data:
            headers_present = security_headers_data.get("headers_present", {})

            waf_headers = ["x-waf", "x-sucuri-id", "x-cdn"]
            for header, value in headers_present.items():
                if any(waf in header.lower() for waf in waf_headers):
                    tech_stack["security"]["detected"].append(f"WAF/Security: {header}")
                    tech_stack["security"]["evidence"].append(f"Security header: {header}: {value}")

        # Analyze port scan results
        port_data = self.results.get("probes", {}).get("port", {}).get("data", {})
        if port_data:
            open_ports = port_data.get("open_ports", [])
            for port_info in open_ports:
                port = port_info.get("port")
                service = port_info.get("service", "Unknown")

                if port == 3306:
                    tech_stack["database"]["detected"].append("MySQL")
                    tech_stack["database"]["evidence"].append("Port 3306 open (MySQL)")
                elif port == 5432:
                    tech_stack["database"]["detected"].append("PostgreSQL")
                    tech_stack["database"]["evidence"].append("Port 5432 open (PostgreSQL)")
                elif port == 27017:
                    tech_stack["database"]["detected"].append("MongoDB")
                    tech_stack["database"]["evidence"].append("Port 27017 open (MongoDB)")
                elif port == 6379:
                    tech_stack["database"]["detected"].append("Redis")
                    tech_stack["database"]["evidence"].append("Port 6379 open (Redis)")

        # Mark sections as unknown if no data collected
        for category, data in tech_stack.items():
            if not data["detected"] and not data["evidence"]:
                data["unknown"] = True

        return tech_stack

    def _generate_architecture_diagram(self, tech_stack: Dict[str, Any]) -> str:
        """Generate ASCII architecture diagram based on detected technologies"""

        # Determine components
        has_cdn = not tech_stack["cdn"]["unknown"]
        has_webserver = not tech_stack["web_server"]["unknown"]
        has_backend = not tech_stack["backend"]["unknown"]
        has_database = not tech_stack["database"]["unknown"]
        has_ssl = not tech_stack["ssl_tls"]["unknown"]

        cdn_name = tech_stack["cdn"]["detected"][0] if has_cdn else "Unknown CDN"
        webserver_name = tech_stack["web_server"]["detected"][0] if has_webserver else "Web Server"
        backend_name = tech_stack["backend"]["detected"][0] if has_backend else "Backend"
        database_name = tech_stack["database"]["detected"][0] if has_database else "Database"

        # Build diagram
        diagram = """
┌─────────────────────────────────────────────────────────────────┐
│                        System Architecture                      │
│                         """ + self.results["target"] + """                         │
└─────────────────────────────────────────────────────────────────┘

        ┌──────────────┐
        │   Internet   │
        │    Users     │
        └──────┬───────┘
               │
               │ HTTPS Request
               │"""

        if has_ssl:
            ssl_info = tech_stack["ssl_tls"]["detected"][0] if tech_stack["ssl_tls"]["detected"] else "TLS"
            diagram += f"\n               │ ({ssl_info})"

        diagram += "\n               ▼\n"

        if has_cdn:
            diagram += f"""        ┌──────────────────┐
        │   {cdn_name:^16} │
        │   (CDN Layer)    │
        └────────┬─────────┘
                 │
                 │ Cache/Forward
                 ▼
"""

        diagram += f"""        ┌──────────────────┐
        │   {webserver_name:^16} │
        │  (Web Server)    │
        └────────┬─────────┘
                 │
                 │ Process Request
                 ▼
        ┌──────────────────┐
        │   {backend_name:^16} │
        │  (Application)   │
        └────────┬─────────┘
"""

        if has_database:
            diagram += f"""                 │
                 │ Query/Store
                 ▼
        ┌──────────────────┐
        │   {database_name:^16} │
        │    (Database)    │
        └──────────────────┘
"""
        else:
            diagram += f"""                 │
                 │ [No Database Detected]
                 ▼
        ┌──────────────────┐
        │ Static/Serverless│
        │   Architecture   │
        └──────────────────┘
"""

        return diagram

    def generate_json(self, output_dir: Path) -> Path:
        """Generate JSON report"""
        output_file = output_dir / "report.json"

        report = {
            "metadata": {
                "target": self.results["target"],
                "scan_time": self.results["scan_time"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": "Vibe Probe v1.0.0"
            },
            "summary": self._generate_summary(),
            "findings": self.organized_findings,
            "raw_data": self.results["probes"]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return output_file

    def generate_html(self, output_dir: Path) -> Path:
        """Generate HTML report"""
        output_file = output_dir / "report.html"

        summary = self._generate_summary()
        probe_status = self._organize_probe_status()
        tech_stack = self._analyze_tech_stack()
        architecture_diagram = self._generate_architecture_diagram(tech_stack)

        # Extract screenshot from http probe if available
        screenshot_data = None
        http_probe_data = self.results.get("probes", {}).get("http", {})
        if http_probe_data.get("status") == "success":
            screenshot_info = http_probe_data.get("data", {}).get("screenshot", {})
            if screenshot_info.get("success"):
                screenshot_data = screenshot_info.get("data")

        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - {{ target }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #4f46e5;
            --primary-light: #6366f1;
            --success: #10b981;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #06b6d4;
            --info: #6b7280;
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --border: #334155;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Header */
        .header {
            background: var(--primary);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2em;
            font-weight: 700;
            margin-bottom: 20px;
        }

        .header-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .meta-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 12px 16px;
            border-radius: 8px;
        }

        .meta-label {
            font-size: 0.85em;
            opacity: 0.9;
            margin-bottom: 4px;
        }

        .meta-value {
            font-size: 1.05em;
            font-weight: 600;
        }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 30px;
            border-bottom: 2px solid var(--border);
        }

        .tab {
            padding: 12px 24px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
        }

        .tab:hover {
            color: var(--text-primary);
            background: rgba(99, 102, 241, 0.1);
        }

        .tab.active {
            color: var(--primary-light);
            border-bottom-color: var(--primary);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* Summary Cards */
        .summary {
            margin-bottom: 30px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
        }

        .summary-card {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid var(--border);
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .summary-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
            border-color: var(--primary-light);
        }

        .summary-number {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--primary-light);
        }

        .summary-card.critical .summary-number { color: var(--critical); }
        .summary-card.high .summary-number { color: var(--high); }
        .summary-card.medium .summary-number { color: var(--medium); }
        .summary-card.low .summary-number { color: var(--low); }

        .summary-label {
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Toggle Switch */
        .toggle-section {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }

        .toggle-section.sticky {
            position: sticky;
            top: 20px;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        .toggle-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
        }

        .toggle-title {
            font-size: 1.2em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .toggle-icon {
            font-size: 1.5em;
            transition: transform 0.2s;
        }

        .toggle-icon.open {
            transform: rotate(90deg);
        }

        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .collapsible-content.show {
            max-height: 5000px;
        }

        .toggle-switch {
            position: relative;
            width: 56px;
            height: 28px;
            background: var(--border);
            border-radius: 28px;
            cursor: pointer;
            transition: background 0.3s ease;
        }

        .toggle-switch.active {
            background: var(--primary);
        }

        .toggle-slider {
            position: absolute;
            top: 3px;
            left: 3px;
            width: 22px;
            height: 22px;
            background: white;
            border-radius: 50%;
            transition: transform 0.3s ease;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        .toggle-switch.active .toggle-slider {
            transform: translateX(28px);
        }

        /* Probe Status */
        .probe-list {
            display: grid;
            gap: 12px;
            margin-bottom: 30px;
        }

        .probe-item {
            background: rgba(15, 23, 42, 0.5);
            padding: 12px 16px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-left: 3px solid var(--border);
        }

        .probe-item.successful { border-left-color: var(--success); }
        .probe-item.failed { border-left-color: var(--critical); }
        .probe-item.skipped { border-left-color: var(--high); }

        .probe-name {
            font-weight: 500;
        }

        .probe-status {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .probe-status.successful {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }

        .probe-status.failed {
            background: rgba(239, 68, 68, 0.2);
            color: var(--critical);
        }

        .probe-status.skipped {
            background: rgba(249, 115, 22, 0.2);
            color: var(--high);
        }

        .probe-error {
            font-size: 0.85em;
            color: var(--text-secondary);
            margin-top: 8px;
            padding-left: 16px;
        }

        /* Screenshot */
        .screenshot-section {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }

        .screenshot-header {
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .screenshot-container {
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
            max-width: 50%;
            margin: 0 auto;
        }

        .screenshot-container img {
            width: 100%;
            height: auto;
            display: block;
        }

        .screenshot-unavailable {
            padding: 48px 20px;
            text-align: center;
            color: var(--text-secondary);
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
        }

        /* Findings */
        .findings-section {
            background: var(--bg-card);
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid var(--border);
        }

        .section-title {
            font-size: 1.5em;
            font-weight: 700;
        }

        .section-count {
            background: var(--primary);
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }

        /* Finding Cards */
        .finding {
            background: rgba(15, 23, 42, 0.5);
            padding: 20px;
            margin-bottom: 16px;
            border-radius: 12px;
            border-left: 4px solid var(--border);
        }

        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .severity-badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--critical); color: white; }
        .severity-badge.high { background: var(--high); color: white; }
        .severity-badge.medium { background: var(--medium); color: #000; }
        .severity-badge.low { background: var(--low); color: white; }
        .severity-badge.info { background: var(--info); color: white; }

        .finding-title {
            font-size: 1.1em;
            font-weight: 600;
            flex: 1;
            min-width: 200px;
        }

        .probe-badge {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary-light);
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 0.8em;
            font-weight: 500;
        }

        .finding-description {
            color: var(--text-secondary);
            margin-bottom: 12px;
            line-height: 1.6;
        }

        .finding-recommendation {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            padding: 12px;
            border-radius: 8px;
            margin-top: 12px;
        }

        .recommendation-label {
            font-weight: 600;
            color: var(--primary-light);
            margin-bottom: 4px;
        }

        .advanced-data {
            margin-top: 12px;
            padding: 12px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border);
            border-radius: 8px;
            display: none;
        }

        .advanced-data.show {
            display: block;
        }

        .advanced-data pre {
            background: rgba(0, 0, 0, 0.3);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.5;
            margin: 0;
        }

        /* Tech Stack */
        .tech-stack-section {
            background: var(--bg-card);
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }

        .tech-category {
            margin-bottom: 30px;
        }

        .tech-category-title {
            font-size: 1.3em;
            font-weight: 700;
            margin-bottom: 16px;
            color: var(--primary-light);
        }

        .tech-detected {
            background: rgba(16, 185, 129, 0.1);
            border-left: 3px solid var(--success);
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 12px;
        }

        .tech-unknown {
            background: rgba(107, 114, 128, 0.1);
            border-left: 3px solid var(--info);
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 12px;
            color: var(--text-secondary);
        }

        .tech-item {
            margin-bottom: 8px;
            font-weight: 500;
        }

        .tech-evidence {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border);
        }

        .tech-evidence-title {
            font-size: 0.9em;
            font-weight: 600;
            color: var(--primary-light);
            margin-bottom: 8px;
        }

        .tech-evidence-item {
            font-size: 0.85em;
            color: var(--text-secondary);
            margin-bottom: 4px;
            padding-left: 16px;
        }

        .tech-evidence-item::before {
            content: "→ ";
            color: var(--primary);
        }

        /* Raw Data Section */
        .raw-data-section {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }

        .raw-data-title {
            font-size: 1.2em;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .raw-data-content {
            background: rgba(0, 0, 0, 0.4);
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }

        .raw-data-content pre {
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.6;
            color: #e0e0e0;
        }

        /* Architecture Diagram */
        .diagram-section {
            background: var(--bg-card);
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }

        .diagram-title {
            font-size: 1.5em;
            font-weight: 700;
            margin-bottom: 20px;
            color: var(--primary-light);
        }

        .diagram-container {
            background: rgba(0, 0, 0, 0.4);
            padding: 24px;
            border-radius: 12px;
            overflow-x: auto;
            border: 2px solid var(--primary);
        }

        .diagram-container pre {
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            color: var(--text-primary);
            white-space: pre;
        }

        /* Footer */
        .footer {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 48px;
            padding: 32px 20px;
            border-top: 1px solid var(--border);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.5em;
            }

            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .findings-section, .tech-stack-section {
                padding: 20px;
            }

            .tabs {
                overflow-x: auto;
            }

            .tab {
                white-space: nowrap;
            }

            .screenshot-container {
                max-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 OSINT Reconnaissance Report</h1>
            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">Target Domain</div>
                    <div class="meta-value">{{ target }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Time</div>
                    <div class="meta-value">{{ scan_time }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Generated</div>
                    <div class="meta-value">{{ generated_at }}</div>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="switchTab('findings')">📊 Report Summary</button>
            <button class="tab" onclick="switchTab('output')">📝 Script Output</button>
            <button class="tab" onclick="switchTab('architecture')">🏗️ Technical Architecture</button>
        </div>

        <!-- Tab 1: Findings -->
        <div id="findings-tab" class="tab-content active">
            <!-- Summary -->
            <div class="summary">
                <div class="summary-grid">
                    <div class="summary-card critical" onclick="scrollToFindings('critical')">
                        <div class="summary-number">{{ summary.critical_count }}</div>
                        <div class="summary-label">Critical</div>
                    </div>
                    <div class="summary-card high" onclick="scrollToFindings('high')">
                        <div class="summary-number">{{ summary.high_count }}</div>
                        <div class="summary-label">High</div>
                    </div>
                    <div class="summary-card medium" onclick="scrollToFindings('medium')">
                        <div class="summary-number">{{ summary.medium_count }}</div>
                        <div class="summary-label">Medium</div>
                    </div>
                    <div class="summary-card low" onclick="scrollToFindings('low')">
                        <div class="summary-number">{{ summary.low_count }}</div>
                        <div class="summary-label">Low</div>
                    </div>
                    <div class="summary-card" onclick="scrollToFindings('info')">
                        <div class="summary-number">{{ summary.info_count }}</div>
                        <div class="summary-label">Info</div>
                    </div>
                    <div class="summary-card" onclick="scrollToTop()">
                        <div class="summary-number">{{ summary.total_findings }}</div>
                        <div class="summary-label">Total</div>
                    </div>
                </div>
            </div>

            <!-- Advanced Mode Toggle -->
            <div class="toggle-section sticky">
                <div class="toggle-header" onclick="toggleAdvancedMode()" style="cursor: pointer;">
                    <div class="toggle-title">
                        <span>🔧</span>
                        <span>Advanced Mode - Show Technical Details</span>
                    </div>
                    <div class="toggle-switch" id="advanced-mode-switch">
                        <div class="toggle-slider"></div>
                    </div>
                </div>
            </div>

            <!-- Screenshot -->
            {% if screenshot %}
            <div class="screenshot-section">
                <div class="screenshot-header">📸 Homepage Screenshot</div>
                <div class="screenshot-container">
                    <img src="data:image/png;base64,{{ screenshot }}" alt="Homepage Screenshot">
                </div>
            </div>
            {% else %}
            <div class="screenshot-section">
                <div class="screenshot-header">📸 Homepage Screenshot</div>
                <div class="screenshot-unavailable">
                    <div style="font-size: 2em; margin-bottom: 10px;">🚫</div>
                    <div>Screenshot unavailable</div>
                    <div style="font-size: 0.85em; margin-top: 8px; opacity: 0.7;">
                        Install playwright: pip install playwright && playwright install chromium
                    </div>
                </div>
            </div>
            {% endif %}

            <!-- Findings -->
            {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
                {% if findings[severity]|length > 0 %}
                <div class="findings-section" id="findings-{{ severity }}">
                    <div class="section-header">
                        <div class="section-title">
                            {% if severity == 'critical' %}
                                🔴 Critical Findings
                            {% elif severity == 'high' %}
                                🟠 High Priority
                            {% elif severity == 'medium' %}
                                🟡 Medium Priority
                            {% elif severity == 'low' %}
                                🔵 Low Priority
                            {% else %}
                                ⚪ Informational
                            {% endif %}
                        </div>
                        <span class="section-count">{{ findings[severity]|length }}</span>
                    </div>

                    {% for finding in findings[severity] %}
                    <div class="finding {{ severity }}">
                        <div class="finding-header">
                            <span class="severity-badge {{ severity }}">{{ severity }}</span>
                            <span class="finding-title">{{ finding.title }}</span>
                            <span class="probe-badge">{{ finding.probe }}</span>
                        </div>
                        <div class="finding-description">{{ finding.description }}</div>
                        {% if finding.recommendation %}
                        <div class="finding-recommendation">
                            <div class="recommendation-label">💡 Recommendation</div>
                            <div>{{ finding.recommendation }}</div>
                        </div>
                        {% endif %}
                        {% if finding.data %}
                        <div class="advanced-data">
                            <pre><code>{{ finding.data | tojson(indent=2) }}</code></pre>
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            {% endfor %}
        </div>

        <!-- Tab 2: Script Output -->
        <div id="output-tab" class="tab-content">
            <div class="findings-section">
                <div class="section-header">
                    <div class="section-title">⚙️ Probe Execution Results</div>
                </div>

                {% for probe_name, probe_data in probes_data.items() %}
                <div class="toggle-section" style="margin-bottom: 16px;">
                    <div class="toggle-header" onclick="toggleProbe('{{ probe_name }}')">
                        <div class="toggle-title" style="font-size: 1em;">
                            <span>
                                {% if probe_data.get('status') == 'success' %}✓{% elif probe_data.get('status') == 'skipped' %}⊘{% else %}✗{% endif %}
                            </span>
                            <span style="margin-left: 8px;">{{ probe_name }}</span>
                            <span class="probe-status {{ probe_data.get('status', 'unknown') }}" style="margin-left: 12px;">
                                {{ probe_data.get('status', 'unknown') }}
                            </span>
                        </div>
                        <div class="toggle-icon" id="{{ probe_name }}-icon">▶</div>
                    </div>
                    <div class="collapsible-content" id="{{ probe_name }}-content">
                        {% if probe_data.get('error') %}
                        <div style="margin-top: 16px; padding: 12px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--critical); border-radius: 8px;">
                            <strong style="color: var(--critical);">Error:</strong>
                            <div style="color: var(--text-secondary); margin-top: 8px;">{{ probe_data.get('error') }}</div>
                        </div>
                        {% endif %}
                        <div style="margin-top: 16px;">
                            <div class="raw-data-content">
                                <pre>{{ probe_data | tojson(indent=2) }}</pre>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Tab 3: Technical Architecture -->
        <div id="architecture-tab" class="tab-content">
            <div class="tech-stack-section">
                <div class="section-header">
                    <div class="section-title">🏗️ Technical Architecture Analysis</div>
                </div>

                <p style="color: var(--text-secondary); margin-bottom: 30px; line-height: 1.8;">
                    This analysis examines the technology stack powering <strong>{{ target }}</strong> based on reconnaissance data gathered by various probes. Each component identifies the technologies detected, the evidence supporting these determinations, and areas where the stack remains unknown or unknowable given current probe capabilities.
                </p>
            </div>

            <!-- Architecture Diagram -->
            <div class="diagram-section">
                <div class="diagram-title">📐 System Architecture Diagram</div>
                <div class="diagram-container">
                    <pre>{{ architecture_diagram }}</pre>
                </div>
            </div>

            <div class="tech-stack-section">
                <!-- Web Server -->
                <div class="tech-category">
                    <div class="tech-category-title">🌐 Web Server</div>
                    {% if tech_stack.web_server.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>Unable to determine web server technology. This could indicate the Server header is masked, removed for security, or the site uses a non-standard configuration.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.web_server.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.web_server.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Backend -->
                <div class="tech-category">
                    <div class="tech-category-title">⚙️ Backend Framework/Language</div>
                    {% if tech_stack.backend.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>Backend technology could not be determined from HTTP headers. Modern applications often hide backend details for security. Additional probes (e.g., technology fingerprinting, response analysis) would be needed.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.backend.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.backend.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Database -->
                <div class="tech-category">
                    <div class="tech-category-title">🗄️ Database</div>
                    {% if tech_stack.database.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>No database ports detected open to the internet. This is expected and secure - databases should not be publicly accessible. Internal database technology cannot be determined externally.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.database.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.database.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- CDN -->
                <div class="tech-category">
                    <div class="tech-category-title">🌍 Content Delivery Network (CDN)</div>
                    {% if tech_stack.cdn.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>No CDN detected. The site may be served directly from origin servers, use a CDN that doesn't add identifying headers, or rely on DNS-based load balancing.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.cdn.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.cdn.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- SSL/TLS -->
                <div class="tech-category">
                    <div class="tech-category-title">🔒 SSL/TLS Configuration</div>
                    {% if tech_stack.ssl_tls.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>SSL/TLS information could not be gathered. The site may not support HTTPS, the SSL probe failed, or certificate details are not accessible.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.ssl_tls.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.ssl_tls.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Security -->
                <div class="tech-category">
                    <div class="tech-category-title">🛡️ Security Tools</div>
                    {% if tech_stack.security.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>No explicit security tools detected via headers or fingerprints. This doesn't mean security measures aren't in place - many modern security tools operate transparently without advertising their presence.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.security.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.security.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Hosting -->
                <div class="tech-category">
                    <div class="tech-category-title">☁️ Hosting & Infrastructure</div>
                    {% if tech_stack.hosting.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>Hosting provider could not be determined from DNS records alone. Additional analysis of IP ranges and ASN data would be needed to identify the infrastructure provider.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.hosting.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.hosting.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Email -->
                <div class="tech-category">
                    <div class="tech-category-title">📧 Email Infrastructure</div>
                    {% if tech_stack.email.unknown %}
                    <div class="tech-unknown">
                        <strong>Status:</strong> Unknown<br>
                        <em>No MX records found or DNS probe failed. The domain may not handle email, or email is configured through a parent domain.</em>
                    </div>
                    {% else %}
                    <div class="tech-detected">
                        {% for item in tech_stack.email.detected %}
                        <div class="tech-item">{{ item }}</div>
                        {% endfor %}
                        <div class="tech-evidence">
                            <div class="tech-evidence-title">Evidence:</div>
                            {% for evidence in tech_stack.email.evidence %}
                            <div class="tech-evidence-item">{{ evidence }}</div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div style="font-size: 1.1em; font-weight: 600; margin-bottom: 8px;">Vibe Probe v1.0.0</div>
            <div style="opacity: 0.6;">Comprehensive OSINT Reconnaissance Tool</div>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');

            // Save preference
            localStorage.setItem('activeTab', tabName);
        }

        function toggleAdvancedMode() {
            const toggleSwitch = document.getElementById('advanced-mode-switch');
            const advancedSections = document.querySelectorAll('.advanced-data');

            toggleSwitch.classList.toggle('active');
            const isActive = toggleSwitch.classList.contains('active');

            advancedSections.forEach(section => {
                if (isActive) {
                    section.classList.add('show');
                } else {
                    section.classList.remove('show');
                }
            });

            localStorage.setItem('advancedMode', isActive ? 'true' : 'false');
        }

        function toggleProbe(probeName) {
            const content = document.getElementById(probeName + '-content');
            const icon = document.getElementById(probeName + '-icon');

            if (content.classList.contains('show')) {
                content.classList.remove('show');
                icon.classList.remove('open');
            } else {
                content.classList.add('show');
                icon.classList.add('open');
            }
        }

        function scrollToFindings(severity) {
            const section = document.getElementById('findings-' + severity);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }

        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        // Restore preferences
        window.addEventListener('DOMContentLoaded', function() {
            const savedMode = localStorage.getItem('advancedMode');
            if (savedMode === 'true') {
                toggleAdvancedMode();
            }

            const savedTab = localStorage.getItem('activeTab');
            if (savedTab && savedTab !== 'findings') {
                const tabButton = document.querySelector(`button.tab[onclick*="${savedTab}"]`);
                if (tabButton) {
                    tabButton.click();
                }
            }
        });
    </script>
</body>
</html>
        """

        template = Template(html_template)
        html_content = template.render(
            target=self.results["target"],
            scan_time=self.results["scan_time"],
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            summary=summary,
            findings=self.organized_findings,
            screenshot=screenshot_data,
            probe_status=probe_status,
            tech_stack=tech_stack,
            probes_data=self.results.get("probes", {}),
            architecture_diagram=architecture_diagram
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

        return output_file

    def generate_markdown(self, output_dir: Path) -> Path:
        """Generate Markdown report"""
        output_file = output_dir / "report.md"

        summary = self._generate_summary()

        md_content = f"""# OSINT Reconnaissance Report

## Target Information
- **Target:** {self.results['target']}
- **Scan Time:** {self.results['scan_time']}
- **Generated:** {datetime.now(timezone.utc).isoformat()}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical_count']} |
| High | {summary['high_count']} |
| Medium | {summary['medium_count']} |
| Low | {summary['low_count']} |
| Info | {summary['info_count']} |
| **Total** | **{summary['total_findings']}** |

"""

        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = self.organized_findings.get(severity, [])
            if findings:
                md_content += f"\n## {severity.capitalize()} Findings ({len(findings)})\n\n"

                for finding in findings:
                    md_content += f"### {finding['title']}\n\n"
                    md_content += f"**Probe:** {finding['probe']}  \n"
                    md_content += f"**Severity:** {severity.upper()}  \n\n"
                    md_content += f"{finding['description']}\n\n"

                    if finding.get('recommendation'):
                        md_content += f"💡 **Recommendation:** {finding['recommendation']}\n\n"

                    md_content += "---\n\n"

        md_content += f"\n---\n\n*Generated by Vibe Probe v1.0.0*\n"

        with open(output_file, 'w') as f:
            f.write(md_content)

        return output_file

    def generate_pdf(self, output_dir: Path) -> Path:
        """Generate PDF report"""
        # Note: PDF generation requires additional setup (weasyprint)
        # For now, return a note about PDF generation
        output_file = output_dir / "report.pdf"

        # Placeholder - in production, use weasyprint or similar
        note = """PDF generation requires weasyprint library.
Install with: pip install weasyprint

Then this method will convert the HTML report to PDF.
"""

        with open(output_dir / "PDF_GENERATION_NOTE.txt", 'w') as f:
            f.write(note)

        return output_dir / "PDF_GENERATION_NOTE.txt"

    def _generate_summary(self) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {
            "critical_count": len(self.organized_findings["critical"]),
            "high_count": len(self.organized_findings["high"]),
            "medium_count": len(self.organized_findings["medium"]),
            "low_count": len(self.organized_findings["low"]),
            "info_count": len(self.organized_findings["info"]),
        }
        summary["total_findings"] = sum(summary.values())

        return summary
