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
            max-width: 1200px;
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
            text-decoration: none;
            color: inherit;
            display: block;
            transition: border-color 0.2s;
        }

        .summary-card:hover {
            border-color: var(--primary);
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

        /* Toggle Section */
        .toggle-section {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
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

        .toggle-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .toggle-content.show {
            max-height: 2000px;
            margin-top: 20px;
        }

        /* Probe Status */
        .probe-list {
            display: grid;
            gap: 12px;
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
        .probe-item.skipped { border-left-color: var(--info); }

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
            background: rgba(107, 114, 128, 0.2);
            color: var(--info);
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

            .findings-section {
                padding: 20px;
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

        <!-- Summary -->
        <div class="summary">
            <div class="summary-grid">
                <a href="#critical-findings" class="summary-card critical">
                    <div class="summary-number">{{ summary.critical_count }}</div>
                    <div class="summary-label">Critical</div>
                </a>
                <a href="#high-findings" class="summary-card high">
                    <div class="summary-number">{{ summary.high_count }}</div>
                    <div class="summary-label">High</div>
                </a>
                <a href="#medium-findings" class="summary-card medium">
                    <div class="summary-number">{{ summary.medium_count }}</div>
                    <div class="summary-label">Medium</div>
                </a>
                <a href="#low-findings" class="summary-card low">
                    <div class="summary-number">{{ summary.low_count }}</div>
                    <div class="summary-label">Low</div>
                </a>
                <a href="#info-findings" class="summary-card">
                    <div class="summary-number">{{ summary.info_count }}</div>
                    <div class="summary-label">Info</div>
                </a>
                <a href="#critical-findings" class="summary-card">
                    <div class="summary-number">{{ summary.total_findings }}</div>
                    <div class="summary-label">Total</div>
                </a>
            </div>
        </div>

        <!-- Probe Execution Status -->
        <div class="toggle-section">
            <div class="toggle-header" onclick="toggleSection('probe-status')">
                <div class="toggle-title">
                    <span>⚙️</span>
                    <span>Probe Execution Status</span>
                </div>
                <div class="toggle-icon" id="probe-status-icon">▶</div>
            </div>
            <div class="toggle-content" id="probe-status-content">
                {% if probe_status.successful %}
                <h3 style="color: var(--success); margin-bottom: 12px;">✓ Successful ({{ probe_status.successful|length }})</h3>
                <div class="probe-list">
                    {% for probe in probe_status.successful %}
                    <div class="probe-item successful">
                        <span class="probe-name">{{ probe.name }}</span>
                        <span class="probe-status successful">Success</span>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}

                {% if probe_status.failed %}
                <h3 style="color: var(--critical); margin: 20px 0 12px;">✗ Failed ({{ probe_status.failed|length }})</h3>
                <div class="probe-list">
                    {% for probe in probe_status.failed %}
                    <div class="probe-item failed">
                        <div style="flex: 1;">
                            <div class="probe-name">{{ probe.name }}</div>
                            <div class="probe-error">{{ probe.error }}</div>
                        </div>
                        <span class="probe-status failed">Failed</span>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}

                {% if probe_status.skipped %}
                <h3 style="color: var(--info); margin: 20px 0 12px;">⊘ Skipped ({{ probe_status.skipped|length }})</h3>
                <div class="probe-list">
                    {% for probe in probe_status.skipped %}
                    <div class="probe-item skipped">
                        <div style="flex: 1;">
                            <div class="probe-name">{{ probe.name }}</div>
                            <div class="probe-error">{{ probe.reason }}</div>
                        </div>
                        <span class="probe-status skipped">Skipped</span>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>

        <!-- Advanced Mode Toggle -->
        <div class="toggle-section">
            <div class="toggle-header" onclick="toggleAdvancedMode()">
                <div class="toggle-title">
                    <span>🔧</span>
                    <span>Advanced Mode - Show Technical Details</span>
                </div>
                <div class="toggle-icon" id="advanced-mode-icon">▶</div>
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
            <div id="{{ severity }}-findings" class="findings-section">
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

        <!-- Footer -->
        <div class="footer">
            <div style="font-size: 1.1em; font-weight: 600; margin-bottom: 8px;">Vibe Probe v1.0.0</div>
            <div style="opacity: 0.6;">Comprehensive OSINT Reconnaissance Tool</div>
        </div>
    </div>

    <script>
        function toggleSection(sectionId) {
            const content = document.getElementById(sectionId + '-content');
            const icon = document.getElementById(sectionId + '-icon');

            if (content.classList.contains('show')) {
                content.classList.remove('show');
                icon.classList.remove('open');
            } else {
                content.classList.add('show');
                icon.classList.add('open');
            }
        }

        function toggleAdvancedMode() {
            const icon = document.getElementById('advanced-mode-icon');
            const advancedSections = document.querySelectorAll('.advanced-data');

            icon.classList.toggle('open');
            const isActive = icon.classList.contains('open');

            advancedSections.forEach(section => {
                if (isActive) {
                    section.classList.add('show');
                } else {
                    section.classList.remove('show');
                }
            });

            localStorage.setItem('advancedMode', isActive ? 'true' : 'false');
        }

        // Restore preferences
        window.addEventListener('DOMContentLoaded', function() {
            const savedMode = localStorage.getItem('advancedMode');
            if (savedMode === 'true') {
                toggleAdvancedMode();
            }
        });

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
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
            probe_status=probe_status
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
