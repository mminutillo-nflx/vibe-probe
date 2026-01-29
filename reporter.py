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
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
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
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            padding: 0;
            margin: 0;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Animated Background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background:
                radial-gradient(circle at 20% 50%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            padding: 60px 40px;
            border-radius: 24px;
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(99, 102, 241, 0.3);
            animation: slideDown 0.6s ease-out;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }

        .header-content {
            position: relative;
            z-index: 1;
        }

        .header h1 {
            font-size: 3em;
            font-weight: 800;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .header-icon {
            font-size: 1.2em;
            animation: pulse 2s ease-in-out infinite;
        }

        .header-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .meta-item {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 15px 20px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .meta-label {
            font-size: 0.85em;
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .meta-value {
            font-size: 1.1em;
            font-weight: 600;
        }

        /* Summary Cards */
        .summary {
            margin-bottom: 40px;
            animation: fadeIn 0.8s ease-out 0.2s backwards;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }

        .summary-card {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 20px;
            text-align: center;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            display: block;
        }

        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border-color: var(--primary);
        }

        .summary-card:active {
            transform: translateY(-3px);
        }

        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .summary-card:hover::before {
            transform: scaleX(1);
        }

        .summary-number {
            font-size: 3.5em;
            font-weight: 800;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .summary-card.critical .summary-number {
            background: linear-gradient(135deg, var(--critical) 0%, #dc2626 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .summary-card.high .summary-number {
            background: linear-gradient(135deg, var(--high) 0%, #ea580c 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .summary-card.medium .summary-number {
            background: linear-gradient(135deg, var(--medium) 0%, #ca8a04 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .summary-card.low .summary-number {
            background: linear-gradient(135deg, var(--low) 0%, #0891b2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .summary-label {
            color: var(--text-secondary);
            font-size: 0.95em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .summary-icon {
            font-size: 2em;
            margin-bottom: 10px;
            opacity: 0.5;
        }

        /* Findings Section */
        .findings-section {
            background: var(--bg-card);
            padding: 40px;
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
            animation: fadeIn 0.6s ease-out;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--border);
        }

        .section-title {
            font-size: 2em;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .section-count {
            background: var(--primary);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }

        /* Finding Cards */
        .finding {
            background: rgba(15, 23, 42, 0.5);
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 16px;
            border-left: 4px solid var(--border);
            position: relative;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }

        .finding:hover {
            transform: translateX(5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .severity-badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .severity-badge.critical { background: var(--critical); color: white; }
        .severity-badge.high { background: var(--high); color: white; }
        .severity-badge.medium { background: var(--medium); color: #000; }
        .severity-badge.low { background: var(--low); color: white; }
        .severity-badge.info { background: var(--info); color: white; }

        .finding-title {
            font-size: 1.2em;
            font-weight: 600;
            flex: 1;
            min-width: 200px;
        }

        .probe-badge {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }

        .finding-description {
            color: var(--text-secondary);
            margin-bottom: 15px;
            line-height: 1.7;
        }

        .finding-recommendation {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            padding: 15px;
            border-radius: 12px;
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }

        .finding-recommendation::before {
            content: "💡";
            font-size: 1.2em;
        }

        .recommendation-content {
            flex: 1;
        }

        .recommendation-label {
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 5px;
        }

        /* Footer */
        .footer {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 60px;
            padding: 40px 20px;
            border-top: 1px solid var(--border);
        }

        .footer-logo {
            font-size: 2em;
            margin-bottom: 15px;
        }

        .footer-text {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .footer-meta {
            opacity: 0.6;
            font-size: 0.9em;
        }

        /* Animations */
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes pulse {
            0%, 100% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.1);
            }
        }

        @keyframes rotate {
            from {
                transform: rotate(0deg);
            }
            to {
                transform: rotate(360deg);
            }
        }

        /* Scroll Progress Bar */
        .progress-bar {
            position: fixed;
            top: 0;
            left: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            z-index: 1000;
            transition: width 0.1s ease;
        }

        /* Smooth scroll target offset for fixed header */
        html {
            scroll-behavior: smooth;
            scroll-padding-top: 20px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2em;
            }

            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .findings-section {
                padding: 20px;
            }

            .finding {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="progress-bar" id="progressBar"></div>

    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <h1>
                    <span class="header-icon">🔍</span>
                    OSINT Reconnaissance Report
                </h1>
                <div class="header-meta">
                    <div class="meta-item">
                        <div class="meta-label">Target Domain</div>
                        <div class="meta-value">{{ target }}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Scan Initiated</div>
                        <div class="meta-value">{{ scan_time }}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Report Generated</div>
                        <div class="meta-value">{{ generated_at }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="summary">
            <div class="summary-grid">
                <a href="#critical-findings" class="summary-card critical">
                    <div class="summary-icon">🔴</div>
                    <div class="summary-number">{{ summary.critical_count }}</div>
                    <div class="summary-label">Critical Issues</div>
                </a>
                <a href="#high-findings" class="summary-card high">
                    <div class="summary-icon">🟠</div>
                    <div class="summary-number">{{ summary.high_count }}</div>
                    <div class="summary-label">High Priority</div>
                </a>
                <a href="#medium-findings" class="summary-card medium">
                    <div class="summary-icon">🟡</div>
                    <div class="summary-number">{{ summary.medium_count }}</div>
                    <div class="summary-label">Medium Priority</div>
                </a>
                <a href="#low-findings" class="summary-card low">
                    <div class="summary-icon">🔵</div>
                    <div class="summary-number">{{ summary.low_count }}</div>
                    <div class="summary-label">Low Priority</div>
                </a>
                <a href="#info-findings" class="summary-card">
                    <div class="summary-icon">⚪</div>
                    <div class="summary-number">{{ summary.info_count }}</div>
                    <div class="summary-label">Informational</div>
                </a>
                <a href="#critical-findings" class="summary-card">
                    <div class="summary-icon">📊</div>
                    <div class="summary-number">{{ summary.total_findings }}</div>
                    <div class="summary-label">Total Findings</div>
                </a>
            </div>
        </div>

        <!-- Findings -->
        {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
            {% if findings[severity]|length > 0 %}
            <div id="{{ severity }}-findings" class="findings-section">
                <div class="section-header">
                    <div class="section-title">
                        {% if severity == 'critical' %}
                            🔴 Critical Findings
                        {% elif severity == 'high' %}
                            🟠 High Priority Findings
                        {% elif severity == 'medium' %}
                            🟡 Medium Priority Findings
                        {% elif severity == 'low' %}
                            🔵 Low Priority Findings
                        {% else %}
                            ⚪ Informational Findings
                        {% endif %}
                        <span class="section-count">{{ findings[severity]|length }}</span>
                    </div>
                </div>

                {% for finding in findings[severity] %}
                <div class="finding {{ severity }}">
                    <div class="finding-header">
                        <span class="severity-badge {{ severity }}">
                            {% if severity == 'critical' %}⚠️{% elif severity == 'high' %}⬆️{% elif severity == 'medium' %}➡️{% elif severity == 'low' %}⬇️{% else %}ℹ️{% endif %}
                            {{ severity }}
                        </span>
                        <span class="finding-title">{{ finding.title }}</span>
                        <span class="probe-badge">{{ finding.probe }}</span>
                    </div>
                    <div class="finding-description">{{ finding.description }}</div>
                    {% if finding.recommendation %}
                    <div class="finding-recommendation">
                        <div class="recommendation-content">
                            <div class="recommendation-label">Recommendation</div>
                            <div>{{ finding.recommendation }}</div>
                        </div>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}
        {% endfor %}

        <!-- Footer -->
        <div class="footer">
            <div class="footer-logo">🔍</div>
            <div class="footer-text">Vibe Probe v1.0.0</div>
            <div class="footer-meta">
                Comprehensive OSINT Reconnaissance Tool
                <br>
                {{ generated_at }}
            </div>
        </div>
    </div>

    <script>
        // Scroll progress bar
        window.addEventListener('scroll', function() {
            const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
            const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrolled = (winScroll / height) * 100;
            document.getElementById('progressBar').style.width = scrolled + '%';
        });

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        // Animate cards on scroll
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver(function(entries) {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        document.querySelectorAll('.finding, .summary-card').forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(20px)';
            el.style.transition = 'all 0.6s ease-out';
            observer.observe(el);
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
            findings=self.organized_findings
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
