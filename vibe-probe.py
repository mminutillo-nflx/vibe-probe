#!/Library/Frameworks/Python.framework/Versions/3.14/bin/python3
"""
Vibe Probe - Comprehensive OSINT Reconnaissance Tool
"""

import argparse
import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

from probes.base_probe import MissingAPIKeyError
from probes import (
    dns_probe,
    whois_probe,
    ssl_probe,
    subdomain_probe,
    port_probe,
    http_probe,
    tech_probe,
    email_probe,
    security_headers_probe,
    certificate_transparency_probe,
    cloud_detection_probe,
    reputation_probe,
    web_intelligence_probe,
    social_media_probe,
    breach_probe,
    github_probe,
    shodan_probe,
    wayback_probe,
    geolocation_probe,
    asn_probe,
)
from reporter import ReportGenerator
from utils.config import Config
from utils.logger import setup_logger

__version__ = "1.0.0"


def check_first_run_warning() -> bool:
    """Check if user has confirmed OSINT tool usage warning"""
    warning_file = Path.home() / ".vibe-probe-confirmed"
    return warning_file.exists()


def show_first_run_warning() -> bool:
    """Display first-run warning and get user confirmation"""
    print("\n" + "="*70)
    print("⚠️  IMPORTANT: OSINT TOOL USAGE WARNING")
    print("="*70)
    print("""
This tool performs automated reconnaissance and information gathering.

CRITICAL WARNINGS:
• Only use on domains you own or have explicit permission to test
• OSINT activities may be logged and monitored by target systems
• Some probes may trigger security alerts or rate limits
• Improper use may violate laws, terms of service, or ethical guidelines

📖 Please read the README.md for detailed warnings about:
   - Legal considerations and authorization requirements
   - OPSEC (Operational Security) best practices
   - API key security and rate limits
   - Network fingerprinting and detection risks
   - Data handling and privacy considerations

By continuing, you acknowledge:
✓ You have read and understand these warnings
✓ You will use this tool responsibly and ethically
✓ You accept full responsibility for your actions
""")
    print("="*70)

    while True:
        response = input("\nDo you understand and accept these risks? (yes/no): ").strip().lower()

        if response in ['yes', 'y']:
            # Create confirmation file
            warning_file = Path.home() / ".vibe-probe-confirmed"
            warning_file.touch()
            print("\n✓ Confirmation recorded. You will not be asked again.")
            print("  (To see this warning again, delete: ~/.vibe-probe-confirmed)\n")
            return True
        elif response in ['no', 'n']:
            print("\n✗ Tool usage declined. Exiting.")
            return False
        else:
            print("Please answer 'yes' or 'no'")


class VibeProbe:
    """Main OSINT reconnaissance orchestrator"""

    def __init__(self, target: str, config: Config):
        self.target = target
        self.config = config
        self.logger = setup_logger(config.verbose)
        self.results: Dict[str, Any] = {
            "target": target,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "probes": {}
        }

    async def run_all_probes(self):
        """Execute all OSINT probes concurrently"""
        self.logger.info(f"Starting comprehensive OSINT scan on: {self.target}")

        # Define probe modules with priority levels (critical > high > medium > low)
        probe_modules = [
            ("dns", dns_probe.DNSProbe, "critical"),
            ("whois", whois_probe.WhoisProbe, "high"),
            ("ssl", ssl_probe.SSLProbe, "high"),
            ("subdomains", subdomain_probe.SubdomainProbe, "high"),
            ("ports", port_probe.PortProbe, "critical"),
            ("http", http_probe.HTTPProbe, "high"),
            ("technology", tech_probe.TechProbe, "medium"),
            ("emails", email_probe.EmailProbe, "medium"),
            ("security_headers", security_headers_probe.SecurityHeadersProbe, "high"),
            ("certificate_transparency", certificate_transparency_probe.CTProbe, "medium"),
            ("cloud_detection", cloud_detection_probe.CloudProbe, "medium"),
            ("reputation", reputation_probe.ReputationProbe, "critical"),
            ("web_intelligence", web_intelligence_probe.WebIntelProbe, "high"),
            ("social_media", social_media_probe.SocialMediaProbe, "medium"),
            ("breaches", breach_probe.BreachProbe, "critical"),
            ("github", github_probe.GitHubProbe, "high"),
            ("shodan", shodan_probe.ShodanProbe, "high"),
            ("wayback", wayback_probe.WaybackProbe, "low"),
            ("geolocation", geolocation_probe.GeolocationProbe, "low"),
            ("asn", asn_probe.ASNProbe, "medium"),
        ]

        # Build task list for concurrent execution
        tasks = []
        for probe_name, probe_class, priority in probe_modules:
            # Only run probes selected by user config
            if self.config.should_run_probe(probe_name):
                probe = probe_class(self.target, self.config)
                task = self._run_probe(probe_name, probe, priority)
                tasks.append(task)

        # Execute all probes concurrently with error isolation
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info("All probes completed")

    async def _run_probe(self, name: str, probe: Any, priority: str):
        """Run a single probe with timeout and error handling"""
        # Set probe timeout: 60 seconds for most probes, 120 for port scans
        timeout = 120 if name == "ports" else 60

        try:
            self.logger.info(f"Running {name} probe...")
            # Run probe with timeout protection
            result = await asyncio.wait_for(probe.scan(), timeout=timeout)
            self.results["probes"][name] = {
                "priority": priority,
                "status": "success",
                "data": result
            }
        except asyncio.TimeoutError:
            # Probe exceeded timeout limit
            self.logger.warning(f"{name} probe timed out after {timeout}s")
            self.results["probes"][name] = {
                "priority": priority,
                "status": "skipped",
                "error": f"Probe timed out after {timeout} seconds"
            }
        except MissingAPIKeyError as e:
            # Probe requires API key that is not configured
            self.logger.info(f"{name} probe skipped: {str(e)}")
            self.results["probes"][name] = {
                "priority": priority,
                "status": "skipped",
                "error": str(e)
            }
        except Exception as e:
            # Handle all other errors
            self.logger.error(f"Error in {name} probe: {str(e)}")
            self.results["probes"][name] = {
                "priority": priority,
                "status": "error",
                "error": str(e)
            }

    def generate_report(self, output_format: str = "all"):
        """Generate comprehensive report in multiple formats"""
        self.logger.info("Generating reports...")

        reporter = ReportGenerator(self.results, self.config)

        # Create timestamped output directory
        output_dir = Path(self.config.output_dir) / self.target / datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate requested report formats
        reports = []
        if output_format in ["all", "json"]:
            json_path = reporter.generate_json(output_dir)
            reports.append(json_path)

        if output_format in ["all", "html"]:
            html_path = reporter.generate_html(output_dir)
            reports.append(html_path)

        if output_format in ["all", "markdown"]:
            md_path = reporter.generate_markdown(output_dir)
            reports.append(md_path)

        if output_format in ["all", "pdf"]:
            pdf_path = reporter.generate_pdf(output_dir)
            reports.append(pdf_path)

        self.logger.info(f"Reports generated in: {output_dir}")
        for report in reports:
            self.logger.info(f"  - {report}")

        return output_dir


async def main():
    parser = argparse.ArgumentParser(
        description="Vibe Probe - Comprehensive OSINT Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --format html
  %(prog)s example.com --probes dns,whois,ssl
  %(prog)s example.com --verbose --output ./reports
        """
    )

    parser.add_argument("target", help="Target domain to investigate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports")
    parser.add_argument("-f", "--format", choices=["all", "json", "html", "markdown", "pdf"],
                       default="all", help="Report format (default: all)")
    parser.add_argument("-p", "--probes", help="Comma-separated list of probes to run (default: all)")
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Check for first-run warning
    if not check_first_run_warning():
        if not show_first_run_warning():
            sys.exit(0)

    # Load configuration
    config = Config(args.config, args)

    # Initialize and run probe
    probe = VibeProbe(args.target, config)
    await probe.run_all_probes()
    probe.generate_report(args.format)

    print(f"\n✓ OSINT reconnaissance complete for {args.target}")

    # Cancel any remaining tasks and cleanup
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    # Wait briefly for cleanup
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
        # Explicitly exit after completion
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)
