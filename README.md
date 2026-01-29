# Vibe Probe 🔍

A comprehensive OSINT (Open Source Intelligence) reconnaissance tool for gathering intelligence on target domains. Vibe Probe combines technical probes with web intelligence to provide a complete security and reputation assessment.

## ⚠️ Important Disclaimer

**This is an experimental project created for learning and exploring Claude Code capabilities. It is NOT official Netflix tooling and should NOT be used for any real business purposes.**

This repository is:
- ✅ A personal learning experiment
- ✅ An exploration of AI-assisted development with Claude Code
- ✅ A proof-of-concept OSINT tool
- ❌ NOT production-ready software
- ❌ NOT endorsed by or affiliated with Netflix beyond being a personal project
- ❌ NOT suitable for business-critical security assessments

**Use at your own risk for educational purposes only.**

## Features

### Technical Reconnaissance
- **DNS Analysis**: Comprehensive DNS record enumeration, DNSSEC validation, zone transfer testing
- **WHOIS Lookup**: Domain registration details, expiration monitoring, privacy analysis
- **SSL/TLS Analysis**: Certificate inspection, protocol testing, vulnerability detection
- **Port Scanning**: Common port discovery with service identification
- **HTTP/HTTPS Probing**: Web server fingerprinting, security header analysis
- **Subdomain Enumeration**: Discover subdomains and associated infrastructure
- **Security Headers**: Comprehensive security header analysis with scoring

### Web Intelligence
- **News Monitoring**: Track mentions in trusted news sources
- **Web Search**: Discover articles, blog posts, and online discussions
- **Social Media**: Monitor social media mentions and sentiment
- **Security Mentions**: Track security-related content and vulnerabilities
- **GitHub Search**: Find code mentions and potential leaks
- **Breach Databases**: Check for data breaches and exposed credentials

### Advanced Features
- **Certificate Transparency**: Search CT logs for certificates
- **Cloud Detection**: Identify cloud providers and services
- **Reputation Checking**: Check domain reputation across threat intelligence services
- **Shodan Integration**: Leverage Shodan for additional host intelligence
- **Wayback Machine**: Historical website analysis
- **Geolocation**: IP geolocation and ASN lookup

### Reporting
- **Multiple Formats**: JSON, HTML, Markdown, and PDF reports
- **Severity Scoring**: Findings categorized by criticality (Critical, High, Medium, Low, Info)
- **Trust Scoring**: Prioritize findings from trusted sources
- **Recency Weighting**: Recent findings prioritized over historical data
- **Executive Summary**: High-level overview with key statistics

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vibe-probe.git
cd vibe-probe

# Quick setup (recommended)
./setup.sh

# OR manual installation:
# Install core dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys
```

**Python Version**: Requires Python 3.8+. Tested with Python 3.14. Some optional features may require `requirements-full.txt` but check compatibility with your Python version.

## Configuration

### API Keys

Vibe Probe integrates with various services for comprehensive intelligence. Configure your API keys in `.env`:

- **Shodan**: Port scanning and host intelligence
- **Censys**: Internet-wide scanning data
- **VirusTotal**: Domain reputation and malware scanning
- **GitHub**: Code search and repository analysis
- **NewsAPI**: News article aggregation
- **Have I Been Pwned**: Breach database checking
- **SecurityTrails**: Historical DNS and WHOIS data

### Configuration File

Optionally create `config.yaml` for advanced configuration:

```yaml
verbose: true
output_dir: ./reports
selected_probes:
  - dns
  - whois
  - ssl
```

## Usage

### Basic Usage

```bash
# Scan a domain (recommended)
./vibe example.com

# Or use python3 explicitly
python3 vibe-probe.py example.com

# Verbose output
./vibe example.com --verbose

# Specify output directory
./vibe example.com --output ./my-reports
```

**Note**: Use `./vibe` wrapper or `python3` explicitly. Don't use `python` if you have multiple Python installations.

### Report Formats

```bash
# Generate all report formats (default)
./vibe example.com

# Generate only HTML report
./vibe example.com --format html

# Generate only JSON report
./vibe example.com --format json
```

### Selective Probes

```bash
# Run only specific probes
./vibe example.com --probes dns,whois,ssl

# Run security-focused probes
./vibe example.com --probes ssl,security_headers,ports,reputation
```

## Architecture

Vibe Probe uses a modular architecture with separate probe modules:

```
vibe-probe/
├── vibe-probe.py          # Main orchestrator
├── probes/                # Probe modules
│   ├── dns_probe.py
│   ├── whois_probe.py
│   ├── ssl_probe.py
│   └── ...
├── reporter.py            # Report generation
├── utils/                 # Utilities
│   ├── config.py
│   └── logger.py
└── requirements.txt
```

Each probe:
- Extends the `BaseProbe` class
- Implements async `scan()` method
- Returns structured findings with severity levels
- Includes recommendations for remediation

## Output

Reports are generated in timestamped directories:

```
reports/
└── example.com/
    └── 20240129_143022/
        ├── report.json      # Machine-readable data
        ├── report.html      # Formatted HTML report
        ├── report.md        # Markdown report
        └── report.pdf       # PDF report (if configured)
```

## Security Considerations

- **Defensive Use Only**: This tool is designed for security research and authorized testing only
- **Rate Limiting**: Respects rate limits and implements delays
- **API Keys**: Never commit API keys to version control
- **Legal Compliance**: Ensure you have authorization before scanning any target
- **Data Protection**: Reports may contain sensitive information - store securely

## Requirements

- Python 3.8+
- Internet connection
- API keys for optional enhanced features

## Contributing

Contributions are welcome! Areas for enhancement:
- Additional probe modules
- Enhanced report templates
- New API integrations
- Improved fingerprinting techniques

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security research purposes only. Users are responsible for complying with applicable laws and regulations. Unauthorized access to computer systems is illegal.

## Support

For issues, questions, or contributions:
- GitHub Issues: Report bugs and request features
- Documentation: See wiki for detailed guides

---

**Vibe Probe** - Comprehensive OSINT Reconnaissance
