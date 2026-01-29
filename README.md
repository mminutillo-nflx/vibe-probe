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

## 🔒 Security Considerations

### API Key Management

**CRITICAL: Never commit API keys to version control!**

#### How This Project Protects You:

1. **`.gitignore` Protection** - The following files are automatically excluded from git:
   - `.env` (your actual environment variables)
   - `config.yaml` (your actual configuration)
   - Any files matching `*_api_key*`, `*_token*`, `*_secret*`

2. **Safe Templates Provided**:
   - ✅ `.env.example` - Template with placeholders (safe to commit)
   - ✅ `config.example.yaml` - Template with placeholders (safe to commit)
   - ❌ `.env` - Your actual keys (NEVER commit)
   - ❌ `config.yaml` - Your actual keys (NEVER commit)

#### Best Practices:

1. **Always use the example files as templates:**
   ```bash
   cp .env.example .env
   # Edit .env with your ACTUAL keys
   # .env will NOT be committed thanks to .gitignore
   ```

2. **Before pushing to git, double-check:**
   ```bash
   git status  # Verify .env and config.yaml are not listed
   git diff    # Review changes before committing
   ```

3. **If you accidentally commit keys:**
   ```bash
   # Remove from git history immediately
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch .env" \
     --prune-empty --tag-name-filter cat -- --all

   # Force push (if already pushed)
   git push origin --force --all

   # ROTATE YOUR API KEYS IMMEDIATELY
   ```

4. **Use environment variables in production:**
   - Never hardcode keys in code
   - Use `.env` for local development only
   - In production, use secret management systems (AWS Secrets Manager, HashiCorp Vault, etc.)

#### Verify Your Safety:

Check that sensitive files are ignored:
```bash
git ls-files | grep -E '(\.env$|config\.yaml)'
# Should only show .env.example and config.example.yaml
```

### OSINT Tool Usage Warnings

> **⚠️ Disclaimer:** The author of this tool is not a lawyer. The following are general considerations based on common practices and known regulations. These are NOT legal advice. Use your own judgment, consult with legal counsel if needed, and when in doubt, proceed with caution or don't proceed at all.

#### ⚖️ Legal Considerations

**READ THIS CAREFULLY BEFORE USE**

1. **Authorization is MANDATORY**
   - Only scan domains you own or have explicit written permission to test
   - Unauthorized scanning may violate:
     - Computer Fraud and Abuse Act (CFAA) in the USA
     - Computer Misuse Act in the UK
     - GDPR and data protection laws in the EU
     - Similar laws worldwide
   - Penalties can include fines and criminal prosecution

2. **Terms of Service Violations**
   - Many services explicitly prohibit automated scanning
   - API usage may violate ToS if used for reconnaissance
   - Some third-party services (Shodan, VirusTotal, etc.) have usage limits and restrictions
   - **You are responsible for complying with all applicable ToS**

3. **Professional Boundaries**
   - Get a written scope of work for professional engagements
   - Document authorization before testing
   - Follow responsible disclosure practices

#### 🕵️ Operational Security (OPSEC) Considerations

**Your reconnaissance activities are NOT invisible**

1. **You Will Be Detected**
   - Port scans leave obvious traces in logs
   - Multiple DNS queries can trigger alerts
   - Repeated HTTP requests show patterns
   - Security teams monitor for reconnaissance
   - Your IP address will be logged everywhere

2. **Attribution Risks**
   - Running from your home/work IP exposes your identity
   - ISPs may receive abuse complaints
   - Corporate networks may have policies against scanning
   - Your activity may be correlated across multiple targets

3. **OPSEC Best Practices**
   - ⚠️ **Never scan from your personal/work IP without authorization**
   - Use authorized testing environments or ranges
   - Consider rate limiting (built into this tool)
   - Be aware that VPNs/proxies may also log your activity
   - Document your authorization before starting

4. **Unintended Consequences**
   - Aggressive scanning can cause service disruptions
   - May trigger automated blocking (IP bans, rate limits)
   - Could impact legitimate business operations
   - May damage professional relationships

#### 🎯 Responsible Use Guidelines

1. **Before Scanning**
   - [ ] Obtain written authorization
   - [ ] Define scope boundaries clearly
   - [ ] Review applicable laws in your jurisdiction
   - [ ] Check Terms of Service for all APIs used
   - [ ] Ensure you're not on a production network without permission

2. **During Scanning**
   - Use reasonable rate limits (default settings are conservative)
   - Stop immediately if you detect problems
   - Respect robots.txt and security.txt
   - Monitor for unintended side effects

3. **After Scanning**
   - Store reports securely (they contain sensitive data)
   - Share findings only with authorized parties
   - Follow responsible disclosure if vulnerabilities found
   - Delete sensitive data when no longer needed

#### 🚨 Red Flags - STOP If Any Apply

- ❌ You don't have written authorization
- ❌ You're "just curious" about a domain you don't own
- ❌ You're testing a competitor without permission
- ❌ You're scanning from a network you don't control
- ❌ You're trying to circumvent security measures
- ❌ You plan to use findings for malicious purposes

#### ✅ Legitimate Use Cases

- ✅ Your own infrastructure and domains
- ✅ Authorized penetration testing engagements
- ✅ Bug bounty programs (follow program rules!)
- ✅ Security research with proper authorization
- ✅ Educational purposes in controlled environments

### Tool-Specific Security Notes

- **Defensive Use Only**: This tool is designed for security research and authorized testing only
- **Rate Limiting**: Built-in delays to be a good netizen, but still creates detectable patterns
- **Data Protection**: Reports may contain sensitive information - store securely
- **Network Exposure**: Some probes WILL trigger security alerts on target networks
- **API Quotas**: Be aware of rate limits on third-party services (Shodan, VirusTotal, etc.)
- **Logging**: Assume all your activities are being logged by target systems

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
