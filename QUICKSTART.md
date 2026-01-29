# Vibe Probe - Quick Start Guide

Get started with Vibe Probe in minutes.

## Prerequisites

- Python 3.8 or higher (tested with Python 3.14)
- pip (Python package manager)
- Internet connection

## Installation

### Quick Setup (Recommended)

```bash
./setup.sh
```

This will:
- Install core dependencies
- Create configuration files
- Get you ready to scan

### Manual Installation

```bash
# Install core dependencies
pip install -r requirements.txt

# For advanced features (optional)
pip install -r requirements-full.txt
```

Or use Make:
```bash
make install
```

### 2. Setup Configuration (Optional)

```bash
# Copy example files
cp .env.example .env

# Edit .env with your API keys (optional but recommended)
nano .env
```

Or use Make:
```bash
make setup
```

## Basic Usage

### Run Your First Scan

```bash
# Scan a domain (using wrapper)
./vibe example.com

# Or use python3 explicitly
python3 vibe-probe.py example.com
```

**Note**: If you're at Netflix and have multiple Python installations, use `python3` or the `./vibe` wrapper script. The Netflix-managed `python` command points to a different Python environment.

The tool will:
1. Run all available probes concurrently
2. Gather OSINT data
3. Analyze findings by severity
4. Generate reports in `./reports/example.com/TIMESTAMP/`

### View Results

Reports are generated in multiple formats:
- `report.html` - Visual report (open in browser)
- `report.json` - Machine-readable data
- `report.md` - Markdown format

```bash
# Open HTML report
open ./reports/example.com/*/report.html
```

## Common Commands

### Verbose Output
```bash
python vibe-probe.py example.com --verbose
```

### Specific Probes Only
```bash
# Run only DNS and SSL checks
python vibe-probe.py example.com --probes dns,ssl,whois

# Security-focused scan
python vibe-probe.py example.com --probes ssl,security_headers,ports,reputation
```

### Custom Output Directory
```bash
python vibe-probe.py example.com --output ./my-reports
```

### Specific Report Format
```bash
# Generate only HTML report
python vibe-probe.py example.com --format html
```

## Understanding Reports

### Severity Levels

Findings are categorized by severity:

- **Critical** 🔴 - Immediate attention required (expired certs, exposed databases)
- **High** 🟠 - Significant security issues (missing HTTPS, weak encryption)
- **Medium** 🟡 - Moderate concerns (missing security headers)
- **Low** 🔵 - Minor issues (information disclosure)
- **Info** ⚪ - Informational findings (discovered subdomains)

### Example Findings

**Critical Example:**
```
Certificate Expired
The SSL certificate expired 15 days ago
Recommendation: Renew SSL/TLS certificate immediately
```

**High Example:**
```
Database Port Exposed
PostgreSQL port 5432 is accessible from internet
Recommendation: Database ports should not be publicly accessible
```

## API Keys (Optional)

Many probes work without API keys, but for enhanced features:

1. Sign up for free API keys:
   - [Shodan](https://shodan.io) - Port scanning intelligence
   - [VirusTotal](https://virustotal.com) - Domain reputation
   - [NewsAPI](https://newsapi.org) - News article search
   - [GitHub](https://github.com/settings/tokens) - Code search

2. Add to `.env`:
   ```
   SHODAN_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   NEWSAPI_KEY=your_key_here
   GITHUB_TOKEN=your_token_here
   ```

## Troubleshooting

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Connection Timeouts
- Check internet connection
- Target domain may be blocking scans
- Try with `--verbose` flag for debugging

### Permission Errors
- Port scanning requires appropriate permissions
- Some operations may need elevated privileges

### No Results
- Ensure target domain is accessible
- Check firewall settings
- Verify DNS resolution: `nslookup example.com`

## What Gets Scanned?

### Without API Keys
- DNS records (A, MX, TXT, NS, etc.)
- WHOIS information
- SSL/TLS certificates
- Common ports (top 25)
- HTTP headers and security headers
- Subdomain enumeration (common names)
- robots.txt and sitemaps

### With API Keys
- + Shodan host intelligence
- + VirusTotal reputation
- + GitHub code mentions
- + News articles
- + Breach databases
- + Social media mentions
- + Certificate Transparency logs

## Examples

### Security Assessment
```bash
python vibe-probe.py mycompany.com --probes ssl,security_headers,ports
```

### Comprehensive Audit
```bash
python vibe-probe.py target.com --verbose
```

### Quick Check
```bash
python vibe-probe.py example.com --probes dns,whois --format json
```

## Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Check [CLAUDE.md](CLAUDE.md) for architecture details
3. Explore probe modules in `probes/` directory
4. Customize report templates in `reporter.py`

## Safety Reminder

- Only scan domains you own or have authorization to test
- Respect rate limits and Terms of Service
- Unauthorized scanning may be illegal
- Use responsibly for security research only

---

**Happy Probing! 🔍**

For issues or questions, please open a GitHub issue.
