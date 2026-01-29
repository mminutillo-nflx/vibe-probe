# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vibe Probe is a comprehensive OSINT (Open Source Intelligence) reconnaissance tool written in Python. It performs automated security assessments and intelligence gathering on target domains through modular probes and generates professional reports in multiple formats.

## Commands

### Setup and Installation
```bash
# Install minimal core dependencies (recommended)
pip install -r requirements.txt

# OR install full dependencies including all optional packages
pip install -r requirements-full.txt

# Setup environment variables
cp .env.example .env
# Then edit .env with your API keys

# Quick setup script
./setup.sh
```

**Note on Python 3.14+**: Some optional packages may not yet support Python 3.14. The minimal `requirements.txt` includes only tested, compatible dependencies. Use `requirements-full.txt` for additional features if your Python version supports them.

### Running the Tool
```bash
# Basic scan
python vibe-probe.py <domain>

# Verbose mode for debugging
python vibe-probe.py <domain> --verbose

# Specify output directory
python vibe-probe.py <domain> --output ./custom-reports

# Run specific probes only
python vibe-probe.py <domain> --probes dns,whois,ssl,ports

# Generate specific report format
python vibe-probe.py <domain> --format html
```

### Testing Individual Probes
```bash
# Test a specific probe module directly
python -c "
import asyncio
from probes.dns_probe import DNSProbe
from utils.config import Config

config = Config()
probe = DNSProbe('example.com', config)
result = asyncio.run(probe.scan())
print(result)
"
```

## Architecture

### High-Level Design

Vibe Probe follows a **modular probe architecture** with async execution:

```
┌─────────────────┐
│  vibe-probe.py  │ ← Main orchestrator
│   (VibeProbe)   │
└────────┬────────┘
         │
         ├─→ Loads configuration (utils/config.py)
         ├─→ Executes probes concurrently (asyncio.gather)
         └─→ Generates reports (reporter.py)
                │
                ├─→ JSON (machine-readable)
                ├─→ HTML (visual report)
                ├─→ Markdown (portable)
                └─→ PDF (requires weasyprint)
```

### Key Components

1. **Main Orchestrator** (`vibe-probe.py`)
   - Entry point and CLI interface
   - Manages concurrent probe execution using asyncio
   - Coordinates report generation
   - Priority system: critical > high > medium > low > info

2. **Probe Modules** (`probes/`)
   - Each probe inherits from `BaseProbe`
   - Implements async `scan()` method
   - Returns structured findings with severity levels
   - All probes execute concurrently for performance

3. **Configuration** (`utils/config.py`)
   - Loads API keys from environment variables or config file
   - Manages probe selection and runtime options
   - Supports both .env and config.yaml

4. **Reporter** (`reporter.py`)
   - Organizes findings by severity
   - Generates multiple report formats from single data structure
   - Includes trust scoring for web intelligence
   - HTML reports use embedded CSS (no external dependencies)

### Probe Types

**Fully Implemented Probes:**
- `dns_probe.py` - DNS records, DNSSEC, zone transfers
- `whois_probe.py` - Domain registration, expiration analysis
- `ssl_probe.py` - Certificate validation, protocol testing
- `port_probe.py` - Common port scanning with service detection
- `http_probe.py` - HTTP/HTTPS reconnaissance, robots.txt
- `subdomain_probe.py` - Subdomain enumeration
- `security_headers_probe.py` - HTTP security header analysis with scoring
- `web_intelligence_probe.py` - News, articles, security mentions

**Stub Probes** (require API integration):
- `tech_probe.py` - Technology fingerprinting
- `email_probe.py` - Email harvesting
- `certificate_transparency_probe.py` - CT log search
- `cloud_detection_probe.py` - Cloud provider detection
- `reputation_probe.py` - Domain reputation checking
- `social_media_probe.py` - Social media mentions
- `breach_probe.py` - Data breach checking
- `github_probe.py` - GitHub code search
- `shodan_probe.py` - Shodan integration
- `wayback_probe.py` - Wayback Machine
- `geolocation_probe.py` - IP geolocation
- `asn_probe.py` - ASN lookup

### Adding New Probes

To add a new probe:

1. Create `probes/your_probe.py` extending `BaseProbe`
2. Implement async `scan()` method
3. Use `self._create_finding()` for consistent findings
4. Import in `vibe-probe.py` and add to `probe_modules` list
5. Set appropriate priority level

Example:
```python
from .base_probe import BaseProbe

class YourProbe(BaseProbe):
    async def scan(self):
        results = {"findings": []}

        # Your probe logic here

        results["findings"].append(
            self._create_finding(
                severity="high",  # critical/high/medium/low/info
                title="Finding title",
                description="Detailed description",
                recommendation="How to fix"
            )
        )

        return results
```

## Important Patterns

### Async Execution
All probes use async/await for concurrent execution. Use `asyncio.gather()` for parallel API calls:

```python
tasks = [self._check_something(item) for item in items]
results = await asyncio.gather(*tasks)
```

### Error Handling
Probes should catch exceptions and return structured errors rather than crashing:

```python
try:
    # probe logic
except Exception as e:
    self.logger.error(f"Probe failed: {e}")
    return {"error": str(e), "findings": []}
```

### Finding Structure
Use the standardized finding structure:

```python
{
    "severity": "critical|high|medium|low|info",
    "title": "Short title",
    "description": "Detailed description",
    "data": {},  # Optional structured data
    "recommendation": "How to remediate"  # Optional
}
```

### Configuration Access
API keys and settings are accessed via config object:

```python
api_key = self.config.get_api_key("shodan")
verbose = self.config.verbose
```

## Development Workflow

1. **Adding Features**: Create new probe modules or enhance existing ones
2. **Testing**: Test individual probes before integration
3. **Reporting**: Modify `reporter.py` templates for report customization
4. **API Integration**: Add API keys to `.env`, implement in probe modules

## Security Considerations

- This tool is for **authorized testing only**
- Never commit API keys or sensitive data
- All API keys must be in `.env` or environment variables
- Port scanning and some probes may trigger security alerts
- Respect rate limits and Terms of Service
- Generated reports may contain sensitive information

## Dependencies

### Core Dependencies (requirements.txt)
Required for basic functionality:
- `aiohttp` - Async HTTP client for concurrent requests
- `dnspython` - DNS queries and analysis
- `python-whois` - WHOIS lookups
- `cryptography` + `pyOpenSSL` - SSL/TLS certificate parsing
- `jinja2` - Report template rendering
- `colorama` - Colored terminal output
- `pyyaml` - Configuration file parsing
- `python-dotenv` - Environment variable management

### Optional Dependencies (requirements-full.txt)
For enhanced features:
- `shodan` - Shodan API integration
- `PyGithub` - GitHub code search
- `newsapi-python` - News article aggregation
- `requests` - Additional HTTP client for legacy APIs
- `weasyprint` - PDF report generation (requires system dependencies)

**Python Version Note**: The minimal requirements.txt is tested with Python 3.14+. Some optional packages may not support newer Python versions yet.
