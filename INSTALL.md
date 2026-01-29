# Installation Guide

## Quick Start

The fastest way to get started:

```bash
./setup.sh
```

This automated script will install dependencies and create configuration files.

## Manual Installation

### Python Version Requirements

- **Minimum**: Python 3.8
- **Tested with**: Python 3.14.2
- **Recommended**: Python 3.10 or higher

Check your Python version:
```bash
python3 --version
```

### Core Dependencies

Install minimal, tested dependencies:

```bash
pip install -r requirements.txt
```

This includes:
- aiohttp (async HTTP)
- dnspython (DNS queries)
- python-whois (WHOIS lookups)
- cryptography & pyOpenSSL (SSL/TLS)
- jinja2 (reporting)
- colorama (colored output)
- pyyaml (config files)
- python-dotenv (environment variables)

### Full Dependencies (Optional)

For all features including API integrations:

```bash
pip install -r requirements-full.txt
```

**Note**: Some packages may not support Python 3.14+ yet. If you encounter compatibility issues, use the minimal `requirements.txt` which is fully tested.

### Configuration

1. **Copy example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit .env with your API keys (optional):**
   ```bash
   nano .env
   ```

3. **Copy example config (optional):**
   ```bash
   cp config.example.yaml config.yaml
   ```

## Troubleshooting

### Package Installation Fails

**Error**: `No matching distribution found`

This usually means a package doesn't support your Python version.

**Solution**: Use the minimal requirements.txt:
```bash
pip install -r requirements.txt
```

### Python Version Constraints

**Error**: `Requires-Python >=3.x,<3.y`

Some packages have Python version restrictions.

**Solution**:
- Use requirements.txt (tested with Python 3.14)
- OR use Python 3.10-3.12 with requirements-full.txt

### Import Errors

**Error**: `ModuleNotFoundError: No module named 'xxx'`

**Solution**: Reinstall dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

### Permission Errors

**Error**: `Permission denied` during installation

**Solution**: Use --user flag:
```bash
pip install -r requirements.txt --user
```

Or use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Virtual Environment (Recommended)

Using a virtual environment isolates dependencies:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # On macOS/Linux
# OR
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt

# When done
deactivate
```

## Verifying Installation

Test that everything is installed correctly:

```bash
# Run basic tests
make test

# OR manually test imports
python3 -c "from probes.dns_probe import DNSProbe; print('✓ Installation successful')"
```

## Optional Features

### API Integrations

To enable API-based features, you'll need:

- **Shodan**: Port scanning intelligence
  - Sign up: https://shodan.io
  - Add `SHODAN_API_KEY` to .env

- **VirusTotal**: Domain reputation
  - Sign up: https://virustotal.com
  - Add `VIRUSTOTAL_API_KEY` to .env

- **NewsAPI**: News articles
  - Sign up: https://newsapi.org
  - Add `NEWSAPI_KEY` to .env

- **GitHub**: Code search
  - Generate token: https://github.com/settings/tokens
  - Add `GITHUB_TOKEN` to .env

Most features work without API keys using the core probes.

### PDF Generation

PDF reports require weasyprint, which has system dependencies:

**macOS:**
```bash
brew install cairo pango gdk-pixbuf libffi
pip install weasyprint
```

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
pip install weasyprint
```

**Windows:**
Follow: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows

## System Requirements

- **Disk Space**: ~100MB for dependencies
- **Memory**: 512MB minimum, 1GB recommended
- **Network**: Internet access required for scans
- **Permissions**: Some probes may require elevated privileges

## Next Steps

After installation:

1. Read [QUICKSTART.md](QUICKSTART.md) for usage examples
2. Check [CLAUDE.md](CLAUDE.md) for development guide
3. Run your first scan:
   ```bash
   python3 vibe-probe.py example.com
   ```

## Getting Help

If you encounter issues:

1. Check this troubleshooting guide
2. Review error messages carefully
3. Ensure Python version compatibility
4. Try minimal requirements.txt first
5. Open an issue on GitHub with:
   - Python version (`python3 --version`)
   - Error message
   - Steps to reproduce
