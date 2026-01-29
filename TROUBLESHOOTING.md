# Troubleshooting Guide

## Common Issues and Solutions

### ModuleNotFoundError: No module named 'dns'

**Problem**: You see this error when running the tool:
```
ModuleNotFoundError: No module named 'dns'
```

**Cause**: You're using a Python interpreter that doesn't have the dependencies installed.

**Solutions**:

1. **Use the wrapper script (easiest)**:
   ```bash
   ./vibe example.com
   ```

2. **Use python3 explicitly**:
   ```bash
   python3 vibe-probe.py example.com
   ```

3. **Check which Python you're using**:
   ```bash
   which python   # Shows current Python
   which python3  # Shows Python 3
   python --version
   python3 --version
   ```

4. **Install dependencies for your Python**:
   ```bash
   # If using python3:
   python3 -m pip install -r requirements.txt

   # If using python:
   python -m pip install -r requirements.txt
   ```

### Multiple Python Installations (Netflix Environment)

**Problem**: You have multiple Python installations (e.g., Netflix Python at `/opt/nflx/python` and system Python).

**Solution**:

The tool is configured to use the system Python 3 where dependencies are installed. Always use one of these methods:

```bash
./vibe example.com              # Wrapper (recommended)
./vibe-probe.py example.com     # Direct execution
python3 vibe-probe.py example.com  # Explicit python3
```

**Don't use**: `python vibe-probe.py` if it points to a different Python installation.

### Externally Managed Environment Error

**Problem**: When trying to install packages:
```
error: externally-managed-environment
```

**Cause**: You're trying to install packages in a managed Python environment (like Netflix's Python).

**Solutions**:

1. **Use python3** which is not externally managed:
   ```bash
   python3 -m pip install -r requirements.txt
   ```

2. **Create a virtual environment** (if needed):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ./vibe-probe.py example.com
   ```

3. **Use the already-configured setup**:
   The `./vibe` wrapper uses the correct Python automatically.

### Permission Denied

**Problem**: `./vibe: Permission denied`

**Solution**: Make the scripts executable:
```bash
chmod +x vibe vibe-probe.py setup.sh
```

### Import Errors After Installation

**Problem**: Modules still not found after installing dependencies.

**Diagnostic**:
```bash
# Check where pip installed packages
python3 -m pip show dnspython

# Verify Python can import
python3 -c "import dns.resolver; print('✓ DNS module works')"
```

**Solution**:
```bash
# Reinstall dependencies
python3 -m pip install -r requirements.txt --force-reinstall --user
```

### Connection Timeouts

**Problem**: Probes fail with connection timeout errors.

**Possible Causes**:
- Target domain is blocking your IP
- Firewall restrictions
- Domain doesn't exist or is unreachable
- VPN/proxy interference

**Solutions**:
1. Verify domain exists:
   ```bash
   nslookup example.com
   ```

2. Test basic connectivity:
   ```bash
   curl -I https://example.com
   ```

3. Run with verbose output to see what's happening:
   ```bash
   ./vibe example.com --verbose
   ```

4. Try with specific probes only:
   ```bash
   ./vibe example.com --probes dns,whois
   ```

### No Reports Generated

**Problem**: Scan completes but no reports appear.

**Check**:
```bash
# Default location
ls -la ./reports/

# Check for errors in verbose mode
./vibe example.com --verbose
```

**Solution**:
- Specify output directory explicitly:
  ```bash
  ./vibe example.com --output ~/Desktop/reports
  ```

- Check permissions on output directory
- Verify disk space available

### DNS Resolution Failures

**Problem**: "Unable to resolve hostname"

**Solutions**:
1. Verify domain is valid:
   ```bash
   host example.com
   ```

2. Check your DNS settings:
   ```bash
   cat /etc/resolv.conf
   ```

3. Try with www prefix:
   ```bash
   ./vibe www.example.com
   ```

### SSL Certificate Errors

**Problem**: SSL verification fails or certificate errors.

**This is often a finding**, not an error! The tool is designed to detect SSL/TLS issues.

**To diagnose**:
```bash
# Test SSL manually
openssl s_client -connect example.com:443 -servername example.com

# Run only SSL probe
./vibe example.com --probes ssl --verbose
```

## Getting Help

If you're still stuck:

1. **Check Python version**:
   ```bash
   python3 --version
   ```
   Requires Python 3.8+, tested with 3.14

2. **Verify dependencies**:
   ```bash
   make test
   ```

3. **Check system requirements**:
   - Internet connectivity
   - ~100MB disk space
   - No firewall blocking Python

4. **Enable verbose mode** for detailed output:
   ```bash
   ./vibe example.com --verbose 2>&1 | tee debug.log
   ```

5. **Try minimal probes** to isolate the issue:
   ```bash
   ./vibe example.com --probes dns
   ```

## Environment-Specific Issues

### Netflix Environment

- Use `python3` not `python` (Netflix Python is managed)
- Use `./vibe` wrapper script
- Dependencies installed in user Python 3.14.2

### macOS

- May need to install Command Line Tools:
  ```bash
  xcode-select --install
  ```

### Linux

- Ensure Python 3.8+ installed:
  ```bash
  sudo apt-get install python3 python3-pip
  ```

### Windows

- Use Windows Subsystem for Linux (WSL) or
- Use PowerShell with Python 3.8+
- Replace `./vibe` with `python vibe-probe.py`

## Quick Diagnostic

Run this to check your environment:

```bash
echo "=== Python Check ==="
which python
python --version
which python3
python3 --version

echo "=== Dependencies Check ==="
python3 -c "import dns.resolver; print('✓ dnspython')"
python3 -c "import whois; print('✓ python-whois')"
python3 -c "import aiohttp; print('✓ aiohttp')"
python3 -c "import jinja2; print('✓ jinja2')"

echo "=== Tool Check ==="
./vibe --help
```

If all these pass, the tool should work!
