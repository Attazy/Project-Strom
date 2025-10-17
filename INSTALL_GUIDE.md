# STROM Installation Guide

## Quick Install (Recommended)

```bash
# 1. Install Python 3.8+ (if not installed)
python --version

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Test installation
python test_dependencies.py

# 4. Run STROM
python strom.py
```

## Manual Install (Core Only)

```bash
pip install requests termcolor colorama pyyaml art dnspython python-whois netifaces pyOpenSSL beautifulsoup4 lxml html5lib pycryptodome Pillow
```

## Troubleshooting

### Issue: pip not found
```bash
# Windows
python -m pip install -r requirements.txt

# Linux/Mac
python3 -m pip install -r requirements.txt
```

### Issue: Permission denied
```bash
# Windows - Run as Administrator
# Linux/Mac
sudo pip install -r requirements.txt
```

### Issue: SSL errors
```bash
pip install --upgrade certifi
pip install --upgrade pip
```

### Issue: Specific package fails
```bash
# Install one by one
pip install requests
pip install termcolor
# ... etc
```

## Optional Features

### Enable Keylogger (Post-Exploitation)
```bash
pip install pynput
```

### Enable PDF Reports
```bash
pip install reportlab
```

### Enable Advanced Network Scanning
```bash
pip install scapy
# May require admin/root privileges
```

### Enable Shodan/Censys APIs
```bash
pip install shodan censys
# Then add API keys to config.yaml
```

## Verify Installation

```bash
python test_dependencies.py
```

Expected output:
