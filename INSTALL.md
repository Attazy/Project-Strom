# STROM Framework Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Administrative/root privileges (for some features)

## Installation Steps

### 1. Clone or Download STROM

```bash
cd "C:\Users\attaj\Documents\TUGAS AKHIR DAN KP"
# Or download and extract to this directory
```

### 2. Install Python Dependencies

```bash
cd strom
pip install -r requirements.txt
```

### 3. Create Required Directories

```bash
mkdir data
mkdir logs
mkdir reports
```

### 4. Configure STROM (Optional)

Edit `config.yaml` to customize settings:

```yaml
general:
  timeout: 10
  max_threads: 20

database:
  enabled: true
  path: "./data/strom.db"

api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  censys_id: "YOUR_CENSYS_ID"
  censys_secret: "YOUR_CENSYS_SECRET"
```

### 5. Verify Installation

```bash
python strom.py
```

You should see the STROM banner and main menu.

## API Keys Configuration (Optional)

### Shodan API

1. Register at https://account.shodan.io/register
2. Get API key from https://account.shodan.io/
3. Add to `config.yaml`:
```yaml
api_keys:
  shodan: "your_api_key_here"
```

### Censys API

1. Register at https://censys.io/register
2. Get API credentials from https://censys.io/account
3. Add to `config.yaml`:
```yaml
api_keys:
  censys_id: "your_api_id"
  censys_secret: "your_api_secret"
```

## Module-Specific Requirements

### Post-Exploitation Module

For screenshot capture on Windows:
```bash
pip install pillow
```

For keylogger:
```bash
pip install pynput
```

### Reporting Module

For PDF generation:
```bash
pip install reportlab
```

## Troubleshooting

### Issue: Module not found

**Solution:**
```bash
# Make sure you're in the strom directory
cd strom
python -m pip install -r requirements.txt
```

### Issue: Permission denied

**Solution:**
- Run terminal/command prompt as Administrator (Windows)
- Use `sudo` on Linux/Mac

### Issue: SSL errors

**Solution:**
```bash
pip install --upgrade certifi
```

## Testing Installation

Run each module individually to test:

```bash
# Test reconnaissance
python -m modules.recon

# Test web scanner
python -m modules.web_scanner

# Test utilities
python -m modules.utilities
```

## Updating STROM

```bash
cd strom
git pull origin main  # if using git
pip install -r requirements.txt --upgrade
```

## Uninstallation

```bash
# Remove STROM directory
rm -rf strom  # Linux/Mac
# Or delete folder manually on Windows
```

## Support

For issues or questions:
- Check README.md for documentation
- Review logs in `logs/strom.log`
- Ensure all dependencies are installed

## Legal Notice

STROM is designed for authorized security testing only. Ensure you have written permission before testing any system.
