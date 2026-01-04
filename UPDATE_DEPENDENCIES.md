# 🔄 Cara Update Dependencies - STROM v3.0

## ✅ Status: requirements.txt SUDAH DIPERBARUI!

**Version:** v3.0 ADVANCED Edition  
**Total Packages:** 90+ packages (was 20)  
**Total Lines:** 218 lines  
**Status:** Ready to use ✅

---

## 📊 Isi requirements.txt Sekarang:

```
# STROM Framework Dependencies v3.0 ADVANCED
# Advanced Penetration Testing Framework - No Limitations Edition

Total Packages: 90+
Categories: 15+

Includes:
✓ Core dependencies (6 packages)
✓ Reconnaissance (9 packages)
✓ Web scanning (6 packages)
✓ Cryptography (7 packages)
✓ Exploitation (8 packages)
✓ Network analysis (6 packages)
✓ Post-exploitation (10 packages)
✓ Web exploitation tools (5 packages)
✓ Reverse engineering (5 packages)
✓ Wireless & Bluetooth (4 packages)
✓ Machine Learning & AI (6 packages)
✓ Database exploitation (6 packages)
✓ Cloud security (5 packages)
✓ Steganography (4 packages)
✓ Reporting & visualization (5 packages)
✓ And many more...
```

---

## 🚀 3 Pilihan Cara Install/Update

### PILIHAN 1: Install SEMUA (Full Power) 🔥

**Untuk fitur lengkap dengan semua kemampuan advanced:**

```bash
cd /home/attazy/strom

# Install SEMUA dependencies (90+ packages)
pip install -r requirements.txt

# Atau dengan upgrade:
pip install -r requirements.txt --upgrade

# Dengan verbose mode (lihat progress):
pip install -r requirements.txt -v
```

**Waktu install:** ~5-10 menit  
**Size:** ~2-3 GB  
**Fitur:** Semua fitur aktif (22 recon features)

---

### PILIHAN 2: Install CORE Only (Basic) ⚡

**Untuk fitur dasar yang cukup untuk kebanyakan tasks:**

```bash
# Install hanya core dependencies (6 packages)
pip install requests termcolor colorama pyyaml urllib3 certifi

# Tambah recon essentials (4 packages):
pip install dnspython python-whois beautifulsoup4 lxml

# Tambah web scanning (2 packages):
pip install html5lib pycryptodome

# Total: 12 packages core
```

**Waktu install:** ~1-2 menit  
**Size:** ~100-200 MB  
**Fitur:** 11 recon features + basic scanning

---

### PILIHAN 3: Install Bertahap (Recommended) 🎯

**Install sesuai modul yang akan digunakan:**

```bash
# 1. Core (WAJIB)
pip install requests termcolor colorama pyyaml

# 2. Reconnaissance Module
pip install dnspython python-whois netifaces pyOpenSSL beautifulsoup4 lxml

# 3. Advanced Recon (Optional)
pip install shodan censys ipwhois

# 4. Web Scanner
pip install selenium playwright

# 5. Exploitation
pip install pwntools impacket

# 6. Post-Exploitation
pip install paramiko pynput pillow qrcode

# 7. Reporting
pip install reportlab matplotlib plotly

# 8. Machine Learning (Optional)
pip install scikit-learn tensorflow torch
```

---

## 🔍 Cek Package Mana yang Sudah Terinstall

```bash
# Cek semua packages
pip list

# Cek package spesifik
pip show requests
pip show dnspython
pip show shodan

# Cek versi
pip freeze | grep requests
pip freeze | grep dnspython
```

---

## ⚠️ Troubleshooting Install Issues

### Problem 1: Permission Error
```bash
# Solusi 1: Gunakan --user
pip install -r requirements.txt --user

# Solusi 2: Gunakan virtual environment (RECOMMENDED)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Problem 2: Package Conflict
```bash
# Upgrade pip terlebih dahulu
pip install --upgrade pip

# Install dengan --upgrade-strategy
pip install -r requirements.txt --upgrade-strategy eager
```

### Problem 3: Network Timeout
```bash
# Increase timeout
pip install -r requirements.txt --timeout=300

# Atau gunakan mirror
pip install -r requirements.txt -i https://pypi.org/simple
```

### Problem 4: Some Package Failed
```bash
# Skip error dan continue
pip install -r requirements.txt --ignore-installed

# Install satu-satu untuk debug
pip install requests
pip install termcolor
# dst...
```

---

## 📦 Package Berat vs Ringan

### Package RINGAN (Fast Install):
```
requests, termcolor, colorama, pyyaml
dnspython, python-whois, beautifulsoup4
Total: <100 MB, Install: <2 min
```

### Package SEDANG (Moderate):
```
pillow, qrcode, paramiko, selenium
pycryptodome, lxml, reportlab
Total: ~500 MB, Install: ~3-5 min
```

### Package BERAT (Heavy):
```
tensorflow, torch, playwright, angr
impacket, scapy, opencv-python
Total: >2 GB, Install: >10 min
```

**Rekomendasi:** Install core + reconnaissance dulu (5 min), lalu install heavy packages sesuai kebutuhan.

---

## ✅ Verifikasi Install Sukses

```bash
# Test import core modules
python3 << 'PYEOF'
try:
    import requests
    import termcolor
    import colorama
    import yaml
    import dns.resolver
    print("✅ Core dependencies OK!")
except ImportError as e:
    print(f"❌ Error: {e}")
PYEOF

# Test STROM
cd /home/attazy/strom
python3 -c "from modules.recon import AdvancedRecon; print('✅ STROM Module OK!')"
```

---

## 🎯 Install Berdasarkan Use Case

### Use Case 1: Bug Bounty Hunter
```bash
pip install requests dnspython python-whois beautifulsoup4
pip install selenium shodan censys
pip install ipwhois
# Lightweight setup, fokus reconnaissance
```

### Use Case 2: Pentester Profesional
```bash
pip install -r requirements.txt
# Full install, semua fitur
```

### Use Case 3: Student/Learning
```bash
pip install requests termcolor colorama pyyaml
pip install dnspython beautifulsoup4 lxml
# Basic setup untuk belajar
```

### Use Case 4: Red Team
```bash
pip install requests dnspython paramiko pynput
pip install pillow qrcode impacket
pip install pwntools scapy
# Fokus exploitation & post-exploitation
```

---

## 🔄 Update Existing Installation

```bash
# Update semua packages ke versi terbaru
pip install -r requirements.txt --upgrade

# Update package spesifik
pip install --upgrade requests
pip install --upgrade dnspython

# Check outdated packages
pip list --outdated

# Update pip itself
pip install --upgrade pip
```

---

## 🌐 Install dengan Virtual Environment (BEST PRACTICE)

```bash
# 1. Create virtual environment
cd /home/attazy/strom
python3 -m venv venv

# 2. Activate
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python3 strom.py

# 5. Deactivate when done
deactivate
```

**Keuntungan Virtual Environment:**
- ✅ Isolasi dependencies
- ✅ Tidak konflikt dengan system packages
- ✅ Mudah di-clean up
- ✅ Reproducible environment

---

## 📊 Storage Requirements

```
Minimal Install (Core):
├─ Python packages: ~100 MB
├─ STROM code: ~5 MB
└─ Total: ~105 MB

Standard Install (Recon + Web):
├─ Python packages: ~500 MB
├─ STROM code: ~5 MB
└─ Total: ~505 MB

Full Install (All Features):
├─ Python packages: ~2-3 GB
├─ STROM code: ~5 MB
└─ Total: ~2-3 GB

With Virtual Environment:
├─ Add: ~50 MB overhead
```

---

## 🎓 Rekomendasi Install Strategy

### Untuk Pemula:
```bash
# Step 1: Core (2 min)
pip install requests termcolor colorama pyyaml dnspython

# Step 2: Test basic recon (sampai sini sudah bisa pakai 50% fitur)
python3 strom.py

# Step 3: Tambah saat butuh
pip install beautifulsoup4 lxml  # Web scanning
pip install shodan  # Jika punya API key
```

### Untuk Advanced User:
```bash
# Langsung full install
pip install -r requirements.txt

# Skip package yang tidak perlu
# Edit requirements.txt, comment out (#) packages yang tidak dibutuhkan
# Misalnya: tensorflow, torch jika tidak pakai ML features
```

---

## ❓ FAQ

**Q: Apakah harus install semua 90+ packages?**  
A: Tidak wajib. Core dependencies (6-12 packages) sudah cukup untuk fitur dasar.

**Q: Package mana yang paling penting?**  
A: requests, termcolor, colorama, pyyaml, dnspython, beautifulsoup4

**Q: Berapa lama waktu install?**  
A: Core: 1-2 min, Standard: 5-7 min, Full: 10-15 min

**Q: Apakah bisa install tanpa internet?**  
A: Bisa, gunakan `pip download` dulu, lalu install offline.

**Q: Package apa yang paling besar?**  
A: tensorflow (~500MB), torch (~700MB), playwright (~200MB)

**Q: Apakah perlu sudo/admin?**  
A: Tidak jika pakai virtual environment atau `--user` flag

---

## 🔧 Maintenance

```bash
# Check untuk security updates
pip-audit  # Install dengan: pip install pip-audit

# Update packages secara berkala (monthly)
pip list --outdated
pip install --upgrade <package_name>

# Clean pip cache jika disk penuh
pip cache purge

# Uninstall package tidak terpakai
pip uninstall <package_name>
```

---

## 📌 Summary

✅ **requirements.txt sudah diperbarui ke v3.0**  
✅ **Total 90+ packages available**  
✅ **3 pilihan install: Full, Core, Bertahap**  
✅ **Rekomendasi: Virtual environment + core first**  
✅ **All features tested & working**  

---

## 🚀 Quick Start Commands

```bash
# FASTEST WAY (Recommended):
cd /home/attazy/strom
python3 -m venv venv
source venv/bin/activate
pip install requests termcolor colorama pyyaml dnspython beautifulsoup4 lxml
python3 strom.py

# Nanti install tambahan sesuai kebutuhan:
pip install shodan  # Untuk API integration
pip install pillow qrcode  # Untuk Android module
pip install paramiko  # Untuk SSH operations
```

---

**Status:** Ready to Install ✅  
**Version:** v3.0 ADVANCED  
**Date:** January 2026  

🌩️ STROM Framework
