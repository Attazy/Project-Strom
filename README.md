
**Security Testing & Research Offensive Methodology**

*Advanced Penetration Testing Framework v3.0 - NO LIMITATIONS EDITION*

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/GitHub-Attazy-black.svg)](https://github.com/Attazy)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/Attazy/strom)
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)](https://github.com/Attazy/strom)

</div>

---

## 🆕 What's New in v3.0

### 🚀 Major Upgrades - NO LIMITATIONS
- ✨ **22 Reconnaissance Features** (was 11) - 100% increase
- 🎯 **65 Ports Coverage** (was 22) - 195% increase  
- 🌐 **244 Subdomain Wordlist** (was 90) - 171% increase
- 🪣 **41 S3 Bucket Patterns** (was 8) - 413% increase
- 📦 **90+ Dependencies** (was 20) - 350% increase

### 🆕 New Advanced Features
- 🌍 **ASN/BGP Lookup** - Network topology analysis
- 📜 **Certificate Transparency** - Historical subdomain discovery  
- 👥 **OSINT Social Media** - 16+ platform reconnaissance
- 🛡️ **Threat Intelligence** - 10+ reputation databases
- 🗺️ **Network Traceroute** - Path analysis
- ☁️ **Cloud Provider Detection** - AWS, Azure, GCP, Cloudflare, etc.

📖 **Read Full Upgrade Guide:** [ADVANCED_UPGRADES.md](ADVANCED_UPGRADES.md)

---

## ⚠️ LEGAL DISCLAIMER

> **For AUTHORIZED security testing ONLY!**

- ❌ Unauthorized access is **ILLEGAL**
- ✅ Get **written permission** before testing
- ⚖️ User is **responsible** for all actions
- 🔒 Framework includes authorization verification
- 📝 Audit trail logging for compliance

---

## 🚀 Quick Installation

```bash
# Clone repository
git clone https://github.com/Attazy/strom.git
cd strom

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install ALL dependencies (full power)
pip install -r requirements.txt

# OR install core only (basic features)
pip install requests termcolor colorama pyyaml dnspython beautifulsoup4

# Run STROM
python3 strom.py


---

## 📋 The 9 Advanced Modules

### [1] 🔍 Reconnaissance - **22 Features** (UPGRADED!)
**The Most Comprehensive Recon Module**

#### Core Features (1-11)
- DNS Enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- WHOIS Lookup & Analysis
- Port Scanning (**65+ ports**, multi-threaded)
- Subdomain Enumeration (**244+ wordlist**)
- SSL/TLS Certificate Analysis
- HTTP Headers & Security Analysis
- Technology Stack Detection
- Directory/File Discovery
- Email Harvesting
- WAF Detection
- Reverse DNS Lookup

#### 🆕 Advanced Features (12-22)
- **Subdomain Takeover Detection** (9+ vulnerable patterns)
- **GitHub/GitLab Dorking** (Secret hunting)
- **S3 Bucket Enumeration** (41+ patterns)
- **Shodan/Censys Integration** (API-based intelligence)
- **Google Dorking** (15+ advanced queries)
- **🌍 ASN/BGP Lookup** - Network ownership, CIDR ranges
- **📜 Certificate Transparency** - Historical subdomains (crt.sh)
- **👥 OSINT Social Media** - 16+ platforms (LinkedIn, GitHub, etc.)
- **🛡️ Threat Intelligence** - 10+ reputation databases
- **🗺️ Network Traceroute** - Full path analysis
- **☁️ Cloud Detection** - AWS, Azure, GCP, Cloudflare, etc.

**Statistics:**
- Port coverage: 65+ (Database, DevOps, Monitoring, Cloud)
- Subdomain wordlist: 244+ (API, DevOps, Cloud-native)
- S3 patterns: 41+ (Environment, Content-type, Storage)

### [2] 🌐 Web Scanner
**Find web vulnerabilities**

- CMS detection & fingerprinting
- Sensitive file discovery
- Security headers analysis
- Form detection & testing
- Directory bruteforce
- API endpoint discovery
- JavaScript analysis
- Cookie security testing

### [3] 💣 Exploitation Engine
**Exploit vulnerabilities** ⚠️

- SQL Injection (5+ types: Boolean, Time, Error, Union, Blind)
- Remote Code Execution (RCE)
- Cross-Site Scripting (XSS: Reflected, Stored, DOM)
- Local File Inclusion (LFI)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Template Injection (SSTI)
- Deserialization attacks
- File Upload bypass
- Interactive shell session

### [4] 🛡️ WAF Bypass
**Bypass security protections**

- Auto-detect WAF (Cloudflare, AWS WAF, etc.)
- 20+ bypass techniques
- Payload obfuscation
- Encoding variations
- Rate limiting bypass
- Proxy rotation support
- Header manipulation
- Request smuggling

### [5] 🔓 Post-Exploitation
**Maintain access & privilege escalation**

- Privilege escalation techniques
- Persistence mechanisms
- Network pivoting
- Keylogger (cross-platform)
- Screenshot capture
- File exfiltration
- Credential harvesting
- Lateral movement

### [6] 🔧 Utilities
**Helper tools for security testing**

- Encoder/Decoder (Base64, URL, Hex, etc.)
- Hash cracker (MD5, SHA1, SHA256)
- Password generator
- Port scanner (advanced)
- String manipulation
- Binary/Hex converter
- Token generator
- Payload formatter

### [7] 📊 Reporting
**Professional security reports**

- Multiple formats: HTML, PDF, Markdown, JSON
- Risk scoring (0-100 scale)
- Executive summary generation
- CVSS scoring integration
- Vulnerability categorization
- Timeline visualization
- Remediation recommendations
- Compliance mapping

### [8] 🎨 Payload Generator
**Generate attack payloads**

- SQL Injection (100+ payloads)
- RCE/Command Injection (50+ payloads)
- XSS (Cross-Site Scripting)
- LFI (Local File Inclusion)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Template Injection
- Deserialization payloads
- Custom payload builder

### [9] 📱 Android Remote Access
**Mobile device testing**

- APK payload generation
- Remote access capabilities
- SMS/Call interception
- Location tracking
- Camera/Microphone access
- File management
- WebSocket communication
- QR code generation

---

## 📊 Feature Comparison

| Feature | v1.0 | v3.0 | Improvement |
|---------|------|------|-------------|
| **Recon Features** | 11 | 22 | +100% 🚀 |
| **Port Coverage** | 22 | 65 | +195% 🚀 |
| **Subdomain List** | 90 | 244 | +171% 🚀 |
| **S3 Patterns** | 8 | 41 | +413% 🚀 |
| **Dependencies** | 20 | 90+ | +350% 🚀 |
| **Cloud Providers** | 0 | 10+ | NEW 🆕 |
| **Threat Intel** | 0 | 10+ | NEW 🆕 |
| **Social OSINT** | 0 | 16+ | NEW 🆕 |

---

## 🎯 Quick Start Guide

### Basic Usage
```bash
# Run STROM
python3 strom.py

# Select module
[1] Reconnaissance

# Enter target
Target: example.com

# Try new features
[17] ASN/BGP Lookup
[18] Certificate Transparency
[19] OSINT Social Media
[20] Threat Intelligence
[21] Network Traceroute
[22] Cloud Provider Detection

# Export results
[24] Export Results
```

### Recommended Workflows

**Quick Assessment (5 min):**
```
[1] → DNS Enum → WHOIS → Port Scan → Export
```

**Standard Recon (15 min):**
```
[23] Full Reconnaissance → Export
```

**Deep Investigation (30+ min):**
```
[23] Full Recon → [17-22] Advanced Features → Export
```

---

## 🔥 Advanced Features Explained

### 🌍 ASN/BGP Lookup
Discover network ownership and routing information:
- Autonomous System Number (ASN)
- Network CIDR ranges
- Organization details
- Geographic location
- ISP information

### 📜 Certificate Transparency Logs
Find hidden subdomains through CT logs:
- Searches crt.sh database
- Discovers 50-200+ subdomains typically
- Historical certificate data
- Wildcard certificate analysis
- Expired domain identification

### 👥 OSINT Social Media
Comprehensive social presence mapping:
- **Business:** LinkedIn, Crunchbase
- **Social:** Twitter/X, Facebook, Instagram, TikTok
- **Developer:** GitHub, GitLab, Stack Overflow, Dev.to
- **Content:** YouTube, Medium, Reddit
- **Security:** HackerOne, Bugcrowd
- **Community:** Discord, Telegram

### 🛡️ Threat Intelligence
Multi-source reputation analysis:
- **Sources:** VirusTotal, AbuseIPDB, Shodan, Censys
- **Enterprise:** IBM X-Force, Talos Intelligence
- **Community:** AlienVault OTX, GreyNoise
- **Blacklists:** Spamhaus, SORBS, SpamCop (5+ lists)

### ☁️ Cloud Provider Detection
Identify hosting infrastructure:
- **Major Cloud:** AWS, Azure, GCP
- **CDN:** Cloudflare, Akamai
- **PaaS:** Heroku, Vercel, Netlify
- **Others:** DigitalOcean, Alibaba Cloud, Oracle Cloud

---

## 📦 Dependencies

### Core Dependencies (Required)
```bash
requests>=2.31.0
termcolor>=2.3.0
colorama>=0.4.6
pyyaml>=6.0.1
dnspython>=2.4.2
beautifulsoup4>=4.12.2
```

### Advanced Features (90+ packages)
- **Binary Analysis:** pwntools, angr, radare2, capstone
- **Network Tools:** impacket, pyshark, mitmproxy
- **Machine Learning:** tensorflow, pytorch, scikit-learn
- **Database Security:** pymongo, redis, psycopg2
- **Cloud Security:** boto3, azure, google-cloud
- **And 60+ more...**

See [requirements.txt](requirements.txt) for complete list.

---

## 🎓 Documentation

### Main Documentation
- 📖 **README.md** - This file (Overview)
- 🚀 **[ADVANCED_UPGRADES.md](ADVANCED_UPGRADES.md)** - Complete upgrade guide (15KB)
- ⚡ **[QUICK_REFERENCE_ADVANCED.md](QUICK_REFERENCE_ADVANCED.md)** - Fast reference (13KB)
- 📋 **[CHANGELOG.md](CHANGELOG.md)** - Detailed version history (19KB)
- 📊 **[UPGRADE_COMPLETE_SUMMARY.md](UPGRADE_COMPLETE_SUMMARY.md)** - Executive summary (16KB)

### Additional Guides
- 📝 **INSTALL.md** - Installation instructions
- 📱 **README_ANDROID.md** - Android module guide
- 🧪 **ANDROID_TESTING_GUIDE.md** - Testing procedures

**Total Documentation:** 60KB+ of comprehensive guides

---

## ⚙️ Configuration

### Optional API Keys
Edit `config.yaml` to enable enhanced features:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_API_KEY"      # Optional
  censys_id: "YOUR_CENSYS_ID"        # Optional
  censys_secret: "YOUR_CENSYS_SECRET" # Optional

reconnaissance:
  use_shodan: true   # Enable Shodan integration
  use_censys: true   # Enable Censys integration
```

**Free API Keys:**
- Shodan: https://account.shodan.io/register
- Censys: https://censys.io/register

**Note:** All features work without API keys. APIs provide additional data.

---

## 🔒 Security & Compliance

### Authorization Required
- ✅ **Written permission** before testing
- ✅ **Authorization code** tracking
- ✅ **Tester identification**
- ✅ **Audit trail** logging
- ✅ **Scope limitation** enforcement

### Operational Security
- 🔐 User-Agent rotation (4+ variations)
- 🔐 Random delays between requests
- 🔐 Rate limiting respect
- 🔐 Connection timeout handling
- 🔐 Error recovery mechanisms

---

## 🌟 Why STROM v3.0?

### Unique Advantages
✨ **Truly Free** - No premium tiers or hidden costs  
✨ **No Limitations** - All features fully unlocked  
✨ **Most Comprehensive** - 22 recon features in one tool  
✨ **Modern Stack** - Latest libraries and techniques  
✨ **Well Documented** - 60KB+ of guides  
✨ **Production Ready** - Enterprise-grade quality  
✨ **Open Source** - MIT License  
✨ **Actively Maintained** - Regular updates  

### vs. Commercial Tools
| Feature | STROM v3.0 | Nmap | Metasploit | Burp Suite |
|---------|------------|------|------------|------------|
| Recon Features | **22** | 15 | 8 | 12 |
| Cloud Detection | **✅** | ❌ | ❌ | ❌ |
| Threat Intel | **10+ sources** | ❌ | ❌ | Limited |
| Social OSINT | **16+ platforms** | ❌ | ❌ | ❌ |
| CT Logs | **✅** | ❌ | ❌ | ❌ |
| ASN/BGP | **✅** | ❌ | ❌ | ❌ |
| **Cost** | **FREE** | FREE | $15k/yr | $399/yr |

---

## 🚀 Performance

### Benchmarks
```
Quick Scan:         2-5 minutes
Standard Scan:      10-15 minutes
Deep Scan:          25-35 minutes
Full Assessment:    40-60 minutes
```

### Optimization
- ⚡ Multi-threading: 50 concurrent workers
- ⚡ Connection pooling
- ⚡ Optimized DNS resolution
- ⚡ Result caching
- ⚡ Memory efficient (100-300MB typical usage)

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. **Report Bugs** - Use GitHub Issues
2. **Suggest Features** - Open feature requests
3. **Submit Code** - Fork → Branch → PR
4. **Improve Docs** - Fix typos, add examples

### Development Setup
```bash
git clone https://github.com/Attazy/strom.git
cd strom
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📞 Support

### Getting Help
1. 📖 Read documentation first
2. 🔍 Search existing issues
3. 💬 Open new issue with details
4. 🌐 Check community forums

### Contact
- **GitHub:** https://github.com/Attazy/strom
- **Issues:** https://github.com/Attazy/strom/issues
- **Author:** Attazy

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details

**Summary:**
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No warranty provided
- ⚠️ Author not liable

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing only**.

**Important:**
- Unauthorized access to computer systems is **ILLEGAL**
- Always obtain **written permission** before testing
- Follow **local laws** and regulations
- Maintain **responsible disclosure** practices
- Users are **fully responsible** for their actions

The authors and contributors are not responsible for misuse or damage caused by this tool.

---

## 🔮 Roadmap

### v3.1 (Q1 2026)
- [ ] Machine learning-based anomaly detection
- [ ] Advanced WAF bypass techniques
- [ ] Automated exploit generation
- [ ] Real-time collaborative scanning

### v4.0 (Q2-Q3 2026)
- [ ] Web dashboard interface
- [ ] Mobile app (Android/iOS)
- [ ] REST API for automation
- [ ] Distributed scanning support
- [ ] Blockchain audit trails
- [ ] Quantum-resistant crypto testing

---

## 📊 Statistics

```
Total Code:        12,000+ lines
Modules:           9 core modules
Features:          50+ tools
Dependencies:      90+ packages
Documentation:     60KB+ guides
Supported OS:      Linux, Windows, macOS
Python Version:    3.8+
License:           MIT
Status:            Production Ready ✅
```

---

## 🎉 Acknowledgments

Special thanks to:
- Open-source community for amazing libraries
- Security researchers for vulnerability patterns
- Beta testers for valuable feedback
- All contributors and supporters

### Built With
- Python 3.8+
- 90+ powerful security libraries
- Modern penetration testing techniques
- Community-driven development

---

## 🌟 Star History

If you find STROM useful, please ⭐ star the repository!

```bash
⭐ Star on GitHub: https://github.com/Attazy/strom
```

---

<div align="center">

**Version:** 3.0.0 - Advanced Edition (No Limitations)  
**Release Date:** January 2026  
**Status:** Production Ready ✅  

---

*"The most advanced penetration testing framework - now with ZERO limitations!"*

---

**🌩️ STROM** - **S**ecurity **T**esting **R**econnaissance **O**ffensive **M**odule

---

Made with ❤️ by [Attazy](https://github.com/Attazy)

</div>
XXE, SSRF
Copy-paste ready
[9] 📱 Android Remote Access ⚡ NEW
Remote control Android devices

QR code deployment • No Metasploit required! • Screen mirror • Camera • SMS • Location • File browser

