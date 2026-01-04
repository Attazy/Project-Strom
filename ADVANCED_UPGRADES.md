# 🚀 STROM Framework - Advanced Upgrades v3.0

## ⚡ Major Enhancements Overview

STROM Framework has been upgraded to version 3.0 with **NO LIMITATIONS** - all tools are now advanced, comprehensive, and production-ready.

---

## 📋 Table of Contents

1. [Reconnaissance Module Upgrades](#reconnaissance-module-upgrades)
2. [Web Scanner Enhancements](#web-scanner-enhancements)
3. [Exploitation Engine Improvements](#exploitation-engine-improvements)
4. [Dependencies Expanded](#dependencies-expanded)
5. [New Features Summary](#new-features-summary)
6. [Installation Guide](#installation-guide)

---

## 🔍 Reconnaissance Module Upgrades

### New Advanced Features

#### 1. **ASN/BGP Lookup** (Option 17)
- Complete Autonomous System Number analysis
- BGP routing information
- Network CIDR ranges
- Organization details
- Geographic location data

```bash
Features:
- RDAP/WHOIS integration
- Fallback to multiple APIs
- Network topology mapping
```

#### 2. **Certificate Transparency Logs** (Option 18)
- Searches crt.sh database
- Discovers hidden subdomains
- Historical certificate data
- Wildcard certificate analysis
- Finds expired domains

```bash
Results:
- Comprehensive subdomain list from CT logs
- Much more thorough than DNS enumeration
- Discovers subdomains before they're active
```

#### 3. **OSINT Social Media** (Option 19)
- 16+ social media platforms checked
- LinkedIn, Twitter/X, Facebook, Instagram
- GitHub, GitLab, Reddit, YouTube
- HackerOne, Bugcrowd profiles
- Telegram, Discord communities
- Automated availability checking

```bash
Platforms Covered:
✓ LinkedIn        ✓ GitHub         ✓ HackerOne
✓ Twitter/X       ✓ GitLab         ✓ Bugcrowd
✓ Facebook        ✓ Reddit         ✓ Discord
✓ Instagram       ✓ YouTube        ✓ Telegram
✓ Medium          ✓ Dev.to         ✓ TikTok
✓ Stack Overflow
```

#### 4. **Threat Intelligence Lookup** (Option 20)
- 10+ reputation databases
- Real-time blacklist checking
- Malware/botnet detection
- Historical threat data
- Security reputation score

```bash
Services Integrated:
- VirusTotal      - IBM X-Force
- AbuseIPDB       - AlienVault OTX
- Shodan          - Talos Intelligence
- Censys          - GreyNoise
- IPVoid          - Spamhaus
```

#### 5. **Network Traceroute** (Option 21)
- Full network path analysis
- Hop-by-hop latency
- Network topology discovery
- Cross-platform support (Linux/Windows)

#### 6. **Cloud Provider Detection** (Option 22)
- Identifies hosting provider
- AWS, Azure, GCP detection
- Cloudflare, Akamai, DigitalOcean
- Header-based detection
- Reverse DNS analysis

```bash
Cloud Providers Detected:
✓ AWS/Amazon Web Services
✓ Microsoft Azure
✓ Google Cloud Platform (GCP)
✓ Cloudflare
✓ Akamai
✓ DigitalOcean
✓ Alibaba Cloud
✓ Oracle Cloud
✓ IBM Cloud
✓ Heroku, Vercel, Netlify
```

### Enhanced Existing Features

#### Port Scanning
- **Expanded from 22 to 60+ common ports**
- Added cloud service ports (Docker, Kubernetes)
- Database ports (MongoDB, Redis, PostgreSQL, Oracle)
- CI/CD ports (Jenkins, GitLab, Nexus)
- Monitoring ports (Grafana, Kibana, Prometheus)

```
New Ports Added:
2375, 2376 (Docker), 3000 (Grafana), 5432 (PostgreSQL)
6379 (Redis), 8081-8088 (various web services)
9000 (SonarQube), 9200-9300 (Elasticsearch)
10000 (Webmin), 11211 (Memcached), 27017-27018 (MongoDB)
```

#### Subdomain Enumeration
- **Expanded wordlist from 90 to 200+ subdomains**
- Added modern tech stack subdomains
- API endpoints (dev-api, staging-api, prod-api)
- DevOps infrastructure (jenkins, gitlab, ci, cd)
- Container orchestration (k8s, docker, rancher)
- Monitoring & logging (grafana, kibana, prometheus)
- Microservices patterns

```
New Categories:
✓ API Variations (30+)
✓ DevOps Tools (25+)
✓ Cloud Native (20+)
✓ Monitoring (15+)
✓ Authentication (10+)
✓ Storage & Data (15+)
✓ Message Queues (10+)
```

#### S3 Bucket Enumeration
- **Expanded from 8 to 40+ patterns**
- More comprehensive naming schemes
- Storage patterns (storage-, -storage)
- Archive patterns (archive-, -archive)
- Multiple extension variations
- CDN and media patterns

---

## 🌐 Web Scanner Enhancements

### Planned Advanced Features (Coming Soon)

1. **AI-Powered Vulnerability Detection**
   - Machine learning models for anomaly detection
   - Pattern recognition for zero-day hunting
   - Behavioral analysis

2. **Advanced Fuzzing Engine**
   - Intelligent payload mutation
   - Context-aware testing
   - Rate-limiting bypass

3. **API Security Testing**
   - GraphQL security scanning
   - REST API fuzzing
   - JWT token analysis
   - OAuth flow testing

4. **Advanced Crawling**
   - JavaScript rendering (Selenium/Playwright)
   - SPA (Single Page Application) support
   - AJAX request interception
   - WebSocket testing

---

## 💥 Exploitation Engine Improvements

### Current Features Enhanced

1. **New Vulnerability Categories**
   - Deserialization attacks (PHP, Java, Python)
   - Template Injection (Jinja2, Twig, FreeMarker)
   - File Upload bypasses
   - SSRF (Server-Side Request Forgery)
   - XXE (XML External Entity)

2. **Evasion Techniques**
   - WAF bypass payloads
   - Obfuscation methods
   - Encoding variations
   - Time-delayed attacks

---

## 📦 Dependencies Expanded

### Added Libraries (70+ New Packages)

#### Exploitation & Binary Analysis
```
pwntools>=4.11.0           # Binary exploitation
ropgadget>=7.4             # ROP chain generation
capstone>=5.0.1            # Disassembly engine
keystone-engine>=0.9.2     # Assembly engine
unicorn>=2.0.1             # CPU emulator
angr>=9.2.80               # Binary analysis
z3-solver>=4.12.4.0        # Constraint solver
radare2-r2pipe>=1.8.0      # Reverse engineering
```

#### Network & Traffic
```
impacket>=0.11.0           # Network protocols
pyshark>=0.6               # Packet analysis
dpkt>=1.9.8                # Packet parsing
netfilterqueue>=1.1.0      # Packet manipulation
mitmproxy>=10.1.6          # SSL/TLS interception
```

#### Machine Learning & AI
```
scikit-learn>=1.3.2        # ML algorithms
tensorflow>=2.15.0         # Deep learning
torch>=2.1.2               # PyTorch
transformers>=4.36.2       # NLP models
```

#### Database Testing
```
pymongo>=4.6.1             # MongoDB
redis>=5.0.1               # Redis
psycopg2-binary>=2.9.9     # PostgreSQL
mysql-connector-python     # MySQL
cx-Oracle>=8.3.0           # Oracle
pymssql>=2.2.10            # MS SQL Server
```

#### Cloud Security
```
boto3>=1.34.16             # AWS SDK
azure-identity>=1.15.0     # Azure
google-cloud-storage       # GCP
kubernetes>=28.1.0         # K8s
docker>=7.0.0              # Docker
```

#### Web Frameworks
```
flask>=3.0.0               # Web server
flask-socketio>=5.3.5      # WebSocket
fastapi>=0.108.0           # Modern API
uvicorn>=0.25.0            # ASGI server
aiohttp>=3.9.1             # Async HTTP
```

#### Wireless & Bluetooth
```
bluepy>=1.3.0              # Bluetooth LE
pybluez>=0.30              # Bluetooth
wifi>=0.3.8                # WiFi
```

#### Reverse Engineering
```
pefile>=2023.2.7           # PE analysis
pyelftools>=0.30           # ELF analysis
python-magic>=0.4.27       # File type detection
yara-python>=4.3.1         # Pattern matching
androguard>=3.4.0          # Android RE
```

#### Steganography & Forensics
```
stegano>=0.11.3            # Steganography
exifread>=3.0.0            # EXIF data
volatility3>=2.5.0         # Memory forensics
```

---

## 🎯 New Features Summary

### Reconnaissance Module

| Feature | Status | Description |
|---------|--------|-------------|
| **ASN/BGP Lookup** | ✅ Complete | Full autonomous system analysis |
| **Certificate Transparency** | ✅ Complete | CT log searching for subdomains |
| **OSINT Social Media** | ✅ Complete | 16+ platforms reconnaissance |
| **Threat Intelligence** | ✅ Complete | 10+ reputation databases |
| **Network Traceroute** | ✅ Complete | Network path analysis |
| **Cloud Provider Detection** | ✅ Complete | 10+ cloud platform detection |
| **Subdomain Takeover** | ✅ Complete | 9+ vulnerable patterns |
| **GitHub/GitLab Dorking** | ✅ Complete | Exposed secrets hunting |
| **S3 Bucket Enumeration** | ✅ Complete | 40+ naming patterns |
| **Shodan/Censys Integration** | ✅ Complete | API-based intelligence |
| **Google Dorking** | ✅ Complete | 15+ advanced dorks |

### Port Scanning
- **60+ ports** (was 22)
- Multi-threaded (50 workers)
- Service fingerprinting
- Banner grabbing support

### Subdomain Discovery
- **200+ wordlist** (was 90)
- Modern tech stack coverage
- API endpoint variations
- DevOps infrastructure

### S3 Enumeration
- **40+ patterns** (was 8)
- Public/private detection
- Multiple URL formats
- Access verification

---

## 🚀 Installation Guide

### Full Installation (All Features)

```bash
# Clone repository
git clone https://github.com/Attazy/strom.git
cd strom

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install ALL dependencies
pip install -r requirements.txt

# Run STROM
python3 strom.py
```

### Quick Start (Core Features Only)

```bash
# Install core dependencies only
pip install requests termcolor colorama pyyaml dnspython beautifulsoup4

# Run STROM
python3 strom.py
```

### Optional API Keys Configuration

Edit `config.yaml`:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  censys_id: "YOUR_CENSYS_ID"
  censys_secret: "YOUR_CENSYS_SECRET"

reconnaissance:
  use_shodan: true
  use_censys: true
```

**Free API Keys:**
- Shodan: https://account.shodan.io/register
- Censys: https://censys.io/register

---

## 📊 Performance Improvements

### Speed Enhancements
- **Multi-threading**: 50 concurrent workers
- **Connection pooling**: Reusable sessions
- **Optimized DNS**: Batch resolution
- **Caching**: Results caching system

### Scalability
- Handles 1000+ subdomains efficiently
- Port scanning 1-65535 support
- Large-scale crawling capability
- Memory-optimized processing

---

## 🛡️ Security Features

### Operational Security
- User-Agent rotation (4+ variations)
- Random delays between requests
- Rate limiting respect
- Proxy support ready
- Tor integration compatible

### Legal Compliance
- Authorization verification
- Audit trail logging
- Scope limitation
- Rate limiting
- Terms of service respect

---

## 📈 Statistics

### Before vs After

| Metric | v1.0 (Before) | v3.0 (After) | Improvement |
|--------|---------------|--------------|-------------|
| **Dependencies** | 20 packages | 90+ packages | 350% ↑ |
| **Recon Options** | 11 features | 22 features | 100% ↑ |
| **Port Coverage** | 22 ports | 60+ ports | 173% ↑ |
| **Subdomain List** | 90 words | 200+ words | 122% ↑ |
| **S3 Patterns** | 8 patterns | 40+ patterns | 400% ↑ |
| **Cloud Providers** | 0 detection | 10+ providers | ∞ ↑ |
| **Threat Intel** | 0 sources | 10+ sources | ∞ ↑ |
| **Social Media** | 0 platforms | 16+ platforms | ∞ ↑ |

---

## 🎓 Advanced Usage Examples

### Example 1: Full Company Reconnaissance

```bash
python3 strom.py
# Select [1] Reconnaissance
# Enter target: example.com
# Select [23] Full Reconnaissance (All)
# Select [24] Export Results
```

**Output:**
- Complete DNS records
- 200+ subdomain checks
- Open ports identification
- SSL certificate analysis
- Technology stack detection
- Social media profiles
- Cloud provider identification
- Threat intelligence report
- Export to JSON + TXT

### Example 2: Subdomain Discovery Deep Dive

```bash
# Select [1] Reconnaissance
# Target: target.com

# Run sequence:
[4]  Subdomain Enumeration (200+ wordlist)
[18] Certificate Transparency Logs (historical data)
[12] Subdomain Takeover Detection (vulnerability check)
[24] Export Results
```

### Example 3: Threat Assessment

```bash
# Select [1] Reconnaissance
# Target: suspicious-domain.com

# Run sequence:
[15] Shodan/Censys Lookup (known vulnerabilities)
[20] Threat Intelligence Lookup (reputation check)
[22] Cloud Provider Detection (infrastructure)
[17] ASN/BGP Lookup (network ownership)
```

---

## 🔧 Troubleshooting

### Common Issues

#### ImportError for Optional Packages
```bash
# Most features work without all packages
# Install specific package only when needed:
pip install package-name
```

#### API Key Errors
```bash
# APIs are OPTIONAL
# Framework works fully without them
# Benefits: More data if configured
```

#### Permission Errors (Port Scanning)
```bash
# Use unprivileged ports or run with appropriate permissions
# Most scans work without root access
```

---

## 🎯 Roadmap v4.0

### Planned Features

#### Q1 2026
- [ ] AI-powered vulnerability classification
- [ ] Automated exploit generation
- [ ] Neural network for traffic analysis
- [ ] Advanced WAF bypass engine

#### Q2 2026
- [ ] Distributed scanning (multi-node)
- [ ] Real-time collaborative pentesting
- [ ] Blockchain for audit trails
- [ ] Quantum-resistant crypto testing

#### Q3 2026
- [ ] Mobile app (Android/iOS)
- [ ] Web dashboard
- [ ] REST API for integration
- [ ] CI/CD pipeline integration

---

## 📝 Changelog v3.0

### Added
✅ ASN/BGP lookup with full network topology
✅ Certificate Transparency log searching
✅ OSINT social media reconnaissance (16+ platforms)
✅ Threat intelligence lookup (10+ databases)
✅ Network traceroute with hop analysis
✅ Cloud provider detection (10+ providers)
✅ Expanded port list (60+ critical ports)
✅ Enhanced subdomain wordlist (200+ entries)
✅ Comprehensive S3 bucket patterns (40+)
✅ DNS blacklist checking
✅ Reputation scoring
✅ ASN CIDR range discovery

### Enhanced
⚡ Multi-threaded performance (50 workers)
⚡ Better error handling and recovery
⚡ More detailed output and reporting
⚡ Improved export formats
⚡ Cross-platform compatibility

### Dependencies
📦 70+ new powerful libraries
📦 Machine learning capabilities
📦 Binary analysis tools
📦 Cloud security frameworks
📦 Network protocol handlers

---

## 🤝 Contributing

Want to add more features? Follow these guidelines:

1. **Maintain backwards compatibility**
2. **Add comprehensive error handling**
3. **Include usage documentation**
4. **Test on multiple platforms**
5. **Follow existing code style**

---

## 📄 License

This project is for **educational and authorized security testing only**.

⚠️ **DISCLAIMER**: Unauthorized access to computer systems is illegal. Always obtain written permission before testing.

---

## 👨‍💻 Author

**Attazy**
- GitHub: https://github.com/Attazy
- Framework: STROM v3.0 Advanced Edition

---

## 🌟 Star This Project

If you find STROM useful, please star the repository!

```bash
# Show your support
⭐ Star on GitHub: https://github.com/Attazy/strom
```

---

## 📞 Support

For issues, questions, or feature requests:
1. Check documentation first
2. Review troubleshooting section
3. Open GitHub issue with details
4. Join community discussions

---

**Version**: 3.0.0 - Advanced Edition (No Limitations)  
**Release Date**: January 2026  
**Status**: Production Ready ✅

---

*"The most advanced penetration testing framework - now with ZERO limitations!"*

🚀 **STROM** - **S**ecurity **T**esting **R**econnaissance **O**ffensive **M**odule
