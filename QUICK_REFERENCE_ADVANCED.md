# 🚀 STROM v3.0 - Quick Reference Guide

## ⚡ Fast Access Commands & Features

---

## 📋 Main Menu Structure

```
STROM Main Menu:
[1] Reconnaissance       ← 22 advanced features
[2] Web Scanner         ← Comprehensive scanning
[3] Exploitation Engine ← 9+ vulnerability types
[4] Bypass              ← WAF evasion
[5] Post Exploitation   ← Privilege escalation
[6] Utilities           ← Helper tools
[7] Reporting           ← Professional reports
[8] Payload Generator   ← 6 payload types
[9] Android Remote      ← Mobile testing
[0] Exit
```

---

## 🔍 Reconnaissance Module - Complete Matrix

### Quick Command Flow
```
strom.py → [1] → Enter target → Select feature → [24] Export
```

### All 22 Features

| # | Feature | Key Info | Speed |
|---|---------|----------|-------|
| **1** | DNS Enumeration | A, AAAA, MX, NS, TXT, SOA, CNAME | ⚡ Fast |
| **2** | WHOIS Lookup | Registration, owner, expiry | ⚡ Fast |
| **3** | Port Scanning | 60+ ports, multi-threaded | 🔥 Moderate |
| **4** | Subdomain Enum | 200+ wordlist, parallel | 🔥 Moderate |
| **5** | SSL/TLS Analysis | Certificate details, SANs | ⚡ Fast |
| **6** | HTTP Headers | Security headers check | ⚡ Fast |
| **7** | Technology Detection | CMS, frameworks, libraries | ⚡ Fast |
| **8** | Directory Discovery | robots.txt, common paths | 🔥 Moderate |
| **9** | Email Harvesting | Extract email addresses | ⚡ Fast |
| **10** | WAF Detection | Identify firewall | ⚡ Fast |
| **11** | Reverse DNS | PTR record lookup | ⚡ Fast |
| **12** | Subdomain Takeover | 9+ vulnerable patterns | 🔥 Moderate |
| **13** | GitHub/GitLab Dork | 10+ secret search queries | ⚡ Fast |
| **14** | S3 Bucket Enum | 40+ naming patterns | 🔥 Moderate |
| **15** | Shodan/Censys | API-based intelligence | ⚡ Fast |
| **16** | Google Dorking | 15+ advanced queries | ⚡ Fast |
| **17** | **ASN/BGP Lookup** | Network ownership, CIDR | ⚡ Fast |
| **18** | **Cert Transparency** | Historical subdomains | 🔥 Moderate |
| **19** | **OSINT Social** | 16+ platform profiles | 🔥 Moderate |
| **20** | **Threat Intel** | 10+ reputation DBs | 🔥 Moderate |
| **21** | **Traceroute** | Network path analysis | 🐌 Slow |
| **22** | **Cloud Detection** | 10+ provider identification | ⚡ Fast |
| **23** | Full Recon (All) | Run features 1-11 | 🐌 Very Slow |
| **24** | Export Results | JSON + TXT report | ⚡ Fast |

---

## 🎯 Best Practices - Recommended Sequences

### 🥇 Quick Assessment (5 minutes)
```
[1]  DNS Enumeration
[2]  WHOIS Lookup  
[3]  Port Scanning (Quick mode)
[6]  HTTP Headers
[10] WAF Detection
[24] Export Results
```

### 🥈 Standard Recon (15 minutes)
```
[1]  DNS Enumeration
[4]  Subdomain Enumeration
[5]  SSL Analysis
[6]  HTTP Headers
[7]  Technology Detection
[8]  Directory Discovery
[22] Cloud Provider Detection
[24] Export Results
```

### 🥉 Deep Investigation (30+ minutes)
```
[23] Full Reconnaissance (All)
     ↓
[17] ASN/BGP Lookup
[18] Certificate Transparency
[19] OSINT Social Media
[20] Threat Intelligence
[12] Subdomain Takeover Check
[14] S3 Bucket Enumeration
[24] Export Results
```

### 🎖️ Security Assessment (45+ minutes)
```
[23] Full Reconnaissance
[15] Shodan/Censys Lookup
[20] Threat Intelligence
[12] Subdomain Takeover
[14] S3 Bucket Enumeration
[13] GitHub/GitLab Dorking
[16] Google Dorking
[21] Network Traceroute
[24] Export Results
```

---

## 💡 Feature Deep Dive

### 🆕 ASN/BGP Lookup (#17)
```
What it does:
✓ Autonomous System Number
✓ Network CIDR ranges
✓ Organization details
✓ Geographic location
✓ Routing information

Use when:
- Need network ownership info
- Planning network-wide scan
- Understanding infrastructure
- Identifying IP blocks

Output example:
[+] ASN: AS15169
[+] Organization: GOOGLE
[+] CIDR: 8.8.8.0/24
[+] Country: US
```

### 🆕 Certificate Transparency (#18)
```
What it does:
✓ Searches crt.sh database
✓ Finds historical subdomains
✓ Discovers wildcard certs
✓ Shows expired domains

Use when:
- DNS enumeration incomplete
- Need comprehensive subdomain list
- Looking for old infrastructure
- Wildcard certificate analysis

Output: 50+ unique subdomains discovered
```

### 🆕 OSINT Social Media (#19)
```
What it does:
✓ Checks 16+ platforms
✓ Automated profile detection
✓ Bug bounty program lookup
✓ Community presence

Platforms:
LinkedIn, Twitter/X, Facebook, Instagram
GitHub, GitLab, Reddit, YouTube
HackerOne, Bugcrowd, Discord, Telegram
Medium, Dev.to, TikTok, Stack Overflow

Use when:
- Social engineering prep
- Employee identification
- Bug bounty program search
- Community intel gathering
```

### 🆕 Threat Intelligence (#20)
```
What it does:
✓ Reputation check (10+ sources)
✓ Blacklist verification
✓ Malware history
✓ Security score

Sources:
VirusTotal, AbuseIPDB, Shodan, Censys
IBM X-Force, AlienVault OTX, Talos
GreyNoise, IPVoid, Spamhaus

Use when:
- Assessing target legitimacy
- Checking for compromise
- Security posture analysis
- Risk assessment

Output:
[✓] Clean on 5/5 blacklists
[!] No malware history
[+] Reputation: Good
```

### 🆕 Cloud Provider Detection (#22)
```
What it does:
✓ Identifies hosting provider
✓ Cloud service detection
✓ CDN identification
✓ Infrastructure mapping

Detects:
AWS, Azure, GCP, Cloudflare
Akamai, DigitalOcean, Heroku
Alibaba, Oracle, IBM Cloud
Vercel, Netlify

Use when:
- Planning cloud-specific attacks
- Understanding infrastructure
- CDN bypass strategies
- Architecture analysis

Methods:
- Reverse DNS analysis
- HTTP header inspection
- IP range matching
- Certificate analysis
```

---

## 📊 Port Scanning Guide

### Port Categories (60+ Ports)

#### Web Services
```
80    HTTP
443   HTTPS
8000  HTTP Alt
8080  HTTP Proxy
8443  HTTPS Alt
8888  HTTP Alt
```

#### Databases
```
3306  MySQL
5432  PostgreSQL
6379  Redis
27017 MongoDB
1433  MS SQL
1521  Oracle
```

#### DevOps & CI/CD
```
8080  Jenkins
8081  Nexus/Artifactory
9000  SonarQube
5000  Docker Registry
```

#### Monitoring
```
3000  Grafana
5601  Kibana
9090  Prometheus
9200  Elasticsearch
```

#### Remote Access
```
22    SSH
3389  RDP
5900  VNC
```

#### File Services
```
21    FTP
445   SMB
2049  NFS
```

---

## 🌐 Subdomain Wordlist Categories (200+)

### Categories Breakdown

1. **Standard** (57 words)
   - www, mail, ftp, admin, blog, etc.

2. **API Endpoints** (30 words)
   - api, api-dev, api-staging, api-prod
   - dev-api, test-api, beta-api, v1, v2, v3

3. **DevOps** (25 words)
   - jenkins, gitlab, ci, cd, bamboo
   - artifactory, nexus, sonar

4. **Cloud Native** (20 words)
   - k8s, kubernetes, docker, registry
   - harbor, rancher, portainer

5. **Monitoring** (15 words)
   - grafana, kibana, prometheus
   - consul, vault, status, metrics

6. **Authentication** (10 words)
   - oauth, sso, auth, identity
   - accounts, users, profiles

7. **Storage** (15 words)
   - storage, data, database, files
   - uploads, downloads, documents

8. **Messaging** (10 words)
   - queue, jobs, workers, kafka
   - rabbitmq, mqtt, amqp

---

## 🪣 S3 Bucket Patterns (40+)

### Pattern Categories

#### Basic Patterns
```
{domain}
{domain}-backup
{domain}-data
{domain}-dev
{domain}-prod
```

#### Storage Variations
```
{domain}-storage
storage-{domain}
{domain}-uploads
uploads-{domain}
{domain}-files
files-{domain}
```

#### Environment-Based
```
{domain}-development
{domain}-staging
{domain}-testing
{domain}-production
dev-{domain}
prod-{domain}
test-{domain}
```

#### Content Types
```
{domain}-assets
{domain}-images
{domain}-media
{domain}-static
{domain}-cdn
cdn-{domain}
```

#### Archival
```
{domain}-archive
archive-{domain}
{domain}-logs
logs-{domain}
{domain}-exports
{domain}-reports
```

---

## 🔒 Subdomain Takeover - Vulnerable Patterns

### Detection Matrix

| Service | CNAME Pattern | Indicator |
|---------|---------------|-----------|
| GitHub Pages | github.io | "There isn't a GitHub Pages site" |
| Heroku | herokuapp.com | "No such app" |
| AWS S3 | amazonaws.com | "NoSuchBucket" |
| Azure | azurewebsites.net | "Not Found" |
| CloudFront | cloudfront.net | "ERROR" |
| Netlify | netlify.com | "Not Found" |
| Vercel | vercel.app | "404" |
| Zendesk | zendesk.com | "Help Center Closed" |
| HelpScout | helpscout.net | "No settings" |

---

## 📈 Performance Tips

### Speed Optimization
```
✓ Use Quick Scan for ports (22 ports vs 1024)
✓ Limit subdomain wordlist for faster enum
✓ Run features in parallel when possible
✓ Export results early and often
✓ Use API lookups for comprehensive data
```

### Resource Management
```
✓ Multi-threading: 50 concurrent workers
✓ Memory: ~100-500MB typical usage
✓ Network: Respects rate limiting
✓ CPU: Moderate usage during scans
```

---

## 🎨 Color Coding System

```
🔴 Red    → Errors, vulnerabilities, critical findings
🟡 Yellow → Warnings, missing features, cautions
🟢 Green  → Success, completed, safe findings
🔵 Cyan   → Information, options, queries
⚪ White  → General output, data display
🟣 Magenta→ NEW advanced features
```

---

## 📁 Export Formats

### JSON Output
```json
{
  "target": "example.com",
  "domain": "example.com",
  "ip": "93.184.216.34",
  "scan_time": "2026-01-04T13:00:00",
  "results": {
    "dns": {...},
    "whois": {...},
    "open_ports": [...],
    ...
  }
}
```

### TXT Output
```
==================================================
RECONNAISSANCE REPORT - example.com
==================================================

Target: example.com
IP: 93.184.216.34
Scan Time: 2026-01-04 13:00:00

DNS:
----------------------------------------
...
```

---

## 🚀 Quick Start Examples

### Example 1: Target a Company
```bash
python3 strom.py
[1] Reconnaissance
Target: company.com
[23] Full Reconnaissance
# Wait 10-20 minutes
[24] Export Results
```

### Example 2: Bug Bounty Prep
```bash
[1] Reconnaissance
Target: target.com
[4] Subdomain Enumeration
[18] Certificate Transparency
[12] Subdomain Takeover Check
[19] OSINT Social Media (find HackerOne)
[24] Export Results
```

### Example 3: Quick Security Check
```bash
[1] Reconnaissance
Target: suspicious.com
[20] Threat Intelligence Lookup
[15] Shodan/Censys Lookup
[17] ASN/BGP Lookup
[22] Cloud Provider Detection
[24] Export Results
```

---

## 🔧 Troubleshooting Quick Fixes

### Issue: Package Missing
```bash
pip install package-name
```

### Issue: DNS Resolution Fails
```bash
# Check internet connection
# Try different DNS (8.8.8.8)
# Use IP address instead
```

### Issue: Port Scan Slow
```bash
# Use Quick Scan mode
# Reduce thread count if network is slow
# Check firewall settings
```

### Issue: API Key Error
```bash
# APIs are OPTIONAL
# Skip features requiring API
# Or get free API keys:
# - Shodan: account.shodan.io/register
# - Censys: censys.io/register
```

---

## 📞 Command Shortcuts

### Most Used Sequences

#### Quick Scan
```
1 → target → 1,2,3,6,10 → 24
```

#### Deep Recon
```
1 → target → 23 → 24
```

#### Threat Assessment
```
1 → target → 15,20,22 → 24
```

#### Subdomain Hunter
```
1 → target → 4,18,12 → 24
```

---

## 🎯 Target Types Guide

### Domain Target
```
Input: example.com
Works for: All features
Best for: Complete reconnaissance
```

### IP Target
```
Input: 93.184.216.34
Works for: Port scan, reverse DNS, API lookups
Limited: No subdomain enum, no cert transparency
```

### URL Target
```
Input: https://example.com/path
Works for: Web-based features
Auto-parsed: Extracts domain automatically
```

---

## 🏆 Pro Tips

### 🥇 Maximum Coverage
```
1. Run Full Recon first [23]
2. Then run advanced features [17-22]
3. Export results immediately [24]
4. Review JSON for detailed data
```

### 🥈 Stealth Mode
```
- Use slower scan speeds
- Enable random delays
- Rotate user agents (built-in)
- Respect rate limits
```

### 🥉 Team Collaboration
```
- Export results after each scan
- Share JSON files with team
- Use consistent naming
- Document findings
```

---

## 📚 Additional Resources

### Documentation Files
```
README.md                 ← Main documentation
ADVANCED_UPGRADES.md      ← This upgrade guide
QUICK_REFERENCE_ADVANCED.md ← You are here
INSTALL.md                ← Installation guide
```

### Configuration
```
config.yaml               ← Main configuration
- API keys
- Scan settings
- Output preferences
```

---

## 🌟 Quick Reference Card

```
╔════════════════════════════════════════════════════╗
║          STROM v3.0 - QUICK REFERENCE              ║
╠════════════════════════════════════════════════════╣
║ RECON FEATURES          : 22 advanced options      ║
║ PORT SCAN              : 60+ critical ports        ║
║ SUBDOMAIN WORDLIST     : 200+ entries              ║
║ S3 BUCKET PATTERNS     : 40+ variations            ║
║ CLOUD PROVIDERS        : 10+ detected              ║
║ THREAT INTEL SOURCES   : 10+ databases             ║
║ SOCIAL MEDIA PLATFORMS : 16+ platforms             ║
╠════════════════════════════════════════════════════╣
║ FASTEST SCAN   : [1,2,6,10] → 24 (2 mins)         ║
║ STANDARD SCAN  : [23] Full Recon (15 mins)        ║
║ DEEP SCAN      : [23]+[17-22] (30+ mins)          ║
╠════════════════════════════════════════════════════╣
║ EXPORT: Always use [24] to save results!          ║
╚════════════════════════════════════════════════════╝
```

---

**Version**: 3.0.0 Advanced  
**Last Updated**: January 2026  
**Status**: Production Ready ✅

*Quick, powerful, comprehensive - STROM v3.0*
