#!/usr/bin/env python3
import requests
import socket
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.recon_helper import ReconHelper
from utils.logger import setup_logger

logger = setup_logger('recon')

# add import guard for dnspython
try:
	# dnspython provides the 'dns' package
	import dns.resolver as dns_resolver
	DNS_AVAILABLE = True
except ImportError:
	dns_resolver = None
	DNS_AVAILABLE = False
	from termcolor import colored
	print(colored("\n[!] Optional dependency missing: dnspython", 'yellow'))
	print(colored("    Install with: pip3 install dnspython", 'yellow'))
	print(colored("    Or: pip3 install -r requirements.txt", 'yellow'))

class AdvancedRecon:
    """Advanced Reconnaissance Module"""
    
    def __init__(self):
        self.helper = ReconHelper()
        self.results = {}
        self.target = None
        self.domain = None
        self.ip = None
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]
        
        # Subdomain wordlist (common subdomains)
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start'
        ]
        
        # API keys (optional - will check if available)
        from utils.config import config
        self.shodan_api = config.get('api_keys.shodan', '')
        self.censys_id = config.get('api_keys.censys_id', '')
        self.censys_secret = config.get('api_keys.censys_secret', '')
        self.use_shodan = config.get('reconnaissance.use_shodan', False) and bool(self.shodan_api)
        self.use_censys = config.get('reconnaissance.use_censys', False) and bool(self.censys_id)
        
        # S3 bucket patterns
        self.s3_patterns = [
            '{domain}',
            '{domain}-backup',
            '{domain}-data',
            '{domain}-dev',
            '{domain}-prod',
            '{domain}-assets',
            'backup-{domain}',
            'data-{domain}'
        ]
    
    def run(self):
        """Run interactive reconnaissance module"""
        try:
            print(colored("\n╔══════════════════════════════════════════════════════════╗", 'cyan'))
            print(colored("║     STROM Advanced Reconnaissance Module v2.0            ║", 'cyan', attrs=['bold']))
            print(colored("╚══════════════════════════════════════════════════════════╝", 'cyan'))
            
            target = input(colored("\n[+] Enter target (domain/IP/URL): ", 'blue'))
            self.target = target
            
            # Parse target
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                self.domain = parsed.netloc
            else:
                self.domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Get IP
            print(colored("\n[*] Resolving target...", 'yellow'))
            self.ip = self.helper.get_ip_from_domain(self.domain)
            
            if self.ip:
                print(colored(f"[+] Target IP: {self.ip}", 'green'))
            else:
                print(colored("[!] Could not resolve domain to IP", 'red'))
                # Assume it's already an IP
                self.ip = self.domain
            
            # Display reconnaissance menu
            self.show_menu()
            
        except KeyboardInterrupt:
            print(colored("\n\n[!] Reconnaissance interrupted", 'red'))
        except Exception as e:
            logger.error(f"Reconnaissance failed: {str(e)}")
            print(colored(f"[!] Error: {str(e)}", 'red'))
    
    def show_menu(self):
        """Show reconnaissance menu"""
        while True:
            print(colored("\n" + "="*60, 'cyan'))
            print(colored("              RECONNAISSANCE OPTIONS", 'white', attrs=['bold']))
            print(colored("="*60, 'cyan'))
            print(colored("  [1]  DNS Enumeration", 'white'))
            print(colored("  [2]  WHOIS Lookup", 'white'))
            print(colored("  [3]  Port Scanning", 'white'))
            print(colored("  [4]  Subdomain Enumeration", 'white'))
            print(colored("  [5]  SSL/TLS Certificate Analysis", 'white'))
            print(colored("  [6]  HTTP Headers Analysis", 'white'))
            print(colored("  [7]  Technology Detection", 'white'))
            print(colored("  [8]  Directory/File Discovery", 'white'))
            print(colored("  [9]  Email Harvesting", 'white'))
            print(colored("  [10] WAF Detection", 'white'))
            print(colored("  [11] Reverse DNS Lookup", 'white'))
            print(colored("  [12] Subdomain Takeover Detection", 'yellow'))  # NEW
            print(colored("  [13] GitHub/GitLab Dorking", 'yellow'))  # NEW
            print(colored("  [14] S3 Bucket Enumeration", 'yellow'))  # NEW
            print(colored("  [15] Shodan/Censys Lookup", 'yellow'))  # NEW
            print(colored("  [16] Google Dorking", 'yellow'))  # NEW
            print(colored("  [17] Full Reconnaissance (All)", 'green'))
            print(colored("  [18] Export Results", 'green'))
            print(colored("  [0]  Exit", 'red'))
            print(colored("="*60, 'cyan'))
            
            choice = input(colored("\n[?] Select option: ", 'blue'))
            
            if choice == '1':
                self.dns_enumeration()
            elif choice == '2':
                self.whois_lookup()
            elif choice == '3':
                self.port_scanning()
            elif choice == '4':
                self.subdomain_enumeration()
            elif choice == '5':
                self.ssl_analysis()
            elif choice == '6':
                self.http_headers_analysis()
            elif choice == '7':
                self.technology_detection()
            elif choice == '8':
                self.directory_discovery()
            elif choice == '9':
                self.email_harvesting()
            elif choice == '10':
                self.waf_detection()
            elif choice == '11':
                self.reverse_dns()
            elif choice == '12':
                self.subdomain_takeover_check()
            elif choice == '13':
                self.github_dorking()
            elif choice == '14':
                self.s3_bucket_enum()
            elif choice == '15':
                self.shodan_censys_lookup()
            elif choice == '16':
                self.google_dorking()
            elif choice == '17':
                self.full_recon()
            elif choice == '18':
                self.export_results()
            elif choice == '0':
                print(colored("[*] Exiting reconnaissance module...", 'yellow'))
                break
            else:
                print(colored("[!] Invalid option", 'red'))
    
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        print(colored("\n[*] Performing DNS enumeration...", 'yellow'))
        
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            records = self.helper.resolve_dns(self.domain, record_type)
            if records:
                dns_results[record_type] = records
                print(colored(f"[+] {record_type} Records:", 'cyan'))
                for record in records:
                    print(colored(f"    {record}", 'white'))
        
        self.results['dns'] = dns_results
        print(colored(f"\n[+] DNS enumeration completed", 'green'))
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        print(colored("\n[*] Performing WHOIS lookup...", 'yellow'))
        
        whois_data = self.helper.get_whois_info(self.domain)
        
        if whois_data:
            print(colored("\n[+] WHOIS Information:", 'cyan'))
            for key, value in whois_data.items():
                if value and value != 'None':
                    print(colored(f"  {key}: {value}", 'white'))
            
            self.results['whois'] = whois_data
            print(colored("\n[+] WHOIS lookup completed", 'green'))
        else:
            print(colored("[-] Could not retrieve WHOIS information", 'red'))
    
    def port_scanning(self):
        """Perform port scanning"""
        print(colored("\n[*] Scanning common ports...", 'yellow'))
        print(colored(f"[*] Target: {self.ip}", 'cyan'))
        
        open_ports = []
        
        # Quick scan mode option
        scan_mode = input(colored("[?] Quick scan (common ports) or Full scan (1-1024)? (q/f): ", 'blue')).lower()
        
        if scan_mode == 'f':
            ports_to_scan = range(1, 1025)
            print(colored("[*] Full scan mode: scanning ports 1-1024...", 'yellow'))
        else:
            ports_to_scan = self.common_ports
            print(colored(f"[*] Quick scan mode: scanning {len(self.common_ports)} common ports...", 'yellow'))
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.helper.check_port, self.ip, port): port for port in ports_to_scan}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        # Get service name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        print(colored(f"[+] Port {port:5d} OPEN  ({service})", 'green'))
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {str(e)}")
        
        self.results['open_ports'] = open_ports
        print(colored(f"\n[+] Port scan completed. Found {len(open_ports)} open ports", 'green'))
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        print(colored("\n[*] Enumerating subdomains...", 'yellow'))
        print(colored(f"[*] Testing {len(self.subdomain_wordlist)} common subdomains...", 'cyan'))
        
        found_subdomains = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = self.helper.get_ip_from_domain(subdomain)
                if ip:
                    return (subdomain, ip)
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.subdomain_wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    found_subdomains.append({'subdomain': subdomain, 'ip': ip})
                    print(colored(f"[+] Found: {subdomain:40s} -> {ip}", 'green'))
        
        self.results['subdomains'] = found_subdomains
        print(colored(f"\n[+] Subdomain enumeration completed. Found {len(found_subdomains)} subdomains", 'green'))
    
    def ssl_analysis(self):
        """Analyze SSL/TLS certificate"""
        print(colored("\n[*] Analyzing SSL/TLS certificate...", 'yellow'))
        
        cert_info = self.helper.get_ssl_cert_info(self.domain)
        
        if cert_info:
            print(colored("\n[+] SSL Certificate Information:", 'cyan'))
            print(colored(f"  Subject: {cert_info['subject']}", 'white'))
            print(colored(f"  Issuer: {cert_info['issuer']}", 'white'))
            print(colored(f"  Valid From: {cert_info['notBefore']}", 'white'))
            print(colored(f"  Valid Until: {cert_info['notAfter']}", 'white'))
            print(colored(f"  Serial Number: {cert_info['serialNumber']}", 'white'))
            
            if cert_info.get('subjectAltName'):
                print(colored(f"  Subject Alt Names:", 'white'))
                for alt_name in cert_info['subjectAltName']:
                    print(colored(f"    - {alt_name[1]}", 'white'))
            
            self.results['ssl'] = cert_info
            print(colored("\n[+] SSL analysis completed", 'green'))
        else:
            print(colored("[-] Could not retrieve SSL certificate", 'red'))
    
    def http_headers_analysis(self):
        """Analyze HTTP headers"""
        print(colored("\n[*] Analyzing HTTP headers...", 'yellow'))
        
        url = self.target if self.target.startswith('http') else f"http://{self.domain}"
        headers = self.helper.get_http_headers(url)
        
        if headers:
            print(colored("\n[+] HTTP Headers:", 'cyan'))
            for key, value in headers.items():
                print(colored(f"  {key}: {value}", 'white'))
            
            # Security headers check
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS filter'
            }
            
            print(colored("\n[*] Security Headers Analysis:", 'yellow'))
            for header, description in security_headers.items():
                if header in headers:
                    print(colored(f"  [✓] {header}: Present ({description})", 'green'))
                else:
                    print(colored(f"  [✗] {header}: Missing ({description})", 'red'))
            
            self.results['headers'] = headers
            print(colored("\n[+] HTTP headers analysis completed", 'green'))
        else:
            print(colored("[-] Could not retrieve HTTP headers", 'red'))
    
    def technology_detection(self):
        """Detect web technologies"""
        print(colored("\n[*] Detecting web technologies...", 'yellow'))
        
        url = self.target if self.target.startswith('http') else f"http://{self.domain}"
        
        try:
            resp = requests.get(url, timeout=10)
            headers = dict(resp.headers)
            content = resp.text
            
            technologies = []
            
            # Server detection
            if 'Server' in headers:
                technologies.append({'type': 'Server', 'name': headers['Server']})
            
            # Technology detection patterns
            tech_patterns = {
                'WordPress': [r'wp-content', r'wp-includes'],
                'Joomla': [r'/components/com_', r'Joomla!'],
                'Drupal': [r'Drupal', r'/sites/default'],
                'PHP': [r'\.php', r'PHPSESSID'],
                'ASP.NET': [r'\.aspx', r'__VIEWSTATE'],
                'Django': [r'csrfmiddlewaretoken'],
                'Laravel': [r'laravel_session'],
                'React': [r'react', r'_reactRoot'],
                'Vue.js': [r'vue\.js', r'__vue__'],
                'Angular': [r'ng-', r'angular'],
                'jQuery': [r'jquery'],
                'Bootstrap': [r'bootstrap'],
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.append({'type': 'Technology', 'name': tech})
                        break
            
            # Remove duplicates
            unique_techs = []
            seen = set()
            for tech in technologies:
                key = (tech['type'], tech['name'])
                if key not in seen:
                    seen.add(key)
                    unique_techs.append(tech)
            
            if unique_techs:
                print(colored("\n[+] Detected Technologies:", 'cyan'))
                for tech in unique_techs:
                    print(colored(f"  {tech['type']}: {tech['name']}", 'white'))
                
                self.results['technologies'] = unique_techs
                print(colored("\n[+] Technology detection completed", 'green'))
            else:
                print(colored("[-] No specific technologies detected", 'yellow'))
                
        except Exception as e:
            print(colored(f"[-] Technology detection failed: {str(e)}", 'red'))
    
    def directory_discovery(self):
        """Discover directories and files"""
        print(colored("\n[*] Discovering directories and files...", 'yellow'))
        
        url = self.target if self.target.startswith('http') else f"http://{self.domain}"
        
        # Check robots.txt
        robots = self.helper.get_robots_txt(url)
        if robots:
            print(colored("\n[+] robots.txt found:", 'cyan'))
            print(colored(robots[:500], 'white'))
        
        # Check sitemap
        sitemap = self.helper.get_sitemap(url)
        if sitemap:
            print(colored("\n[+] sitemap.xml found", 'cyan'))
        
        # Common paths
        common_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin',
            '/dashboard', '/api', '/backup', '/config', '/database',
            '/.git', '/.env', '/server-status', '/phpinfo.php'
        ]
        
        print(colored("\n[*] Checking common paths...", 'yellow'))
        found_paths = []
        
        for path in common_paths:
            try:
                test_url = url.rstrip('/') + path
                resp = requests.get(test_url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    found_paths.append({'path': path, 'status': resp.status_code})
                    status_color = 'green' if resp.status_code == 200 else 'yellow'
                    print(colored(f"[+] {path:30s} [{resp.status_code}]", status_color))
            except:
                pass
        
        self.results['directories'] = {
            'robots': robots,
            'sitemap': sitemap is not None,
            'found_paths': found_paths
        }
        
        print(colored(f"\n[+] Directory discovery completed. Found {len(found_paths)} paths", 'green'))
    
    def email_harvesting(self):
        """Harvest email addresses"""
        print(colored("\n[*] Harvesting email addresses...", 'yellow'))
        
        url = self.target if self.target.startswith('http') else f"http://{self.domain}"
        
        try:
            resp = requests.get(url, timeout=10)
            emails = self.helper.extract_emails(resp.text)
            
            if emails:
                print(colored(f"\n[+] Found {len(emails)} email addresses:", 'cyan'))
                for email in emails:
                    print(colored(f"  {email}", 'white'))
                
                self.results['emails'] = emails
                print(colored("\n[+] Email harvesting completed", 'green'))
            else:
                print(colored("[-] No email addresses found", 'yellow'))
        except Exception as e:
            print(colored(f"[-] Email harvesting failed: {str(e)}", 'red'))
    
    def waf_detection(self):
        """Detect Web Application Firewall"""
        print(colored("\n[*] Detecting WAF...", 'yellow'))
        
        url = self.target if self.target.startswith('http') else f"http://{self.domain}"
        waf = self.helper.detect_waf_simple(url)
        
        if waf:
            print(colored(f"\n[+] WAF Detected: {waf}", 'red', attrs=['bold']))
            self.results['waf'] = waf
        else:
            print(colored("[-] No WAF detected", 'green'))
            self.results['waf'] = None
    
    def reverse_dns(self):
        """Perform reverse DNS lookup"""
        print(colored("\n[*] Performing reverse DNS lookup...", 'yellow'))
        
        if self.ip:
            hostname = self.helper.reverse_dns_lookup(self.ip)
            if hostname:
                print(colored(f"[+] Hostname: {hostname}", 'cyan'))
                self.results['reverse_dns'] = hostname
            else:
                print(colored("[-] No PTR record found", 'yellow'))
        else:
            print(colored("[-] No IP address available", 'red'))
    
    def subdomain_takeover_check(self):
        """Check for subdomain takeover vulnerabilities"""
        print(colored("\n[+] Subdomain Takeover Detection", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        if 'subdomains' not in self.results or not self.results['subdomains']:
            print(colored("[!] Run subdomain enumeration first", 'red'))
            return
        
        # Vulnerable CNAME patterns
        vulnerable_patterns = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'amazonaws.com': 'AWS S3',
            'azurewebsites.net': 'Azure',
            'cloudfront.net': 'CloudFront',
            'netlify.com': 'Netlify',
            'vercel.app': 'Vercel',
            'zendesk.com': 'Zendesk',
            'helpscout.net': 'HelpScout'
        }
        
        vulnerable_subdomains = []
        
        for subdomain_data in self.results['subdomains']:
            subdomain = subdomain_data['subdomain']
            
            try:
                # Check CNAME records
                cnames = self.helper.resolve_dns(subdomain, 'CNAME')
                
                for cname in cnames:
                    for pattern, service in vulnerable_patterns.items():
                        if pattern in cname:
                            # Try to access
                            try:
                                resp = requests.get(f"http://{subdomain}", timeout=5)
                                # Check for takeover indicators
                                takeover_indicators = [
                                    'There isn\'t a GitHub Pages site here',
                                    'No such app',
                                    'NoSuchBucket',
                                    'Not Found'
                                ]
                                
                                for indicator in takeover_indicators:
                                    if indicator in resp.text:
                                        vulnerable_subdomains.append({
                                            'subdomain': subdomain,
                                            'cname': cname,
                                            'service': service,
                                            'indicator': indicator
                                        })
                                        print(colored(f"[!] VULNERABLE: {subdomain} -> {cname} ({service})", 'red', attrs=['bold']))
                                        break
                            except:
                                pass
            except:
                continue
        
        if vulnerable_subdomains:
            print(colored(f"\n[!] Found {len(vulnerable_subdomains)} potential subdomain takeovers!", 'red', attrs=['bold']))
            self.results['subdomain_takeover'] = vulnerable_subdomains
        else:
            print(colored("\n[+] No subdomain takeover vulnerabilities found", 'green'))
    
    def github_dorking(self):
        """GitHub/GitLab dorking for exposed secrets"""
        print(colored("\n[+] GitHub/GitLab Dorking", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        domain_name = self.domain.split('.')[0]
        
        # GitHub dorks
        github_dorks = [
            f"{domain_name} password",
            f"{domain_name} api_key",
            f"{domain_name} secret",
            f"{domain_name} token",
            f"{domain_name} aws_access_key",
            f"{domain_name} credentials",
            f"{domain_name} db_password",
            f"filename:.env {domain_name}",
            f"filename:config.php {domain_name}",
            f"extension:pem {domain_name}",
        ]
        
        print(colored("\n[*] GitHub Search Queries:", 'cyan'))
        for dork in github_dorks:
            github_url = f"https://github.com/search?q={requests.utils.quote(dork)}&type=code"
            print(colored(f"  {github_url}", 'white'))
        
        print(colored("\n[*] GitLab Search Queries:", 'cyan'))
        for dork in github_dorks:
            gitlab_url = f"https://gitlab.com/search?search={requests.utils.quote(dork)}"
            print(colored(f"  {gitlab_url}", 'white'))
        
        print(colored("\n[!] Manual review required for exposed secrets", 'yellow'))
        
        self.results['github_dorking'] = {
            'github_queries': [f"https://github.com/search?q={requests.utils.quote(d)}&type=code" for d in github_dorks],
            'gitlab_queries': [f"https://gitlab.com/search?search={requests.utils.quote(d)}" for d in github_dorks]
        }
    
    def s3_bucket_enum(self):
        """S3 bucket enumeration"""
        print(colored("\n[+] S3 Bucket Enumeration", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        domain_base = self.domain.replace('.', '-').replace('www', '')
        
        found_buckets = []
        
        print(colored(f"[*] Testing S3 bucket patterns for: {domain_base}", 'cyan'))
        
        for pattern in self.s3_patterns:
            bucket_name = pattern.format(domain=domain_base)
            s3_urls = [
                f"http://{bucket_name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket_name}",
                f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com"
            ]
            
            for url in s3_urls:
                try:
                    resp = requests.head(url, timeout=5)
                    if resp.status_code in [200, 403]:
                        # Bucket exists
                        found_buckets.append({
                            'bucket': bucket_name,
                            'url': url,
                            'status': resp.status_code,
                            'accessible': resp.status_code == 200
                        })
                        
                        status_color = 'red' if resp.status_code == 200 else 'yellow'
                        access_text = 'PUBLIC' if resp.status_code == 200 else 'PRIVATE'
                        print(colored(f"[+] Found: {bucket_name} [{access_text}]", status_color))
                        break
                except:
                    continue
        
        if found_buckets:
            print(colored(f"\n[+] Found {len(found_buckets)} S3 buckets", 'green'))
            self.results['s3_buckets'] = found_buckets
            
            # Check for public buckets
            public_buckets = [b for b in found_buckets if b['accessible']]
            if public_buckets:
                print(colored(f"[!] WARNING: {len(public_buckets)} PUBLIC buckets found!", 'red', attrs=['bold']))
        else:
            print(colored("\n[-] No S3 buckets found", 'yellow'))
    
    def shodan_censys_lookup(self):
        """Shodan/Censys API lookup"""
        print(colored("\n[+] Shodan/Censys Lookup", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        if not self.ip:
            print(colored("[!] No IP address available", 'red'))
            return
        
        results = {}
        
        # Check if APIs are configured
        if not self.shodan_api and not self.censys_id:
            print(colored("\n[!] No API keys configured", 'yellow'))
            print(colored("[*] This feature is optional. You can:", 'cyan'))
            print(colored("    1. Continue without API lookups", 'white'))
            print(colored("    2. Get free Shodan API key at https://account.shodan.io/register", 'white'))
            print(colored("    3. Get Censys API at https://censys.io/register", 'white'))
            print(colored("\n[*] To enable: Add API keys to config.yaml", 'cyan'))
            return
        
        # Shodan lookup
        if self.use_shodan and self.shodan_api:
            print(colored("\n[*] Querying Shodan API...", 'cyan'))
            try:
                import shodan
                api = shodan.Shodan(self.shodan_api)
                host = api.host(self.ip)
                
                print(colored(f"[+] Organization: {host.get('org', 'N/A')}", 'white'))
                print(colored(f"[+] Operating System: {host.get('os', 'N/A')}", 'white'))
                print(colored(f"[+] Open Ports: {', '.join(map(str, host.get('ports', [])))}", 'white'))
                
                if 'vulns' in host:
                    print(colored(f"[!] Known Vulnerabilities: {len(host['vulns'])}", 'red'))
                    for vuln in list(host['vulns'].keys())[:5]:
                        print(colored(f"    - {vuln}", 'red'))
                
                results['shodan'] = {
                    'org': host.get('org'),
                    'os': host.get('os'),
                    'ports': host.get('ports'),
                    'vulns': list(host.get('vulns', {}).keys())
                }
                
            except ImportError:
                print(colored("[!] Shodan library not installed. Install with: pip install shodan", 'yellow'))
            except Exception as e:
                print(colored(f"[!] Shodan error: {str(e)}", 'red'))
        else:
            print(colored("[!] Shodan API not configured or disabled", 'yellow'))
        
        # Censys lookup
        if self.use_censys and self.censys_id and self.censys_secret:
            print(colored("\n[*] Querying Censys API...", 'cyan'))
            try:
                from censys.search import CensysHosts
                h = CensysHosts(self.censys_id, self.censys_secret)
                host = h.view(self.ip)
                
                print(colored(f"[+] Services: {len(host.get('services', []))}", 'white'))
                for service in host.get('services', [])[:5]:
                    print(colored(f"    - Port {service['port']}: {service.get('service_name', 'Unknown')}", 'white'))
                
                results['censys'] = {
                    'services': host.get('services', []),
                    'location': host.get('location', {})
                }
                
            except ImportError:
                print(colored("[!] Censys library not installed. Install with: pip install censys", 'yellow'))
            except Exception as e:
                print(colored(f"[!] Censys error: {str(e)}", 'red'))
        else:
            print(colored("[!] Censys API not configured or disabled", 'yellow'))
        
        if results:
            self.results['api_lookups'] = results
        else:
            print(colored("\n[*] Skipping API lookups - not critical for reconnaissance", 'cyan'))

    def google_dorking(self):
        """Google dorking automation"""
        print(colored("\n[+] Google Dorking", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        # Google dorks
        dorks = [
            f"site:{self.domain} intitle:index.of",
            f"site:{self.domain} ext:php inurl:?id=",
            f"site:{self.domain} ext:asp inurl:?id=",
            f"site:{self.domain} ext:jsp inurl:?id=",
            f"site:{self.domain} inurl:admin",
            f"site:{self.domain} inurl:login",
            f"site:{self.domain} inurl:upload",
            f"site:{self.domain} filetype:sql",
            f"site:{self.domain} filetype:log",
            f"site:{self.domain} filetype:bak",
            f"site:{self.domain} filetype:old",
            f"site:{self.domain} intext:\"sql syntax near\"",
            f"site:{self.domain} intext:\"mysql_fetch\"",
            f"site:{self.domain} inurl:.env",
            f"site:{self.domain} inurl:config.php",
        ]
        
        print(colored("\n[*] Google Dork Queries:", 'cyan'))
        for i, dork in enumerate(dorks, 1):
            google_url = f"https://www.google.com/search?q={requests.utils.quote(dork)}"
            print(colored(f"  {i:2d}. {dork}", 'white'))
            print(colored(f"      {google_url}", 'cyan'))
        
        print(colored("\n[!] Note: Execute these queries manually to avoid CAPTCHA", 'yellow'))
        
        self.results['google_dorks'] = dorks

    def full_recon(self):
        """Perform full reconnaissance"""
        print(colored("\n[*] Starting FULL reconnaissance...", 'yellow', attrs=['bold']))
        print(colored("[*] This may take several minutes...\n", 'yellow'))
        
        tasks = [
            ("DNS Enumeration", self.dns_enumeration),
            ("WHOIS Lookup", self.whois_lookup),
            ("Port Scanning", self.port_scanning),
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("SSL Analysis", self.ssl_analysis),
            ("HTTP Headers", self.http_headers_analysis),
            ("Technology Detection", self.technology_detection),
            ("Directory Discovery", self.directory_discovery),
            ("Email Harvesting", self.email_harvesting),
            ("WAF Detection", self.waf_detection),
            ("Reverse DNS", self.reverse_dns)
        ]
        
        for i, (task_name, task_func) in enumerate(tasks, 1):
            print(colored(f"\n[{i}/{len(tasks)}] {task_name}", 'cyan', attrs=['bold']))
            try:
                task_func()
            except Exception as e:
                print(colored(f"[!] {task_name} failed: {str(e)}", 'red'))
        
        print(colored("\n\n" + "="*60, 'green'))
        print(colored("         FULL RECONNAISSANCE COMPLETED", 'green', attrs=['bold']))
        print(colored("="*60, 'green'))
    
    def export_results(self):
        """Export reconnaissance results"""
        if not self.results:
            print(colored("\n[-] No results to export", 'yellow'))
            return
        
        print(colored("\n[*] Exporting results...", 'yellow'))
        
        # Create report structure
        report = {
            'target': self.target,
            'domain': self.domain,
            'ip': self.ip,
            'scan_time': datetime.now().isoformat(),
            'results': self.results
        }
        
        # Export to JSON
        json_filename = f"recon_{self.domain}_{int(time.time())}.json"
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Export to TXT (summary)
        txt_filename = f"recon_{self.domain}_{int(time.time())}.txt"
        with open(txt_filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write(f"RECONNAISSANCE REPORT - {self.domain}\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Domain: {self.domain}\n")
            f.write(f"IP Address: {self.ip}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for key, value in self.results.items():
                f.write(f"\n{key.upper()}:\n")
                f.write("-" * 40 + "\n")
                f.write(f"{json.dumps(value, indent=2, default=str)}\n")
        
        print(colored(f"\n[+] Results exported:", 'green'))
        print(colored(f"    - JSON: {json_filename}", 'cyan'))
        print(colored(f"    - TXT:  {txt_filename}", 'cyan'))

if __name__ == "__main__":
    recon = AdvancedRecon()
    recon.run()
