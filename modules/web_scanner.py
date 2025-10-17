#!/usr/bin/env python3
import requests
import time
from urllib.parse import urlparse, urljoin
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scanner_helper import ScannerHelper
from core.payloads import PayloadGenerator
from utils.logger import setup_logger

logger = setup_logger('web_scanner')

class WebScanner:
    """Comprehensive Web Vulnerability Scanner"""
    
    def __init__(self):
        self.helper = ScannerHelper()
        self.payloads = PayloadGenerator()
        self.session = requests.Session()
        self.target = None
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.crawl_depth = 3
        
    def run(self):
        """Run interactive web scanner"""
        try:
            print(colored("\n╔══════════════════════════════════════════════════════════╗", 'green'))
            print(colored("║        STROM Web Vulnerability Scanner v2.0              ║", 'green', attrs=['bold']))
            print(colored("╚══════════════════════════════════════════════════════════╝", 'green'))
            
            target = input(colored("\n[+] Target URL: ", 'blue'))
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            self.target = target
            
            print(colored("\n[*] Scan Options:", 'cyan'))
            print(colored("  [1] Quick Scan (Basic checks)", 'white'))
            print(colored("  [2] Standard Scan (Recommended)", 'white'))
            print(colored("  [3] Deep Scan (Thorough, may take time)", 'white'))
            print(colored("  [4] Custom Scan", 'white'))
            
            choice = input(colored("\n[?] Select scan type (1-4): ", 'blue'))
            
            if choice == '1':
                self.quick_scan()
            elif choice == '2':
                self.standard_scan()
            elif choice == '3':
                self.deep_scan()
            elif choice == '4':
                self.custom_scan()
            
            # Show results
            self.show_results()
            
        except KeyboardInterrupt:
            print(colored("\n[!] Scan interrupted", 'red'))
        except Exception as e:
            logger.error(f"Scanner error: {str(e)}")
            print(colored(f"[!] Error: {str(e)}", 'red'))
    
    def quick_scan(self):
        """Quick vulnerability scan"""
        print(colored("\n[*] Starting Quick Scan...", 'yellow'))
        
        self.check_robots_sitemap()
        self.check_security_headers()
        self.detect_cms()
        self.check_common_files()
        
        print(colored("\n[+] Quick scan completed", 'green'))
    
    def standard_scan(self):
        """Standard vulnerability scan"""
        print(colored("\n[*] Starting Standard Scan...", 'yellow'))
        
        self.quick_scan()
        self.crawl_website(depth=2)
        self.scan_forms()
        self.check_backup_files()
        self.check_git_exposure()
        
        print(colored("\n[+] Standard scan completed", 'green'))
    
    def deep_scan(self):
        """Deep vulnerability scan"""
        print(colored("\n[*] Starting Deep Scan...", 'yellow'))
        print(colored("[!] This may take a while...", 'yellow'))
        
        self.standard_scan()
        self.crawl_website(depth=3)
        self.directory_bruteforce()
        self.check_ssl_vulnerabilities()
        self.scan_api_endpoints()
        
        print(colored("\n[+] Deep scan completed", 'green'))
    
    def custom_scan(self):
        """Custom scan with user selection"""
        print(colored("\n[*] Custom Scan Configuration", 'cyan'))
        
        checks = {
            '1': ('Robots.txt & Sitemap', self.check_robots_sitemap),
            '2': ('Security Headers', self.check_security_headers),
            '3': ('CMS Detection', self.detect_cms),
            '4': ('Common Files', self.check_common_files),
            '5': ('Crawl Website', lambda: self.crawl_website(depth=2)),
            '6': ('Form Scanning', self.scan_forms),
            '7': ('Backup Files', self.check_backup_files),
            '8': ('Git Exposure', self.check_git_exposure),
            '9': ('SSL Vulnerabilities', self.check_ssl_vulnerabilities),
            '10': ('API Endpoints', self.scan_api_endpoints)
        }
        
        for key, (name, _) in checks.items():
            print(colored(f"  [{key}] {name}", 'white'))
        
        selected = input(colored("\n[?] Select checks (comma-separated, e.g., 1,2,3): ", 'blue')).split(',')
        
        for selection in selected:
            selection = selection.strip()
            if selection in checks:
                name, func = checks[selection]
                print(colored(f"\n[*] Running: {name}", 'yellow'))
                func()
    
    def check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml"""
        print(colored("\n[*] Checking robots.txt and sitemap.xml...", 'cyan'))
        
        # Check robots.txt
        robots_url = urljoin(self.target, '/robots.txt')
        try:
            resp = self.session.get(robots_url, timeout=5)
            if resp.status_code == 200:
                print(colored("[+] robots.txt found", 'green'))
                print(colored(f"    {robots_url}", 'white'))
                
                # Extract disallowed paths
                disallowed = re.findall(r'Disallow:\s*(.+)', resp.text)
                if disallowed:
                    print(colored(f"    Found {len(disallowed)} disallowed paths", 'cyan'))
                    for path in disallowed[:5]:
                        print(colored(f"      - {path}", 'white'))
        except:
            pass
        
        # Check sitemap.xml
        sitemap_url = urljoin(self.target, '/sitemap.xml')
        try:
            resp = self.session.get(sitemap_url, timeout=5)
            if resp.status_code == 200:
                print(colored("[+] sitemap.xml found", 'green'))
                print(colored(f"    {sitemap_url}", 'white'))
        except:
            pass
    
    def check_security_headers(self):
        """Check security headers"""
        print(colored("\n[*] Analyzing security headers...", 'cyan'))
        
        try:
            resp = self.session.get(self.target, timeout=5)
            headers = self.helper.check_security_headers(resp.headers)
            
            print(colored("\n  Security Headers Status:", 'yellow'))
            for header, present in headers.items():
                if present:
                    print(colored(f"    [✓] {header}: Present", 'green'))
                else:
                    print(colored(f"    [✗] {header}: Missing", 'red'))
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'header': header,
                        'url': self.target
                    })
        except Exception as e:
            logger.debug(f"Security headers check failed: {e}")
    
    def detect_cms(self):
        """Detect CMS"""
        print(colored("\n[*] Detecting CMS...", 'cyan'))
        
        try:
            resp = self.session.get(self.target, timeout=10)
            cms_list = self.helper.detect_cms(resp.text, resp.headers)
            
            if cms_list:
                for cms in cms_list:
                    print(colored(f"[+] Detected: {cms}", 'green'))
                    
                    # CMS-specific checks
                    if cms == 'WordPress':
                        self.check_wordpress()
                    elif cms == 'Joomla':
                        self.check_joomla()
            else:
                print(colored("[-] No CMS detected", 'yellow'))
        except Exception as e:
            logger.debug(f"CMS detection failed: {e}")
    
    def check_wordpress(self):
        """WordPress-specific checks"""
        print(colored("  [*] Running WordPress checks...", 'cyan'))
        
        wp_paths = [
            '/wp-admin/',
            '/wp-login.php',
            '/wp-json/wp/v2/users',
            '/wp-content/uploads/',
            '/wp-config.php.bak',
            '/readme.html'
        ]
        
        for path in wp_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 301, 302]:
                    print(colored(f"    [+] Found: {path}", 'yellow'))
            except:
                pass
    
    def check_joomla(self):
        """Joomla-specific checks"""
        print(colored("  [*] Running Joomla checks...", 'cyan'))
        
        joomla_paths = [
            '/administrator/',
            '/configuration.php.bak',
            '/README.txt'
        ]
        
        for path in joomla_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 301, 302]:
                    print(colored(f"    [+] Found: {path}", 'yellow'))
            except:
                pass
    
    def check_common_files(self):
        """Check for common sensitive files"""
        print(colored("\n[*] Checking common sensitive files...", 'cyan'))
        
        common_files = [
            '.env', '.git/config', '.gitignore', '.htaccess', '.htpasswd',
            'config.php', 'config.inc.php', 'database.yml', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'backup.sql', 'dump.sql',
            'admin.php', 'login.php', 'install.php', 'setup.php'
        ]
        
        found_files = []
        
        for file in common_files:
            url = urljoin(self.target, file)
            try:
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 403]:
                    found_files.append(file)
                    status_color = 'red' if resp.status_code == 200 else 'yellow'
                    print(colored(f"[+] Found: {file} [{resp.status_code}]", status_color))
                    
                    if resp.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Sensitive File Exposed',
                            'severity': 'HIGH',
                            'file': file,
                            'url': url
                        })
            except:
                continue
        
        if found_files:
            print(colored(f"\n  [!] Found {len(found_files)} sensitive files", 'red'))
    
    def crawl_website(self, depth=2):
        """Crawl website to discover URLs"""
        print(colored(f"\n[*] Crawling website (depth: {depth})...", 'cyan'))
        
        to_crawl = [(self.target, 0)]
        crawled = set()
        
        while to_crawl:
            url, current_depth = to_crawl.pop(0)
            
            if url in crawled or current_depth > depth:
                continue
            
            crawled.add(url)
            
            try:
                resp = self.session.get(url, timeout=5)
                urls = self.helper.extract_urls(resp.text, url)
                
                self.discovered_urls.update(urls)
                
                for new_url in urls:
                    if new_url not in crawled:
                        to_crawl.append((new_url, current_depth + 1))
                
                print(f"\r  Discovered URLs: {len(self.discovered_urls)}", end='', flush=True)
                
            except:
                continue
        
        print(colored(f"\n[+] Crawling complete. Found {len(self.discovered_urls)} URLs", 'green'))
    
    def scan_forms(self):
        """Scan forms for vulnerabilities"""
        print(colored("\n[*] Scanning forms...", 'cyan'))
        
        if not self.discovered_urls:
            self.crawl_website(depth=1)
        
        total_forms = 0
        
        for url in list(self.discovered_urls)[:50]:  # Limit to 50 URLs
            try:
                resp = self.session.get(url, timeout=5)
                forms = self.helper.extract_forms(resp.text, url)
                
                total_forms += len(forms)
                
                for form in forms:
                    # Check for CSRF protection
                    csrf_tokens = ['csrf', 'token', '_token', 'authenticity_token']
                    has_csrf = any(csrf in str(form['inputs']).lower() for csrf in csrf_tokens)
                    
                    if not has_csrf:
                        print(colored(f"  [!] Form without CSRF protection: {form['action']}", 'yellow'))
                        self.vulnerabilities.append({
                            'type': 'Missing CSRF Protection',
                            'severity': 'MEDIUM',
                            'form_action': form['action'],
                            'url': url
                        })
            except:
                continue
        
        print(colored(f"[+] Scanned {total_forms} forms", 'green'))
    
    def check_backup_files(self):
        """Check for backup files"""
        print(colored("\n[*] Checking for backup files...", 'cyan'))
        
        parsed = urlparse(self.target)
        base_path = parsed.path.rstrip('/')
        
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save', '.swp', 
            '.tmp', '~', '.copy', '.BAK', '.sql'
        ]
        
        test_files = ['index.php', 'config.php', 'database.php', 'admin.php']
        
        for file in test_files:
            for ext in backup_extensions:
                test_url = urljoin(self.target, f"{file}{ext}")
                try:
                    resp = self.session.head(test_url, timeout=3)
                    if resp.status_code == 200:
                        print(colored(f"[+] Backup file found: {file}{ext}", 'red'))
                        self.vulnerabilities.append({
                            'type': 'Backup File Exposed',
                            'severity': 'HIGH',
                            'url': test_url
                        })
                except:
                    continue
    
    def check_git_exposure(self):
        """Check for exposed .git directory"""
        print(colored("\n[*] Checking for .git exposure...", 'cyan'))
        
        git_files = [
            '/.git/config',
            '/.git/HEAD',
            '/.git/index',
            '/.git/logs/HEAD'
        ]
        
        for git_file in git_files:
            url = urljoin(self.target, git_file)
            try:
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200:
                    print(colored(f"[!] .git directory exposed: {git_file}", 'red', attrs=['bold']))
                    self.vulnerabilities.append({
                        'type': 'Git Repository Exposed',
                        'severity': 'CRITICAL',
                        'url': url
                    })
                    break
            except:
                continue
    
    def directory_bruteforce(self):
        """Bruteforce common directories"""
        print(colored("\n[*] Directory bruteforce...", 'cyan'))
        
        common_dirs = [
            'admin', 'administrator', 'backup', 'backups', 'config', 'conf',
            'data', 'db', 'download', 'downloads', 'files', 'images', 'img',
            'include', 'includes', 'log', 'logs', 'old', 'temp', 'tmp',
            'upload', 'uploads', 'user', 'users', 'wp-admin', 'api', 'v1', 'v2'
        ]
        
        found_dirs = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_directory, dir_name): dir_name for dir_name in common_dirs}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_dirs.append(result)
        
        if found_dirs:
            print(colored(f"\n[+] Found {len(found_dirs)} directories", 'green'))
    
    def _check_directory(self, dir_name):
        """Check if directory exists"""
        url = urljoin(self.target, f"/{dir_name}/")
        try:
            resp = self.session.head(url, timeout=3, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                print(colored(f"[+] Found: /{dir_name}/ [{resp.status_code}]", 'green'))
                return dir_name
        except:
            pass
        return None
    
    def check_ssl_vulnerabilities(self):
        """Check SSL/TLS vulnerabilities"""
        print(colored("\n[*] Checking SSL/TLS configuration...", 'cyan'))
        
        if not self.target.startswith('https://'):
            print(colored("[-] Target is not HTTPS", 'yellow'))
            self.vulnerabilities.append({
                'type': 'No HTTPS',
                'severity': 'HIGH',
                'url': self.target
            })
            return
        
        try:
            import ssl
            import socket
            
            hostname = urlparse(self.target).netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    print(colored(f"  [+] SSL/TLS Version: {version}", 'cyan'))
                    
                    # Check for weak protocols
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        print(colored(f"  [!] Weak TLS version: {version}", 'red'))
                        self.vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'HIGH',
                            'version': version,
                            'url': self.target
                        })
                    else:
                        print(colored(f"  [+] TLS version is acceptable", 'green'))
        except Exception as e:
            logger.debug(f"SSL check failed: {e}")
    
    def scan_api_endpoints(self):
        """Scan for API endpoints"""
        print(colored("\n[*] Scanning for API endpoints...", 'cyan'))
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/swagger.json', '/swagger-ui',
            '/api-docs', '/openapi.json', '/api/swagger.json'
        ]
        
        found_apis = []
        
        for path in api_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    print(colored(f"[+] API endpoint found: {path}", 'green'))
                    found_apis.append(path)
            except:
                continue
        
        if found_apis:
            print(colored(f"\n[+] Found {len(found_apis)} API endpoints", 'green'))
    
    def show_results(self):
        """Display scan results"""
        print(colored("\n" + "="*70, 'green'))
        print(colored("                  SCAN RESULTS", 'white', attrs=['bold']))
        print(colored("="*70, 'green'))
        
        if not self.vulnerabilities:
            print(colored("\n[+] No vulnerabilities found", 'green'))
            return
        
        # Group by severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            by_severity[severity].append(vuln)
        
        print(colored(f"\n[!] Total Vulnerabilities: {len(self.vulnerabilities)}", 'red', attrs=['bold']))
        print(colored(f"    Critical: {len(by_severity['CRITICAL'])}", 'red'))
        print(colored(f"    High: {len(by_severity['HIGH'])}", 'yellow'))
        print(colored(f"    Medium: {len(by_severity['MEDIUM'])}", 'cyan'))
        print(colored(f"    Low: {len(by_severity['LOW'])}", 'white'))
        
        # Show details
        for severity, vulns in by_severity.items():
            if vulns:
                print(colored(f"\n{severity} Severity:", severity.lower() if severity != 'CRITICAL' else 'red', attrs=['bold']))
                for vuln in vulns[:5]:  # Show first 5
                    print(colored(f"  • {vuln['type']}", 'white'))
                    if 'url' in vuln:
                        print(colored(f"    URL: {vuln['url']}", 'cyan'))
        
        # Save report
        save = input(colored("\n[?] Save report to file? (y/N): ", 'yellow')).lower()
        if save == 'y':
            import json
            filename = f"web_scan_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.target,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'vulnerabilities': self.vulnerabilities,
                    'discovered_urls': list(self.discovered_urls)
                }, f, indent=2)
            print(colored(f"[+] Report saved: {filename}", 'green'))

if __name__ == "__main__":
    scanner = WebScanner()
    scanner.run()
