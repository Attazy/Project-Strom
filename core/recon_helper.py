#!/usr/bin/env python3
import socket
import ssl
import dns.resolver
import whois
from urllib.parse import urlparse
import requests
import re

class ReconHelper:
    """Helper functions for reconnaissance tasks"""
    
    @staticmethod
    def resolve_dns(domain, record_type='A'):
        """Resolve DNS records for a domain"""
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    @staticmethod
    def get_ip_from_domain(domain):
        """Get IP address from domain"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
    
    @staticmethod
    def reverse_dns_lookup(ip):
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    @staticmethod
    def get_ssl_cert_info(domain, port=443):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return None
    
    @staticmethod
    def get_whois_info(domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            return None
    
    @staticmethod
    def check_port(ip, port, timeout=1):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def get_http_headers(url):
        """Get HTTP response headers"""
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            return dict(resp.headers)
        except:
            try:
                resp = requests.get(url, timeout=5, allow_redirects=True)
                return dict(resp.headers)
            except:
                return {}
    
    @staticmethod
    def extract_emails(text):
        """Extract email addresses from text"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))
    
    @staticmethod
    def extract_subdomains(text, domain):
        """Extract subdomains from text"""
        subdomain_pattern = rf'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(domain)}'
        matches = re.findall(subdomain_pattern, text)
        return list(set([m[0] + domain if m[0] else domain for m in matches]))
    
    @staticmethod
    def get_robots_txt(url):
        """Fetch and parse robots.txt"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = requests.get(robots_url, timeout=5)
            if resp.status_code == 200:
                return resp.text
        except:
            pass
        return None
    
    @staticmethod
    def get_sitemap(url):
        """Fetch sitemap.xml"""
        try:
            parsed = urlparse(url)
            sitemap_urls = [
                f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
                f"{parsed.scheme}://{parsed.netloc}/sitemap_index.xml",
                f"{parsed.scheme}://{parsed.netloc}/sitemap1.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                resp = requests.get(sitemap_url, timeout=5)
                if resp.status_code == 200:
                    return resp.text
        except:
            pass
        return None
    
    @staticmethod
    def detect_waf_simple(url):
        """Simple WAF detection"""
        waf_indicators = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'Akamai': ['akamai', 'ak-'],
            'Incapsula': ['incapsula', '_incap_'],
            'ModSecurity': ['mod_security'],
            'Sucuri': ['sucuri', 'x-sucuri']
        }
        
        try:
            resp = requests.get(url, timeout=5)
            headers_str = str(resp.headers).lower()
            body_str = resp.text.lower()
            
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in headers_str or indicator in body_str:
                        return waf_name
        except:
            pass
        
        return None
    
    @staticmethod
    def get_server_banner(ip, port=80):
        """Get server banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except:
            return None
