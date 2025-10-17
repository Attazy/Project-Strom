#!/usr/bin/env python3
import re
from urllib.parse import urlparse, urljoin
import requests

class ScannerHelper:
    """Helper functions for web scanning"""
    
    @staticmethod
    def extract_urls(html, base_url):
        """Extract URLs from HTML"""
        urls = set()
        
        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, html, re.IGNORECASE)
        
        # Find all src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        srcs = re.findall(src_pattern, html, re.IGNORECASE)
        
        all_links = hrefs + srcs
        
        for link in all_links:
            if link.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            
            absolute_url = urljoin(base_url, link)
            
            if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                urls.add(absolute_url)
        
        return list(urls)
    
    @staticmethod
    def detect_cms(html, headers):
        """Detect CMS from HTML and headers"""
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
            'Joomla': [r'/components/com_', r'Joomla!'],
            'Drupal': [r'Drupal', r'/sites/default/'],
            'Magento': [r'Magento', r'/skin/frontend/'],
            'Shopify': [r'cdn.shopify.com'],
            'PrestaShop': [r'prestashop'],
            'OpenCart': [r'catalog/view/theme']
        }
        
        detected = []
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if cms not in detected:
                        detected.append(cms)
                    break
        
        return detected
    
    @staticmethod
    def check_security_headers(headers):
        """Check for security headers"""
        security_headers = {
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False
        }
        
        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = True
        
        return security_headers
    
    @staticmethod
    def extract_forms(html, base_url):
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for form_html in form_matches:
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            forms.append({
                'action': urljoin(base_url, action),
                'method': method,
                'inputs': inputs
            })
        
        return forms
