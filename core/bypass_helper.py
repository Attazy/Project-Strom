#!/usr/bin/env python3
import random
import urllib.parse
import base64

class BypassHelper:
    """Helper functions library for WAF/IDS/IPS bypass techniques"""
    
    @staticmethod
    def case_switching(payload):
        """Randomly switch case of characters"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in payload
        )
    
    @staticmethod
    def comment_insertion_sql(payload):
        """Insert SQL comments to bypass filters"""
        payload = payload.replace(' ', '/**/').replace('SELECT', 'SEL/**/ECT')
        payload = payload.replace('UNION', 'UNI/**/ON').replace('FROM', 'FR/**/OM')
        payload = payload.replace('WHERE', 'WH/**/ERE').replace('AND', '/**/AND/**/')
        return payload
    
    @staticmethod
    def whitespace_manipulation(payload):
        """Replace spaces with alternative whitespace characters"""
        whitespace_chars = ['%09', '%0a', '%0b', '%0c', '%0d', '/**/', '+']
        replacement = random.choice(whitespace_chars)
        return payload.replace(' ', replacement)
    
    @staticmethod
    def url_encode(payload):
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload):
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def unicode_encode(payload):
        """Unicode encode payload"""
        encoded = ''
        for char in payload:
            if random.random() > 0.5:
                encoded += f'\\u{ord(char):04x}'
            else:
                encoded += char
        return encoded
    
    @staticmethod
    def hex_encode(payload):
        """Hex encode payload"""
        encoded = ''
        for char in payload:
            if random.random() > 0.5:
                encoded += f'\\x{ord(char):02x}'
            else:
                encoded += char
        return encoded
    
    @staticmethod
    def mixed_encoding(payload):
        """Mix different encoding types"""
        encoded = ''
        for i, char in enumerate(payload):
            if i % 3 == 0:
                encoded += urllib.parse.quote(char)
            elif i % 3 == 1:
                encoded += f'\\x{ord(char):02x}'
            else:
                encoded += char
        return encoded
    
    @staticmethod
    def null_byte_injection(payload):
        """Add null bytes to bypass length checks"""
        return payload + '%00'
    
    @staticmethod
    def newline_injection(payload):
        """Inject newlines to bypass single-line filters"""
        return payload.replace(';', '%0a;').replace('|', '%0a|')
    
    @staticmethod
    def concatenation_bypass(payload):
        """Break up keywords using concatenation"""
        if "'" in payload:
            payload = payload.replace("'", "'++'")
        return payload
    
    @staticmethod
    def crlf_injection(payload):
        """Use CRLF injection to bypass filters"""
        return payload.replace(' ', '%0d%0a')
    
    @staticmethod
    def tab_replacement(payload):
        """Replace spaces with tabs"""
        return payload.replace(' ', '%09')
