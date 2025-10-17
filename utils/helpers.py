# utils/helpers.py
import random
import string

def generate_random_ip():
    """Generate random IPv4 address"""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def obfuscate_payload(payload):
    """Advanced payload obfuscation with multiple techniques"""
    techniques = [
        lambda x: x.replace(' ', '/**/'),
        lambda x: x.replace('AND', 'AND/*random*/'),
        lambda x: x.lower() if random.choice([True, False]) else x.upper(),
        lambda x: x.replace('SELECT', 'SEL' + ''.join(['%{:02x}'.format(ord(c)) for c in 'ECT']))
    ]
    for technique in techniques:
        payload = technique(payload)
    return payload

def generate_random_useragent():
    """Generate random user agent with comprehensive options"""
    user_agents = [
        # Desktop browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
        
        # Mobile browsers
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
        
        # Search engine bots
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        
        # Custom framework
        "STROM-Framework/1.0 (+https://github.com/yourusername/strom)"
    ]
    return random.choice(user_agents)
