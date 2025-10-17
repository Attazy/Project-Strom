#!/usr/bin/env python3
"""Test if all required dependencies are installed"""

def test_dependencies():
    print("Testing STROM dependencies...\n")
    
    required = {
        'requests': 'HTTP requests',
        'termcolor': 'Colored output',
        'colorama': 'Windows color support',
        'yaml': 'YAML parser (pyyaml)',
        'art': 'ASCII art',
        'dns.resolver': 'DNS queries (dnspython)',
        'whois': 'WHOIS lookup (python-whois)',
        'netifaces': 'Network interfaces',
        'OpenSSL': 'SSL/TLS (pyOpenSSL)',
        'bs4': 'HTML parser (beautifulsoup4)',
        'lxml': 'XML parser',
        'Crypto': 'Cryptography (pycryptodome)',
        'PIL': 'Image processing (Pillow)',
    }
    
    optional = {
        'pynput': 'Keylogger',
        'reportlab': 'PDF reports',
        'scapy': 'Network scanning',
        'paramiko': 'SSH operations',
        'shodan': 'Shodan API',
        'censys': 'Censys API',
    }
    
    passed = 0
    failed = 0
    
    print("="*60)
    print("REQUIRED PACKAGES:")
    print("="*60)
    
    for module, description in required.items():
        try:
            __import__(module)
            print(f"✓ {module:20s} - {description}")
            passed += 1
        except ImportError:
            print(f"✗ {module:20s} - {description} (MISSING!)")
            failed += 1
    
    print("\n" + "="*60)
    print("OPTIONAL PACKAGES:")
    print("="*60)
    
    for module, description in optional.items():
        try:
            __import__(module)
            print(f"✓ {module:20s} - {description}")
        except ImportError:
            print(f"○ {module:20s} - {description} (optional)")
    
    print("\n" + "="*60)
    print(f"RESULT: {passed} passed, {failed} failed")
    print("="*60)
    
    if failed > 0:
        print("\n⚠️  Install missing packages with:")
        print("pip install -r requirements.txt")
        return False
    else:
        print("\n✓ All required dependencies are installed!")
        print("✓ STROM is ready to use!")
        return True

if __name__ == "__main__":
    import sys
    success = test_dependencies()
    sys.exit(0 if success else 1)
