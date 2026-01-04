#!/usr/bin/env python3
import base64
import hashlib
import urllib.parse
import binascii
import socket
import requests
from termcolor import colored
from utils.logger import setup_logger

logger = setup_logger('utilities')

class Utilities:
    """Utility Tools Module"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def run(self):
        """Run interactive utilities module"""
        try:
            print(colored("\n╔══════════════════════════════════════════════════════════╗", 'blue'))
            print(colored("║           STROM Utilities Module v2.0                    ║", 'blue', attrs=['bold']))
            print(colored("╚══════════════════════════════════════════════════════════╝", 'blue'))
            
            while True:
                self.show_menu()
                
        except KeyboardInterrupt:
            print(colored("\n[!] Utilities module interrupted", 'red'))
    
    def show_menu(self):
        """Show utilities menu"""
        print(colored("\n" + "="*60, 'blue'))
        print(colored("              UTILITIES MENU", 'white', attrs=['bold']))
        print(colored("="*60, 'blue'))
        print(colored("\n  [1]     Encoder/Decoder", 'cyan'))
        print(colored("  [2]     hash Calculator", 'cyan'))
        print(colored("  [3]     Hash Cracker", 'yellow'))
        print(colored("  [4]     Password Generator", 'green'))
        print(colored("  [5]     Reverse IP Lookup", 'cyan'))
        print(colored("  [6]     Port Scanner", 'yellow'))
        print(colored("  [7]     Banner Grabber", 'cyan'))
        print(colored("  [8]     String Manipulator", 'green'))
        print(colored("  [0]     Exit", 'red'))
        print(colored("="*60, 'blue'))
        
        choice = input(colored("\n[?] Select option: ", 'blue'))
        
        if choice == '1':
            self.encoder_decoder()
        elif choice == '2':
            self.hash_calculator()
        elif choice == '3':
            self.hash_cracker()
        elif choice == '4':
            self.password_generator()
        elif choice == '5':
            self.reverse_ip()
        elif choice == '6':
            self.port_scanner()
        elif choice == '7':
            self.banner_grabber()
        elif choice == '8':
            self.string_manipulator()
        elif choice == '0':
            print(colored("[*] Exiting utilities module...", 'yellow'))
            return
    
    def encoder_decoder(self):
        """Encoder/Decoder tool"""
        print(colored("\n[+] Encoder/Decoder", 'cyan', attrs=['bold']))
        print(colored("="*60, 'cyan'))
        
        print(colored("\n  [1] Encode", 'white'))
        print(colored("  [2] Decode", 'white'))
        
        mode = input(colored("\n[?] Select mode (1-2): ", 'blue'))
        
        if mode not in ['1', '2']:
            return
        
        print(colored("\n  Available formats:", 'yellow'))
        print(colored("    [1] Base64", 'white'))
        print(colored("    [2] URL Encoding", 'white'))
        print(colored("    [3] Hex", 'white'))
        print(colored("    [4] HTML Entities", 'white'))
        print(colored("    [5] Unicode", 'white'))
        
        format_choice = input(colored("\n[?] Select format (1-5): ", 'blue'))
        
        data = input(colored("[+] Enter data: ", 'blue'))
        
        if mode == '1':  # Encode
            if format_choice == '1':
                result = base64.b64encode(data.encode()).decode()
            elif format_choice == '2':
                result = urllib.parse.quote(data)
            elif format_choice == '3':
                result = data.encode().hex()
            elif format_choice == '4':
                result = ''.join(f'&#{ord(c)};' for c in data)
            elif format_choice == '5':
                result = ''.join(f'\\u{ord(c):04x}' for c in data)
            else:
                return
            
            print(colored(f"\n[+] Encoded: {result}", 'green'))
            
        else:  # Decode
            try:
                if format_choice == '1':
                    result = base64.b64decode(data).decode()
                elif format_choice == '2':
                    result = urllib.parse.unquote(data)
                elif format_choice == '3':
                    result = bytes.fromhex(data).decode()
                elif format_choice == '4':
                    import html
                    result = html.unescape(data)
                elif format_choice == '5':
                    result = data.encode().decode('unicode-escape')
                else:
                    return
                
                print(colored(f"\n[+] Decoded: {result}", 'green'))
            except Exception as e:
                print(colored(f"[!] Decoding failed: {e}", 'red'))
    
    def hash_calculator(self):
        """Hash calculator"""
        print(colored("\n[+] Hash Calculator", 'cyan', attrs=['bold']))
        print(colored("="*60, 'cyan'))
        
        data = input(colored("\n[+] Enter data to hash: ", 'blue'))
        
        hashes = {
            'MD5': hashlib.md5(data.encode()).hexdigest(),
            'SHA1': hashlib.sha1(data.encode()).hexdigest(),
            'SHA256': hashlib.sha256(data.encode()).hexdigest(),
            'SHA512': hashlib.sha512(data.encode()).hexdigest(),
        }
        
        print(colored("\n[+] Hash Results:", 'green'))
        for algo, hash_value in hashes.items():
            print(colored(f"  {algo:10s}: {hash_value}", 'white'))
    
    def hash_cracker(self):
        """Simple hash cracker"""
        print(colored("\n[+] Hash Cracker", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        print(colored("[!] Note: This is a simple dictionary-based cracker", 'yellow'))
        
        hash_input = input(colored("\n[+] Enter hash: ", 'blue'))
        
        print(colored("\n  [1] MD5", 'white'))
        print(colored("  [2] SHA1", 'white'))
        print(colored("  [3] SHA256", 'white'))
        
        hash_type = input(colored("\n[?] Hash type (1-3): ", 'blue'))
        
        wordlist_path = input(colored("[+] Wordlist path (press Enter for common passwords): ", 'blue'))
        
        if not wordlist_path:
            # Use common passwords
            wordlist = ['password', '123456', '12345678', 'qwerty', 'abc123', 
                       'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
                       'baseball', '111111', 'iloveyou', 'master', 'sunshine',
                       'ashley', 'bailey', 'passw0rd', 'shadow', '123123']
        else:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f]
            except Exception as e:
                print(colored(f"[!] Failed to load wordlist: {e}", 'red'))
                return
        
        print(colored(f"\n[*] Testing {len(wordlist)} passwords...", 'cyan'))
        
        algo_map = {'1': hashlib.md5, '2': hashlib.sha1, '3': hashlib.sha256}
        hash_func = algo_map.get(hash_type)
        
        if not hash_func:
            return
        
        for i, password in enumerate(wordlist):
            hash_value = hash_func(password.encode()).hexdigest()
            
            if hash_value == hash_input:
                print(colored(f"\n[+] CRACKED! Password: {password}", 'green', attrs=['bold']))
                return
            
            if i % 100 == 0:
                print(f"\r[*] Tested: {i}/{len(wordlist)}", end='', flush=True)
        
        print(colored(f"\n[-] Password not found in wordlist", 'red'))
    
    def password_generator(self):
        """Password generator"""
        print(colored("\n[+] Password Generator", 'green', attrs=['bold']))
        print(colored("="*60, 'green'))
        
        length = int(input(colored("\n[+] Password length (default: 16): ", 'blue')) or "16")
        count = int(input(colored("[+] Number of passwords (default: 5): ", 'blue')) or "5")
        
        print(colored("\n  Character sets:", 'yellow'))
        include_upper = input(colored("    Include uppercase (Y/n): ", 'blue')).lower() != 'n'
        include_lower = input(colored("    Include lowercase (Y/n): ", 'blue')).lower() != 'n'
        include_digits = input(colored("    Include digits (Y/n): ", 'blue')).lower() != 'n'
        include_special = input(colored("    Include special chars (Y/n): ", 'blue')).lower() != 'n'
        
        import string
        import random
        
        charset = ''
        if include_upper:
            charset += string.ascii_uppercase
        if include_lower:
            charset += string.ascii_lowercase
        if include_digits:
            charset += string.digits
        if include_special:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not charset:
            print(colored("[!] No character set selected", 'red'))
            return
        
        print(colored("\n[+] Generated Passwords:", 'green'))
        for _ in range(count):
            password = ''.join(random.choice(charset) for _ in range(length))
            print(colored(f"  {password}", 'white'))
    
    def reverse_ip(self):
        """Reverse IP lookup"""
        print(colored("\n[+] Reverse IP Lookup", 'cyan', attrs=['bold']))
        print(colored("="*60, 'cyan'))
        
        ip = input(colored("\n[+] Enter IP address: ", 'blue'))
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(colored(f"[+] Hostname: {hostname}", 'green'))
        except socket.herror:
            print(colored("[-] No PTR record found", 'red'))
        except Exception as e:
            print(colored(f"[!] Error: {e}", 'red'))
    
    def port_scanner(self):
        """Simple port scanner"""
        print(colored("\n[+] Port Scanner", 'yellow', attrs=['bold']))
        print(colored("="*60, 'yellow'))
        
        target = input(colored("\n[+] Target IP/hostname: ", 'blue'))
        
        print(colored("\n  [1] Quick Scan (Common ports)", 'white'))
        print(colored("  [2] Custom Port Range", 'white'))
        
        scan_type = input(colored("\n[?] Select scan type (1-2): ", 'blue'))
        
        if scan_type == '1':
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
        else:
            start = int(input(colored("[+] Start port: ", 'blue')))
            end = int(input(colored("[+] End port: ", 'blue')))
            ports = range(start, end + 1)
        
        print(colored(f"\n[*] Scanning {len(list(ports))} ports on {target}...", 'cyan'))
        
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                print(colored(f"[+] Port {port:5d} OPEN  ({service})", 'green'))
            
            sock.close()
            
            if len(list(ports)) > 100 and port % 10 == 0:
                print(f"\r[*] Progress: {port}/{max(ports)}", end='', flush=True)
        
        print(colored(f"\n\n[+] Scan complete. Found {len(open_ports)} open ports", 'green'))
    
    def banner_grabber(self):
        """Banner grabber"""
        print(colored("\n[+] Banner Grabber", 'cyan', attrs=['bold']))
        print(colored("="*60, 'cyan'))
        
        target = input(colored("\n[+] Target IP/hostname: ", 'blue'))
        port = int(input(colored("[+] Port: ", 'blue')))
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send HTTP request for common web ports
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443]:
                print(colored("[!] SSL port detected. Use openssl s_client for HTTPS", 'yellow'))
                return
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            print(colored("\n[+] Banner:", 'green'))
            print(colored(banner, 'white'))
            
        except Exception as e:
            print(colored(f"[!] Banner grab failed: {e}", 'red'))
    
    def string_manipulator(self):
        """String manipulation tool"""
        print(colored("\n[+] String Manipulator", 'green', attrs=['bold']))
        print(colored("="*60, 'green'))
        
        text = input(colored("\n[+] Enter text: ", 'blue'))
        
        print(colored("\n  Transformations:", 'yellow'))
        print(colored(f"    Uppercase: {text.upper()}", 'white'))
        print(colored(f"    Lowercase: {text.lower()}", 'white'))
        print(colored(f"    Capitalize: {text.capitalize()}", 'white'))
        print(colored(f"    Title Case: {text.title()}", 'white'))
        print(colored(f"    Reverse: {text[::-1]}", 'white'))
        print(colored(f"    Length: {len(text)}", 'white'))
        print(colored(f"    Word Count: {len(text.split())}", 'white'))

if __name__ == "__main__":
    utils = Utilities()
    utils.run()
