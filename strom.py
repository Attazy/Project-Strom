#!/usr/bin/env python3
import sys
import time
from termcolor import colored
from utils.logger import setup_logger
from art import STROM_BANNER

logger = setup_logger('strom')

def print_banner():
    """Print STROM banner"""
    print(colored(STROM_BANNER, 'red', attrs=['bold']))
    print(colored("⚡ Advanced Penetration Testing Framework", 'yellow'))
    print(colored("⚡ https://github.com/Attazy\n", 'yellow'))

def show_menu():
    """Display main menu"""
    print(colored("="*60, 'white'))
    print(colored("  MAIN MENU", 'green', attrs=['bold']))
    print(colored("[1] ", 'green') + colored("Reconnaissance", 'white'))
    print(colored("[2] ", 'green') + colored("Web Scanner", 'white'))
    print(colored("[3] ", 'green') + colored("Exploitation Engine", 'white'))
    print(colored("[4] ", 'green') + colored("Bypass", 'white'))
    print(colored("[5] ", 'green') + colored("Post Exploitation", 'white'))
    print(colored("[6] ", 'green') + colored("Utilities", 'white'))
    print(colored("[7] ", 'green') + colored("Reporting", 'white'))
    print(colored("[8] ", 'green') + colored("Payload Generator", 'white'))
    print(colored("[9] ", 'green') + colored("Android Remote Access", 'white'))  # NEW
    print(colored("[0] ", 'red') + colored("Exit", 'white'))
    print(colored("="*60, 'white'))

def main():
    """Main function"""
    try:
        print_banner()
        
        while True:
            show_menu()
            choice = input(colored("\nSTROM> ", 'white', attrs=['bold']) + colored("Select module: ", 'cyan'))
            
            if choice == '1':
                print(colored("\n[*] Loading Reconnaissance...", 'yellow'))
                time.sleep(0.3)
                from modules.recon import AdvancedRecon
                recon = AdvancedRecon()
                recon.run()
                
            elif choice == '2':
                print(colored("\n[*] Loading Web Scanner...", 'yellow'))
                time.sleep(0.3)
                from modules.web_scanner import WebScanner
                scanner = WebScanner()
                scanner.run()
                
            elif choice == '3':
                print(colored("\n[*] Loading Exploitation Engine...", 'yellow'))
                time.sleep(0.3)
                from modules.exploiter import AdvancedExploiter
                exploiter = AdvancedExploiter()
                exploiter.run()
                
            elif choice == '4':
                print(colored("\n[*] Loading Bypass Module...", 'yellow'))
                time.sleep(0.3)
                from modules.bypass import WAFBypass
                bypass_module = WAFBypass()
                bypass_module.run()
            
            elif choice == '5':
                print(colored("\n[*] Loading Post Exploitation...", 'yellow'))
                time.sleep(0.3)
                from modules.post_exploit import PostExploitation
                post_exploit = PostExploitation()
                post_exploit.run()
            
            elif choice == '6':
                print(colored("\n[*] Loading Utilities...", 'yellow'))
                time.sleep(0.3)
                from modules.utilities import Utilities
                utils = Utilities()
                utils.run()
            
            elif choice == '7':
                print(colored("\n[*] Loading Reporting...", 'yellow'))
                time.sleep(0.3)
                from modules.reporting import UnifiedReporting
                reporting = UnifiedReporting()
                reporting.run()
                
            elif choice == '8':
                print(colored("\n[*] Loading Payload Generator...", 'yellow'))
                time.sleep(0.3)
                from core.payloads import PayloadGenerator
                generator = PayloadGenerator()
                
                print(colored("\n  Select payload type:", 'cyan'))
                print(colored("  [1] SQL Injection", 'white'))
                print(colored("  [2] RCE/Command Injection", 'white'))
                print(colored("  [3] XSS", 'white'))
                print(colored("  [4] LFI", 'white'))
                print(colored("  [5] XXE", 'white'))
                print(colored("  [6] SSRF", 'white'))
                
                ptype = input(colored("\n  Select [1-6]: ", 'cyan'))
                
                payload_map = {
                    '1': ('SQL Injection', generator.generate_sqli_payloads()),
                    '2': ('RCE', generator.generate_rce_payloads()),
                    '3': ('XSS', generator.generate_xss_payloads()),
                    '4': ('LFI', generator.generate_lfi_payloads()),
                    '5': ('XXE', generator.generate_xxe_payloads()),
                    '6': ('SSRF', generator.generate_ssrf_payloads())
                }
                
                if ptype in payload_map:
                    name, payloads = payload_map[ptype]
                    print(colored(f"\n[+] Generated {len(payloads)} {name} payloads", 'green'))
                    
                    for i, payload in enumerate(payloads[:15], 1):
                        print(colored(f"  [{i:2d}] {payload[:65]}", 'white'))
                    
                    if len(payloads) > 15:
                        print(colored(f"\n  ... {len(payloads) - 15} more payloads", 'yellow'))
                    
                    save = input(colored("\n  Save to file? (y/N): ", 'cyan')).lower()
                    if save == 'y':
                        filename = f"payloads_{int(time.time())}.txt"
                        with open(filename, 'w') as f:
                            for payload in payloads:
                                f.write(payload + '\n')
                        print(colored(f"  [+] Saved: {filename}", 'green'))
                
            elif choice == '9':
                print(colored("\n[*] Loading Android Remote Access...", 'yellow'))
                time.sleep(0.3)
                from modules.android_access import AndroidRemoteAccess
                android = AndroidRemoteAccess()
                android.run()
            
            elif choice == '0':
                print(colored("\n[*] Exiting STROM Framework...", 'yellow'))
                print(colored("[!] Happy Hacking!\n", 'green'))
                sys.exit(0)
                
            else:
                print(colored("\n[!] Invalid option", 'red'))
            
            input(colored("\nPress Enter to continue...", 'yellow'))
                
    except KeyboardInterrupt:
        print(colored("\n\n[!] Interrupted", 'red'))
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        print(colored(f"\n[!] Error: {str(e)}", 'red'))
        sys.exit(1)

if __name__ == "__main__":
    main()
