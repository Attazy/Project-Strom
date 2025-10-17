#!/usr/bin/env python3
import sqlite3
import json
from datetime import datetime
from pathlib import Path

class Database:
    """Database handler for STROM framework"""
    
    def __init__(self, db_path='./data/strom.db'):
        self.db_path = db_path
        # Create data directory if not exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT,
                payload TEXT,
                description TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                first_scan TEXT,
                last_scan TEXT,
                total_scans INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_scan(self, target, scan_type, results=None):
        """Add new scan record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        results_json = json.dumps(results) if results else None
        
        cursor.execute('''
            INSERT INTO scans (target, scan_type, timestamp, status, results)
            VALUES (?, ?, ?, ?, ?)
        ''', (target, scan_type, timestamp, 'completed', results_json))
        
        scan_id = cursor.lastrowid
        
        # Update targets table
        cursor.execute('''
            INSERT OR REPLACE INTO targets (target, first_scan, last_scan, total_scans)
            VALUES (?, ?, ?, COALESCE((SELECT total_scans FROM targets WHERE target=?), 0) + 1)
        ''', (target, timestamp, timestamp, target))
        
        conn.commit()
        conn.close()
        
        return scan_id
    
    def add_vulnerability(self, scan_id, vuln_type, severity, url=None, payload=None, description=None):
        """Add vulnerability record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, payload, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, vuln_type, severity, url, payload, description, timestamp))
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self, target=None, limit=10):
        """Get scan history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if target:
            cursor.execute('''
                SELECT * FROM scans WHERE target=? ORDER BY timestamp DESC LIMIT ?
            ''', (target, limit))
        else:
            cursor.execute('''
                SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        scans = cursor.fetchall()
        conn.close()
        
        return scans
    
    def get_vulnerabilities(self, scan_id=None, severity=None):
        """Get vulnerabilities"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if scan_id:
            if severity:
                cursor.execute('''
                    SELECT * FROM vulnerabilities WHERE scan_id=? AND severity=?
                ''', (scan_id, severity))
            else:
                cursor.execute('''
                    SELECT * FROM vulnerabilities WHERE scan_id=?
                ''', (scan_id,))
        else:
            cursor.execute('SELECT * FROM vulnerabilities')
        
        vulns = cursor.fetchall()
        conn.close()
        
        return vulns
    
    def get_target_stats(self, target):
        """Get statistics for a target"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM targets WHERE target=?
        ''', (target,))
        
        stats = cursor.fetchone()
        conn.close()
        
        return stats
    
    def close(self):
        """Close database connection"""
        pass

# Global database instance
db = Database()
