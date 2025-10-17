#!/usr/bin/env python3
from datetime import datetime
import json

class ReportHelper:
    """Helper functions for report generation"""
    
    @staticmethod
    def calculate_risk_score(vulnerabilities):
        """Calculate overall risk score"""
        severity_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            total_score += severity_scores.get(severity, 0)
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10
        if max_possible > 0:
            return min(100, int((total_score / max_possible) * 100))
        return 0
    
    @staticmethod
    def generate_executive_summary(data):
        """Generate executive summary"""
        total_vulns = len(data.get('vulnerabilities', []))
        critical = sum(1 for v in data.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in data.get('vulnerabilities', []) if v.get('severity') == 'HIGH')
        
        summary = f"""
During the security assessment of {data.get('target', 'the target system')}, 
{total_vulns} vulnerabilities were identified, including {critical} critical 
and {high} high severity issues that require immediate attention.
"""
        return summary.strip()
    
    @staticmethod
    def group_by_severity(vulnerabilities):
        """Group vulnerabilities by severity"""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            grouped[severity].append(vuln)
        
        return grouped
    
    @staticmethod
    def format_timestamp(iso_timestamp):
        """Format ISO timestamp to readable format"""
        try:
            dt = datetime.fromisoformat(iso_timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return iso_timestamp
