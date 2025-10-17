#!/usr/bin/env python3
import json
import os
from datetime import datetime
from termcolor import colored
from core.report_helper import ReportHelper
from utils.logger import setup_logger

logger = setup_logger('reporting')

class UnifiedReporting:
    """Unified Reporting Module for all STROM modules"""
    
    def __init__(self):
        self.helper = ReportHelper()
        self.reports_dir = "./reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def run(self):
        """Run interactive reporting module"""
        try:
            print(colored("\n╔══════════════════════════════════════════════════════════╗", 'green'))
            print(colored("║        STROM Unified Reporting Module v2.0               ║", 'green', attrs=['bold']))
            print(colored("╚══════════════════════════════════════════════════════════╝", 'green'))
            
            print(colored("\n[*] Report Generation Options:", 'cyan'))
            print(colored("  [1] Generate from JSON file", 'white'))
            print(colored("  [2] View existing reports", 'white'))
            print(colored("  [3] Combine multiple reports", 'white'))
            
            choice = input(colored("\n[?] Select option (1-3): ", 'blue'))
            
            if choice == '1':
                self.generate_from_json()
            elif choice == '2':
                self.view_reports()
            elif choice == '3':
                self.combine_reports()
                
        except KeyboardInterrupt:
            print(colored("\n[!] Reporting interrupted", 'red'))
        except Exception as e:
            logger.error(f"Reporting error: {str(e)}")
            print(colored(f"[!] Error: {str(e)}", 'red'))
    
    def generate_from_json(self):
        """Generate report from JSON file"""
        print(colored("\n[+] Generate Report from JSON", 'cyan'))
        
        json_file = input(colored("[+] JSON file path: ", 'blue'))
        
        if not os.path.exists(json_file):
            print(colored("[!] File not found", 'red'))
            return
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            print(colored("\n[*] Select report format:", 'yellow'))
            print(colored("  [1] HTML", 'white'))
            print(colored("  [2] PDF (requires reportlab)", 'white'))
            print(colored("  [3] Markdown", 'white'))
            print(colored("  [4] All formats", 'white'))
            
            format_choice = input(colored("\n[?] Select format (1-4): ", 'blue'))
            
            if format_choice in ['1', '4']:
                self.generate_html_report(data)
            if format_choice in ['2', '4']:
                self.generate_pdf_report(data)
            if format_choice in ['3', '4']:
                self.generate_markdown_report(data)
                
        except Exception as e:
            print(colored(f"[!] Report generation failed: {e}", 'red'))
    
    def generate_html_report(self, data):
        """Generate HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.reports_dir, f"report_{timestamp}.html")
        
        vulnerabilities = data.get('vulnerabilities', [])
        grouped_vulns = self.helper.group_by_severity(vulnerabilities)
        risk_score = self.helper.calculate_risk_score(vulnerabilities)
        executive_summary = self.helper.generate_executive_summary(data)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <meta charset="UTF-8">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; margin: -40px -40px 40px -40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #667eea; border-bottom: 3px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        
        .info-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }}
        .info-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .info-box label {{ font-weight: bold; color: #667eea; display: block; margin-bottom: 5px; }}
        
        .risk-score {{ text-align: center; padding: 30px; background: #f8f9fa; border-radius: 10px; margin: 20px 0; }}
        .risk-score .score {{ font-size: 4em; font-weight: bold; margin: 10px 0; }}
        .risk-critical {{ color: #dc3545; }}
        .risk-high {{ color: #fd7e14; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
        
        .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h3 {{ font-size: 2.5em; margin: 10px 0; }}
        .card.critical {{ background: #fff5f5; border-top: 4px solid #dc3545; }}
        .card.high {{ background: #fff8ed; border-top: 4px solid #fd7e14; }}
        .card.medium {{ background: #fffbea; border-top: 4px solid #ffc107; }}
        .card.low {{ background: #f0f9f0; border-top: 4px solid #28a745; }}
        
        .vulnerability {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #999; }}
        .vulnerability h3 {{ margin-bottom: 15px; }}
        .vulnerability .severity {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em; }}
        .severity.critical {{ background: #dc3545; }}
        .severity.high {{ background: #fd7e14; }}
        .severity.medium {{ background: #ffc107; color: #333; }}
        .severity.low {{ background: #28a745; }}
        
        .vuln-detail {{ margin: 10px 0; }}
        .vuln-detail strong {{ color: #667eea; }}
        code {{ background: #e9ecef; padding: 3px 8px; border-radius: 4px; font-family: 'Courier New', monospace; }}
        
        .executive-summary {{ background: #e3f2fd; padding: 25px; border-left: 5px solid #2196f3; border-radius: 5px; margin: 20px 0; }}
        
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 2px solid #dee2e6; text-align: center; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <p>Generated by STROM Framework</p>
            <p>{datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>Test Information</h2>
            <div class="info-grid">
                <div class="info-box">
                    <label>Target</label>
                    {data.get('target', 'N/A')}
                </div>
                <div class="info-box">
                    <label>Tester</label>
                    {data.get('tester', 'N/A')}
                </div>
                <div class="info-box">
                    <label>Authorization Code</label>
                    {data.get('authorization_code', 'N/A')}
                </div>
                <div class="info-box">
                    <label>Session ID</label>
                    {data.get('session_id', 'N/A')}
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="risk-score">
                <div>Overall Risk Score</div>
                <div class="score {'risk-critical' if risk_score >= 75 else 'risk-high' if risk_score >= 50 else 'risk-medium' if risk_score >= 25 else 'risk-low'}">
                    {risk_score}/100
                </div>
                <div>{'CRITICAL' if risk_score >= 75 else 'HIGH' if risk_score >= 50 else 'MEDIUM' if risk_score >= 25 else 'LOW'} RISK</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="executive-summary">
                {executive_summary}
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Summary</h2>
            <div class="summary-cards">
                <div class="card critical">
                    <h3>{len(grouped_vulns['CRITICAL'])}</h3>
                    <p>Critical</p>
                </div>
                <div class="card high">
                    <h3>{len(grouped_vulns['HIGH'])}</h3>
                    <p>High</p>
                </div>
                <div class="card medium">
                    <h3>{len(grouped_vulns['MEDIUM'])}</h3>
                    <p>Medium</p>
                </div>
                <div class="card low">
                    <h3>{len(grouped_vulns['LOW'])}</h3>
                    <p>Low</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
"""
        
        # Add vulnerabilities
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = grouped_vulns[severity]
            if vulns:
                html += f"<h3>{severity} Severity</h3>"
                for i, vuln in enumerate(vulns, 1):
                    html += f"""
            <div class="vulnerability">
                <h3>Finding #{i}: {vuln.get('type', 'Unknown')} <span class="severity {severity.lower()}">{severity}</span></h3>
                <div class="vuln-detail"><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></div>
                <div class="vuln-detail"><strong>Technique:</strong> {vuln.get('technique', vuln.get('method', 'N/A'))}</div>
"""
                    if 'payload' in vuln:
                        html += f"<div class='vuln-detail'><strong>Payload:</strong> <code>{vuln['payload'][:100]}...</code></div>"
                    html += "</div>"
        
        html += """
        </div>
        
        <div class="footer">
            <p>This report was generated by STROM Framework v2.0</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(colored(f"[+] HTML report generated: {filename}", 'green'))
    
    def generate_markdown_report(self, data):
        """Generate Markdown report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.reports_dir, f"report_{timestamp}.md")
        
        vulnerabilities = data.get('vulnerabilities', [])
        grouped_vulns = self.helper.group_by_severity(vulnerabilities)
        
        md = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target:** {data.get('target', 'N/A')}  
**Tester:** {data.get('tester', 'N/A')}  

## Executive Summary

{self.helper.generate_executive_summary(data)}

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {len(grouped_vulns['CRITICAL'])} |
| High     | {len(grouped_vulns['HIGH'])} |
| Medium   | {len(grouped_vulns['MEDIUM'])} |
| Low      | {len(grouped_vulns['LOW'])} |

## Detailed Findings

"""
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = grouped_vulns[severity]
            if vulns:
                md += f"\n### {severity} Severity\n\n"
                for i, vuln in enumerate(vulns, 1):
                    md += f"#### Finding #{i}: {vuln.get('type', 'Unknown')}\n\n"
                    md += f"- **URL:** `{vuln.get('url', 'N/A')}`\n"
                    md += f"- **Technique:** {vuln.get('technique', vuln.get('method', 'N/A'))}\n"
                    if 'payload' in vuln:
                        md += f"- **Payload:** `{vuln['payload'][:100]}...`\n"
                    md += "\n"
        
        md += "\n---\n*Report generated by STROM Framework v2.0*\n"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md)
        
        print(colored(f"[+] Markdown report generated: {filename}", 'green'))
    
    def generate_pdf_report(self, data):
        """Generate PDF report (requires reportlab)"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.reports_dir, f"report_{timestamp}.pdf")
            
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            story.append(Paragraph("Security Assessment Report", styles['Title']))
            story.append(Spacer(1, 12))
            
            # Basic info
            story.append(Paragraph(f"<b>Target:</b> {data.get('target', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            doc.build(story)
            print(colored(f"[+] PDF report generated: {filename}", 'green'))
            
        except ImportError:
            print(colored("[!] reportlab not installed. Install with: pip install reportlab", 'yellow'))
    
    def view_reports(self):
        """View existing reports"""
        reports = [f for f in os.listdir(self.reports_dir) if f.endswith(('.html', '.pdf', '.md'))]
        
        if not reports:
            print(colored("[-] No reports found", 'yellow'))
            return
        
        print(colored(f"\n[+] Found {len(reports)} reports:", 'green'))
        for i, report in enumerate(reports, 1):
            print(colored(f"  {i}. {report}", 'white'))
    
    def combine_reports(self):
        """Combine multiple JSON reports"""
        print(colored("\n[+] Combine Multiple Reports", 'cyan'))
        print(colored("[*] Enter JSON file paths (one per line, empty line to finish):", 'yellow'))
        
        files = []
        while True:
            file_path = input(colored("File: ", 'blue'))
            if not file_path:
                break
            if os.path.exists(file_path):
                files.append(file_path)
            else:
                print(colored("[!] File not found, skipping", 'red'))
        
        if len(files) < 2:
            print(colored("[!] Need at least 2 files to combine", 'red'))
            return
        
        combined_data = {
            'target': 'Multiple Targets',
            'tester': 'Combined Report',
            'vulnerabilities': []
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    combined_data['vulnerabilities'].extend(data.get('vulnerabilities', []))
            except Exception as e:
                print(colored(f"[!] Failed to load {file_path}: {e}", 'red'))
        
        print(colored(f"\n[+] Combined {len(combined_data['vulnerabilities'])} vulnerabilities", 'green'))
        self.generate_html_report(combined_data)

if __name__ == "__main__":
    reporting = UnifiedReporting()
    reporting.run()
