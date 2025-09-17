#!/usr/bin/env python3

import argparse
import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try to import modules, provide fallbacks if they fail
try:
    from core.scanner import CodeScanner
    SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Scanner not available: {e}")
    SCANNER_AVAILABLE = False

try:
    from core.reporter import ReportGenerator
    REPORTER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Reporter not available: {e}")
    REPORTER_AVAILABLE = False

try:
    from config.settings import SCAN_CONFIG
except ImportError:
    SCAN_CONFIG = {
        'supported_extensions': ['py', 'js'],
    }

def main():
    parser = argparse.ArgumentParser(description='Smart Code Vulnerability Triage System')
    parser.add_argument('--scan', '-s', required=True, help='Path to scan')
    parser.add_argument('--ai', action='store_true', help='Enable AI integration')
    parser.add_argument('--report-format', choices=['json', 'html'], default='json', help='Report format')
    parser.add_argument('--output', '-o', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Simple regex-based scanner as fallback
    if not SCANNER_AVAILABLE:
        print("Using basic regex scanner...")
        basic_scan(args.scan, args.output, args.report_format)
        return
    
    try:
        # Initialize scanner
        scanner = CodeScanner(ai_enabled=args.ai)
        
        # Scan files
        if os.path.isfile(args.scan):
            files_to_scan = [args.scan]
        else:
            files_to_scan = []
            for ext in SCAN_CONFIG['supported_extensions']:
                files_to_scan.extend(Path(args.scan).rglob(f'*.{ext}'))
        
        print("🔍 Smart Code Vulnerability Triage System")
        print(f"Scanning {len(files_to_scan)} files...\n")
        
        all_findings = []
        for file_path in files_to_scan:
            try:
                findings = scanner.scan_file(str(file_path))
                all_findings.extend(findings)
                if findings:
                    print(f"File: {file_path}")
                    for finding in findings:
                        severity_icon = {"Critical": "🚨", "High": "🚨", "Medium": "⚠️", "Low": "ℹ️"}
                        icon = severity_icon.get(finding.get('severity', 'Low'), "ℹ️")
                        line_num = finding.get('line', 'N/A')
                        print(f"{icon} {finding.get('severity', 'Unknown')}: {finding.get('description', 'Unknown issue')} (Line {line_num})")
                    print()
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
        
        # Generate report
        if REPORTER_AVAILABLE:
            try:
                reporter = ReportGenerator()
                triage_score = reporter.calculate_triage_score(all_findings)
                risk_level = 'Critical' if triage_score >= 8 else 'High' if triage_score >= 6 else 'Medium' if triage_score >= 4 else 'Low'
                print(f"Triage Score: {triage_score:.1f}/10 ({risk_level} Risk)")
                
                report_path = reporter.generate_report(all_findings, args.output, args.report_format)
                print(f"\nReport generated: {report_path}")
            except Exception as e:
                print(f"Error generating report: {e}")
        else:
            # Simple JSON output
            import json
            report_path = os.path.join(args.output, "basic_report.json")
            with open(report_path, 'w') as f:
                json.dump(all_findings, f, indent=2)
            print(f"\nBasic report generated: {report_path}")
            
    except Exception as e:
        print(f"Error initializing scanner: {e}")
        print("Running in minimal mode...")

def basic_scan(scan_path, output_dir, format_type):
    """Basic regex-based scanning as fallback"""
    import re
    from pathlib import Path
    
    # Simple regex patterns
    patterns = {
        "HARDCODED_SECRET": {
            "pattern": re.compile(r"(?i)(password|secret|token|key|api_key)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']", re.IGNORECASE),
            "description": "Hardcoded credentials detected",
            "severity": "Critical"
        },
        "DANGEROUS_EVAL": {
            "pattern": re.compile(r"\beval\s*\(", re.IGNORECASE),
            "description": "Use of eval() detected",
            "severity": "High"
        },
        "SQL_INJECTION": {
            "pattern": re.compile(r"(?i)(execute|query)\s*\([^)]*(\+|format|%)", re.IGNORECASE),
            "description": "Potential SQL Injection",
            "severity": "High"
        }
    }
    
    findings = []
    
    # Find files to scan
    if os.path.isfile(scan_path):
        files_to_scan = [scan_path]
    else:
        files_to_scan = []
        for ext in ['py', 'js']:
            files_to_scan.extend(Path(scan_path).rglob(f'*.{ext}'))
    
    print(f"Scanning {len(files_to_scan)} files with basic scanner...")
    
    for file_path in files_to_scan:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern_data in patterns.items():
                    if pattern_data['pattern'].search(line):
                        findings.append({
                            'type': pattern_name,
                            'description': pattern_data['description'],
                            'severity': pattern_data['severity'],
                            'line': line_num,
                            'file': str(file_path),
                            'code_snippet': line.strip()[:100]
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    
    # Output results
    if format_type == 'json':
        import json
        report_path = os.path.join(output_dir, "basic_report.json")
        with open(report_path, 'w') as f:
            json.dump({
                'findings': findings,
                'total_findings': len(findings)
            }, f, indent=2)
        print(f"Basic JSON report generated: {report_path}")
    else:
        report_path = os.path.join(output_dir, "basic_report.txt")
        with open(report_path, 'w') as f:
            f.write("Smart Code Vulnerability Triage System - Basic Report\n")
            f.write("=" * 50 + "\n\n")
            for finding in findings:
                f.write(f"{finding['severity']}: {finding['description']}\n")
                f.write(f"File: {finding['file']}:{finding['line']}\n")
                f.write(f"Code: {finding['code_snippet']}\n\n")
        print(f"Basic text report generated: {report_path}")

if __name__ == "__main__":
    main()
