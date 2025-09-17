# api.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import sys
import requests
from bs4 import BeautifulSoup
import re
import json
import tempfile
import hashlib
from datetime import datetime

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'py', 'js', 'html'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

# Enhanced vulnerability detection functions
def detect_vulnerabilities(code, language='javascript'):
    findings = []
    lines = code.split('\n')
    
    # Hardcoded secrets detection
    secret_patterns = [
        {'pattern': r'API[_-]?KEY\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'API_KEY', 'severity': 'Critical'},
        {'pattern': r'SECRET[_-]?KEY\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'SECRET_KEY', 'severity': 'Critical'},
        {'pattern': r'TOKEN\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'TOKEN', 'severity': 'Critical'},
        {'pattern': r'PASSWORD\s*[:=]\s*["\']([^"\']{6,})["\']', 'name': 'PASSWORD', 'severity': 'Critical'},
        {'pattern': r'[A-Z_]*[A-Z0-9_]*\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']', 'name': 'GENERIC_SECRET', 'severity': 'High'}
    ]
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith('//') or line.strip().startswith('#'):
            continue
            
        # Hardcoded secrets
        for secret_pattern in secret_patterns:
            matches = re.finditer(secret_pattern['pattern'], line, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(1) if len(match.groups()) > 0 else "hidden"
                findings.append({
                    'type': 'HARDCODED_SECRET',
                    'description': f'Hardcoded {secret_pattern["name"]} detected',
                    'severity': secret_pattern['severity'],
                    'line': line_num,
                    'code_snippet': line.strip()
                })
        
        # Dangerous eval usage
        if 'eval(' in line and not ('//' in line or '#' in line):
            findings.append({
                'type': 'DANGEROUS_EVAL',
                'description': 'Use of eval() detected - potential code injection',
                'severity': 'High',
                'line': line_num,
                'code_snippet': line.strip()
            })
        
        # XSS vulnerabilities (JavaScript)
        if language == 'javascript' and 'innerHTML' in line and '=' in line:
            findings.append({
                'type': 'XSS_VULNERABILITY',
                'description': 'Potential XSS via innerHTML assignment',
                'severity': 'High',
                'line': line_num,
                'code_snippet': line.strip()
            })
        
        # XSS via document.write
        if language == 'javascript' and ('document.write(' in line or 'document.writeln(' in line):
            findings.append({
                'type': 'XSS_VULNERABILITY',
                'description': 'Potential XSS via document.write()',
                'severity': 'High',
                'line': line_num,
                'code_snippet': line.strip()
            })
        
        # Command injection (Python)
        if language == 'python' and 'subprocess.' in line and 'shell=True' in line:
            findings.append({
                'type': 'COMMAND_INJECTION',
                'description': 'Potential command injection with shell=True',
                'severity': 'Critical',
                'line': line_num,
                'code_snippet': line.strip()
            })
        
        # SQL Injection patterns
        if ('execute' in line or 'query' in line) and ('+' in line or 'format(' in line or '%' in line):
            findings.append({
                'type': 'SQL_INJECTION',
                'description': 'Potential SQL injection via string concatenation',
                'severity': 'High',
                'line': line_num,
                'code_snippet': line.strip()
            })
        
        # Weak crypto
        if 'md5(' in line or 'sha1(' in line or '.md5(' in line or '.sha1(' in line:
            findings.append({
                'type': 'WEAK_CRYPTO',
                'description': 'Weak cryptographic algorithm (MD5/SHA1) detected',
                'severity': 'Medium',
                'line': line_num,
                'code_snippet': line.strip()
            })
    
    return findings

def calculate_triage_score(findings):
    if not findings:
        return 0.0
    
    severity_weights = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1
    }
    
    total_weight = sum(severity_weights.get(finding['severity'], 1) for finding in findings)
    max_possible = len(findings) * 10
    
    return (total_weight / max_possible) * 10 if max_possible > 0 else 0.0

def get_risk_level(findings):
    if not findings:
        return 'Low'
    
    severities = [f['severity'] for f in findings]
    if 'Critical' in severities:
        return 'Critical'
    elif 'High' in severities:
        return 'High'
    elif 'Medium' in severities:
        return 'Medium'
    else:
        return 'Low'

# Enhanced API endpoints
@app.route('/api/scan-code', methods=['POST'])
def scan_code():
    try:
        data = request.get_json()
        code = data.get('code', '')
        language = data.get('language', 'javascript')
        
        if not code.strip():
            return jsonify({'error': 'No code provided'}), 400
        
        findings = detect_vulnerabilities(code, language)
        triage_score = calculate_triage_score(findings)
        risk_level = get_risk_level(findings)
        
        return jsonify({
            'findings': findings,
            'triage_score': round(triage_score, 1),
            'total_findings': len(findings),
            'risk_level': risk_level
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-website', methods=['POST'])
def scan_website():
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Fetch website content
        headers = {
            'User-Agent': 'Smart Code Vulnerability Triage System/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract JavaScript code
        scripts = soup.find_all('script')
        js_code = ''
        
        for script in scripts:
            if script.string:
                js_code += script.string + '\n'
            elif script.get('src'):
                # Try to fetch external script
                try:
                    script_url = script['src']
                    if not script_url.startswith(('http://', 'https://')):
                        # Handle relative URLs
                        if script_url.startswith('/'):
                            script_url = url.rstrip('/') + script_url
                        else:
                            script_url = url.rsplit('/', 1)[0] + '/' + script_url
                    
                    script_response = requests.get(script_url, headers=headers, timeout=5)
                    if script_response.status_code == 200:
                        js_code += script_response.text + '\n'
                except:
                    pass
        
        # Analyze JavaScript code
        findings = detect_vulnerabilities(js_code, 'javascript')
        triage_score = calculate_triage_score(findings)
        risk_level = get_risk_level(findings)
        
        return jsonify({
            'findings': findings,
            'triage_score': round(triage_score, 1),
            'total_findings': len(findings),
            'risk_level': risk_level,
            'scanned_url': url,
            'scripts_analyzed': len(scripts)
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Failed to fetch website: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Read file content
        content = file.read().decode('utf-8', errors='ignore')
        
        # Determine language from file extension
        extension = file.filename.rsplit('.', 1)[1].lower()
        language = 'python' if extension == 'py' else 'javascript'
        
        # Analyze code
        findings = detect_vulnerabilities(content, language)
        triage_score = calculate_triage_score(findings)
        risk_level = get_risk_level(findings)
        
        return jsonify({
            'findings': findings,
            'triage_score': round(triage_score, 1),
            'total_findings': len(findings),
            'risk_level': risk_level,
            'filename': file.filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Enhanced dashboard data endpoint
@app.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    # In a real implementation, this would query a database
    # For demo, return sample data
    sample_stats = {
        'total_scans': 127,
        'vulnerabilities_found': 45,
        'critical_issues': 8,
        'high_issues': 15,
        'recent_scans': [
            {'target': 'github.com', 'score': 7.2, 'date': '2024-01-15'},
            {'target': 'test.py', 'score': 2.1, 'date': '2024-01-14'},
            {'target': 'example.com', 'score': 4.5, 'date': '2024-01-13'}
        ]
    }
    return jsonify(sample_stats)

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🚀 Starting Smart Code Vulnerability Triage System...")
    print("📋 Access the web interface at: http://localhost:5000")
    print("📊 API endpoints available at: http://localhost:5000/api/*")
    app.run(debug=True, host='0.0.0.0', port=5000)
