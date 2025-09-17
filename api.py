# api.py - Complete version with all functions
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import sys
import re
import tempfile

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'js', 'html'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

def detect_vulnerabilities(code, language='javascript'):
    findings = []
    lines = code.split('\n')
    
    # Hardcoded secrets detection
    secret_patterns = [
        {'pattern': r'API[_-]?KEY\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'API_KEY', 'severity': 'Critical'},
        {'pattern': r'SECRET[_-]?KEY\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'SECRET_KEY', 'severity': 'Critical'},
        {'pattern': r'TOKEN\s*[:=]\s*["\']([^"\']{10,})["\']', 'name': 'TOKEN', 'severity': 'Critical'},
        {'pattern': r'PASSWORD\s*[:=]\s*["\']([^"\']{6,})["\']', 'name': 'PASSWORD', 'severity': 'Critical'}
    ]
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith('//') or line.strip().startswith('#'):
            continue
            
        # Hardcoded secrets
        for secret_pattern in secret_patterns:
            matches = re.finditer(secret_pattern['pattern'], line, re.IGNORECASE)
            for match in matches:
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
        
        # Command injection (Python)
        if language == 'python' and 'subprocess.' in line and 'shell=True' in line:
            findings.append({
                'type': 'COMMAND_INJECTION',
                'description': 'Potential command injection with shell=True',
                'severity': 'Critical',
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

@app.route('/api/scan-website', methods=['POST'])
def scan_website():
    try:
        # For now, return a simplified response
        # In a real implementation, you would add website scanning here
        data = request.get_json()
        url = data.get('url', '')
        
        return jsonify({
            'findings': [],
            'triage_score': 0.0,
            'total_findings': 0,
            'risk_level': 'Low',
            'scanned_url': url,
            'message': 'Website scanning functionality ready for implementation'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("🚀 Starting Smart Code Vulnerability Triage System...")
    print("📋 Access the web interface at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
