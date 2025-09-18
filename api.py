# api.py - Vulnscanner with ASCII Art Loader
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
import os
import sys
import re
import time
import threading

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'js', 'html', 'java', 'php', 'cs'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def show_ascii_art():
    """Display Vulnscanner ASCII art loader in terminal"""
    ascii_art = r"""                                                      
            (                                         
 (   (   (  )\                )               (  (    
 )\  )\ ))\((_)(    (   (  ( /(  (     (     ))\ )(   
((_)((_)((_)_  )\ ) )\  )\ )(_)) )\ )  )\ ) /((_|()\  
\ \ / (_))(| |_(_/(((_)((_|(_)_ _(_/( _(_/((_))  ((_) 
 \ V /| || | | ' \)|_-< _|/ _` | ' \)) ' \)) -_)| '_| 
  \_/  \_,_|_|_||_|/__|__|\__,_|_||_||_||_|\___||_|                                                                                                                                                                                                                                           
    """
    
    loading_messages = [
        "Initializing Vulnscanner Core Engine...",
        "Loading detection modules: SQLi, XSS, CSRF, RCE...",
        "All systems operational!",
        "Starting web interface..."
    ]
    
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Print ASCII art with colors
    print("\033[91m" + ascii_art + "\033[0m")  # Red color for Vulnscanner
    print("\033[94m" + "="*100 + "\033[0m")
    print("\033[96mVULNSCANNER v2.0 - ADVANCED CODE VULNERABILITY DETECTION SYSTEM\033[0m")
    print("\033[94m" + "="*100 + "\033[0m\n")
    
    
    print("\n\033[92m✓ System initialization complete!\033[0m")
    print("\033[96m✓ Web interface available at: http://localhost:5000\033[0m")
    print("\033[96m✓ API endpoints ready for vulnerability scanning\033[0m")
    print("\033[93m\nPress Ctrl+C to stop the server\033[0m\n")

@app.route('/')
def index():
    return render_template('index.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_security_vulnerabilities(code, language='javascript'):
    findings = []
    lines = code.split('\n')
    
    # Advanced vulnerability detection based on security best practices
    vulnerability_patterns = {
        # Injection Vulnerabilities
        'SQL_INJECTION': {
            'patterns': [
                r'\b(execute|query|prepare)\s*\([^)]*(\+|%s|format\(|\$\{)',
                r'\bSELECT\s+.*\bFROM\s+.*\bWHERE\s+.*[\'"]\s*\+',
                r'\bINSERT\s+INTO\s+.*\bVALUES\s*\(.*[\'"]\s*\+'
            ],
            'description': 'SQL Injection - Untrusted data is concatenated into SQL queries without proper sanitization',
            'severity': 'Critical',
            'category': 'Injection'
        },
        'COMMAND_INJECTION': {
            'patterns': [
                r'\b(os\.system|subprocess\.(call|run|Popen)|commands\.getoutput|popen)\s*\([^)]*\+',
                r'\b(exec|spawn|execFile)\s*\([^)]*\+'
            ],
            'description': 'Command Injection - User input is executed as system commands without proper validation',
            'severity': 'Critical',
            'category': 'Injection'
        },
        'XSS_VULNERABILITY': {
            'patterns': [
                r'\binnerHTML\s*=\s*[\'"]?\s*\$\{',
                r'\b(document\.write|eval|setTimeout|setInterval)\s*\([^)]*\+'
            ],
            'description': 'Cross-Site Scripting (XSS) - Untrusted data is inserted into HTML without proper encoding',
            'severity': 'High',
            'category': 'Injection'
        },
        
        # Authentication & Session Management
        'HARDCODED_SECRETS': {
            'patterns': [
                r'(API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD)\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]',
                r'[A-Z_]*[A-Z0-9_]*\s*[:=]\s*[\'"][a-zA-Z0-9]{32,}[\'"]'
            ],
            'description': 'Hardcoded Secrets - Sensitive credentials are embedded directly in source code',
            'severity': 'Critical',
            'category': 'Authentication'
        },
        
        # Dangerous Functions
        'DANGEROUS_FUNCTIONS': {
            'patterns': [
                r'\b(eval|exec|system|shell_exec|passthru|popen)\s*\(',
                r'\beval\s*\$\{.*\}'
            ],
            'description': 'Dangerous Functions - Use of functions that can execute arbitrary code',
            'severity': 'High',
            'category': 'Code Quality'
        },
        
        # Weak Cryptography
        'WEAK_CRYPTOGRAPHY': {
            'patterns': [
                r'\b(md5|sha1|DES|RC4)\s*\(',
                r'\bMD5|SHA1\s*\([^)]*password'
            ],
            'description': 'Weak Cryptography - Use of deprecated or insecure cryptographic algorithms',
            'severity': 'High',
            'category': 'Cryptography'
        }
    }
    
    # Language-specific patterns
    language_specific = {
        'python': {
            'patterns': [
                r'\b(subprocess\.Popen|os\.system|eval|exec)\s*\(',
                r'\bpickle\.loads?\s*\('
            ],
            'description': 'Python-specific dangerous functions detected',
            'severity': 'High'
        },
        'javascript': {
            'patterns': [
                r'\beval\s*\(',
                r'\bdocument\.write\s*\(',
                r'\binnerHTML\s*='
            ],
            'description': 'JavaScript-specific XSS vulnerabilities detected',
            'severity': 'High'
        }
    }
    
    # Scan for vulnerabilities
    for line_num, line in enumerate(lines, 1):
        # Skip comments and empty lines
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(('#', '//', '/*', '*', '*/')):
            continue
            
        # Check for general vulnerability patterns
        for vuln_name, vuln_data in vulnerability_patterns.items():
            for pattern in vuln_data['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'type': vuln_name,
                        'description': vuln_data['description'],
                        'severity': vuln_data['severity'],
                        'category': vuln_data['category'],
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'recommendation': get_recommendation(vuln_name)
                    })
        
        # Check for language-specific patterns
        if language in language_specific:
            lang_patterns = language_specific[language]
            for pattern in lang_patterns['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'type': f'{language.upper()}_{lang_patterns["description"].split()[0].upper()}',
                        'description': lang_patterns['description'],
                        'severity': lang_patterns['severity'],
                        'category': 'Language Specific',
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'recommendation': get_language_recommendation(language)
                    })
    
    # Remove duplicates based on line and type
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding['line'], finding['type'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return unique_findings

def get_recommendation(vuln_type):
    recommendations = {
        'SQL_INJECTION': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
        'COMMAND_INJECTION': 'Avoid shell=True in subprocess calls. Use input validation and allowlists for acceptable commands.',
        'XSS_VULNERABILITY': 'Encode output data before rendering in HTML. Use frameworks that auto-escape output.',
        'HARDCODED_SECRETS': 'Store secrets in environment variables or secure vaults. Never commit credentials to source control.',
        'DANGEROUS_FUNCTIONS': 'Avoid eval() and similar functions. Use safer alternatives for dynamic code execution.',
        'WEAK_CRYPTOGRAPHY': 'Use modern cryptographic libraries and algorithms (AES, SHA-256, bcrypt).'
    }
    return recommendations.get(vuln_type, 'Follow security best practices and validate all user inputs.')

def get_language_recommendation(language):
    lang_recommendations = {
        'python': 'Use secure alternatives to dangerous functions. Validate all inputs and outputs.',
        'javascript': 'Sanitize user inputs and encode outputs. Use Content Security Policy (CSP).'
    }
    return lang_recommendations.get(language, 'Follow language-specific security best practices.')

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
        
        findings = detect_security_vulnerabilities(code, language)
        triage_score = calculate_triage_score(findings)
        risk_level = get_risk_level(findings)
        
        return jsonify({
            'findings': findings,
            'triage_score': round(triage_score, 1),
            'total_findings': len(findings),
            'risk_level': risk_level,
            'vulnerability_categories': get_category_summary(findings)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_category_summary(findings):
    categories = {}
    for finding in findings:
        category = finding.get('category', 'Unknown')
        if category in categories:
            categories[category] += 1
        else:
            categories[category] = 1
    return categories

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
        language_map = {
            'py': 'python',
            'js': 'javascript',
            'html': 'javascript',
            'java': 'java',
            'php': 'php',
            'cs': 'csharp'
        }
        language = language_map.get(extension, 'javascript')
        
        # Analyze code
        findings = detect_security_vulnerabilities(content, language)
        triage_score = calculate_triage_score(findings)
        risk_level = get_risk_level(findings)
        
        return jsonify({
            'findings': findings,
            'triage_score': round(triage_score, 1),
            'total_findings': len(findings),
            'risk_level': risk_level,
            'filename': file.filename,
            'language': language,
            'vulnerability_categories': get_category_summary(findings)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-website', methods=['POST'])
def scan_website():
    try:
        # Return placeholder response - ready for implementation
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
    # Show Vulnscanner ASCII art loader
    show_ascii_art()
    
    # Start Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
