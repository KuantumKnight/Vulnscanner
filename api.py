# api.py - Ultimate Security Vulnerability Scanner
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import sys
import re
import hashlib

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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

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
                r'\bINSERT\s+INTO\s+.*\bVALUES\s*\(.*[\'"]\s*\+',
                r'\bUPDATE\s+.*\bSET\s+.*[\'"]\s*\+',
                r'\bDELETE\s+FROM\s+.*\bWHERE\s+.*[\'"]\s*\+'
            ],
            'description': 'SQL Injection - Untrusted data is concatenated into SQL queries without proper sanitization',
            'severity': 'Critical',
            'category': 'Injection'
        },
        'COMMAND_INJECTION': {
            'patterns': [
                r'\b(os\.system|subprocess\.(call|run|Popen)|commands\.getoutput|popen)\s*\([^)]*\+',
 
               r'\b(exec|spawn|execFile)\s*\([^)]*\+',
                r'\bshell_exec|eval|system\s*\([^)]*\$',
                r'\bRuntime\.getRuntime\(\)\.exec\s*\([^)]*\+'
            ],
            'description': 'Command Injection - User input is executed as system commands without proper validation',
            'severity': 'Critical',
            'category': 'Injection'
        },
        'LDAP_INJECTION': {
            'patterns': [
                r'\b(search|find)\s*\([^)]*=\s*[\'"][^\'"]*\$\{',
 
               r'\bldap\.(search|bind)\s*\([^)]*\+',
                r'\bfilter\s*=\s*[\'"][^\'"]*\$\{'
            ],
            'description': 'LDAP Injection - User input is used in LDAP queries without proper escaping',
            'severity': 'High',
            'category': 'Injection'
        },
        'XSS_VULNERABILITY': {
            'patterns': [
                r'\binnerHTML\s*=\s*[\'"]?\s*\$\{',
 
               r'\b(document\.write|eval|setTimeout|setInterval)\s*\([^)]*\+',
                r'\bouterHTML\s*=\s*[\'"]?\s*\$\{',
                r'\binsertAdjacentHTML\s*\([^)]*\+',
                r'\bresponse\.write\s*\([^)]*\+'
            ],
            'description': 'Cross-Site Scripting (XSS) - Untrusted data is inserted into HTML without proper encoding',
            'severity': 'High',
            'category': 'Injection'
        },
        
        # Authentication & Session Management
        'INSECURE_PASSWORD_STORAGE': {
            'patterns': [
                r'password\s*[:=]\s*[\'"][^\'"]{1,6}[\'"]',
 
               r'(md5|sha1)\s*\([^)]*password',
                r'hash\s*[:=]\s*[\'"][a-f0-9]{32}[\'"]',
                r'secret\s*[:=]\s*[\'"][^\'"]{4,}[\'"]'
            ],
            'description': 'Insecure Password Storage - Weak hashing or hardcoded credentials detected',
            'severity': 'Critical',
            'category': 'Authentication'
        },
        'HARDCODED_SECRETS': {
            'patterns': [
                r'(API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD)\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]',
 
               r'[A-Z_]*[A-Z0-9_]*\s*[:=]\s*[\'"][a-zA-Z0-9]{32,}[\'"]',
                r'aws_access_key|aws_secret_key\s*[:=]\s*[\'"][^\'"]{10,}[\'"]'
            ],
            'description': 'Hardcoded Secrets - Sensitive credentials are embedded directly in source code',
            'severity': 'Critical',
            'category': 'Authentication'
        },
        
        # Input Validation
        'INSUFFICIENT_INPUT_VALIDATION': {
            'patterns': [
                r'\b(input|request|param|argv)\s*\[\s*[\'"][^\'"]*[\'"]\s*\]',
 
               r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"][^\'"]*[\'"]\s*\]',
                r'\.getParameter\s*\([^)]*\)',
                r'\bparams\s*\[\s*[\'"][^\'"]*[\'"]\s*\]'
            ],
            'description': 'Insufficient Input Validation - User input is used without proper sanitization',
            'severity': 'Medium',
            'category': 'Input Validation'
        },
        
        # CSRF Protection
        'CSRF_VULNERABILITY': {
            'patterns': [
                r'\b(method|type)\s*[:=]\s*[\'"]post[\'"]',
 
               r'\bform\s*.*\baction\s*=',
                r'\$_POST\s*\[\s*[\'"][^\'"]*[\'"]\s*\]',
                r'\.post\s*\([^)]*\)'
            ],
            'description': 'Potential CSRF Vulnerability - POST requests without anti-CSRF tokens detected',
            'severity': 'Medium',
            'category': 'CSRF Protection'
        },
        
        # Dangerous Functions
        'DANGEROUS_FUNCTIONS': {
            'patterns': [
                r'\b(eval|exec|system|shell_exec|passthru|popen)\s*\(',
 
               r'\bUnsafe\.eval|dangerouslySetInnerHTML',
                r'\beval\s*\$\{.*\}',
                r'\bRuntime\.getRuntime\(\)\.exec'
            ],
            'description': 'Dangerous Functions - Use of functions that can execute arbitrary code',
            'severity': 'High',
            'category': 'Code Quality'
        },
        
        # Weak Cryptography
        'WEAK_CRYPTOGRAPHY': {
            'patterns': [
                r'\b(md5|sha1|DES|RC4)\s*\(',
 
               r'\bMD5|SHA1\s*\([^)]*password',
                r'\bencryption\s*[:=]\s*[\'"](DES|RC4)[\'"]',
                r'\bhash\s*\([^)]*(md5|sha1)'
            ],
            'description': 'Weak Cryptography - Use of deprecated or insecure cryptographic algorithms',
            'severity': 'High',
            'category': 'Cryptography'
        },
        
        # Path Traversal
        'PATH_TRAVERSAL': {
            'patterns': [
                r'\b(open|readFile|include|require)\s*\([^)]*\.\./',
 
               r'\$_(GET|POST)\s*\[\s*[\'"]file[\'"]\s*\]',
                r'\bpath\.join\s*\([^)]*\.\./',
                r'\b\.\./.*\.(php|jsp|asp|aspx)'
            ],
            'description': 'Path Traversal - User input is used to access files without proper path validation',
            'severity': 'High',
            'category': 'File Access'
        }
    }
    
    # Language-specific patterns
    language_specific = {
        'python': {
            'patterns': [
                r'\b(subprocess\.Popen|os\.system|eval|exec)\s*\(',
                r'\bpickle\.loads?\s*\(',
                r'\byaml\.load\s*\('
            ],
            'description': 'Python-specific dangerous functions detected',
            'severity': 'High'
        },
        'javascript': {
            'patterns': [
                r'\beval\s*\(',
                r'\bdocument\.write\s*\(',
                r'\binnerHTML\s*=',
                r'\bdangerouslySetInnerHTML'
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
        'INSECURE_PASSWORD_STORAGE': 'Use strong hashing algorithms like bcrypt, scrypt, or Argon2 with salt.',
        'CSRF_VULNERABILITY': 'Implement anti-CSRF tokens for all state-changing requests.',
        'DANGEROUS_FUNCTIONS': 'Avoid eval() and similar functions. Use safer alternatives for dynamic code execution.',
        'WEAK_CRYPTOGRAPHY': 'Use modern cryptographic libraries and algorithms (AES, SHA-256, bcrypt).',
        'PATH_TRAVERSAL': 'Validate and sanitize file paths. Use allowlists for acceptable file operations.',
        'LDAP_INJECTION': 'Use parameterized LDAP queries and properly escape special characters.'
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
    print("🚀 Starting Ultimate Security Vulnerability Scanner...")
    print("📋 Access the web interface at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
