from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import os
import sys

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_code():
    try:
        data = request.get_json()
        code = data.get('code', '')
        language = data.get('language', 'python')
        
        # This is where you would integrate your actual vulnerability scanner
        # For now, we'll return mock results
        findings = []
        
        # Simple pattern matching for demo
        if 'API_KEY' in code or 'API_TOKEN' in code:
            findings.append({
                'type': 'HARDCODED_SECRET',
                'description': 'Hardcoded API key or token detected',
                'severity': 'Critical',
                'line': 1,
                'code_snippet': code.split('\n')[0] if code.split('\n') else ''
            })
        
        if 'eval(' in code:
            findings.append({
                'type': 'DANGEROUS_EVAL',
                'description': 'Use of eval() detected - potential code injection',
                'severity': 'High',
                'line': 1,
                'code_snippet': code.split('\n')[0] if code.split('\n') else ''
            })
        
        # Add more pattern matching as needed
        
        result = {
            'triage_score': len(findings) * 2.5 if findings else 2.0,
            'total_findings': len(findings),
            'risk_level': 'Critical' if any(f['severity'] == 'Critical' for f in findings) 
                         else 'High' if any(f['severity'] == 'High' for f in findings)
                         else 'Medium' if findings else 'Low',
            'findings': findings
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    print("Starting Smart Code Vulnerability Triage System...")
    print("Access the web interface at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
