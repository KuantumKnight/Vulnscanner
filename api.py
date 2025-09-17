from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import os
import json
import tempfile
from werkzeug.utils import secure_filename
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import your existing modules
try:
    from core.scanner import CodeScanner
    from core.reporter import ReportGenerator
    SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Scanner import error: {e}")
    SCANNER_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'py', 'js'}

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

@app.route('/api/scan', methods=['POST'])
def scan_code():
    if not SCANNER_AVAILABLE:
        return jsonify({
            'error': 'Scanner not available',
            'findings': [],
            'triage_score': 0
        }), 500

    # Handle file upload
    if 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    elif 'code' in request.form:
        # Handle direct code input
        code_content = request.form['code']
        language = request.form.get('language', 'py')
        file_extension = '.py' if language == 'python' else '.js'
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix=file_extension, delete=False) as f:
            f.write(code_content)
            file_path = f.name
            filename = f"temp_code{file_extension}"
    else:
        return jsonify({'error': 'No file or code provided'}), 400

    try:
        # Initialize scanner
        scanner = CodeScanner()
        
        # Scan the file
        findings = scanner.scan_file(file_path)
        
        # Generate report
        reporter = ReportGenerator()
        triage_score = reporter.calculate_triage_score(findings)
        
        # Clean up temporary file if it was created
        if 'code' in request.form:
            os.unlink(file_path)
        
        return jsonify({
            'filename': filename,
            'findings': findings,
            'triage_score': triage_score,
            'risk_level': get_risk_level(triage_score),
            'total_findings': len(findings)
        })
        
    except Exception as e:
        # Clean up temporary file if it was created
        if 'code' in request.form and 'file_path' in locals():
            os.unlink(file_path)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-directory', methods=['POST'])
def scan_directory():
    # For directory scanning, we'll need to implement file upload handling
    # This is a simplified version for single files
    return scan_code()

def get_risk_level(score):
    if score >= 8:
        return 'Critical'
    elif score >= 6:
        return 'High'
    elif score >= 4:
        return 'Medium'
    else:
        return 'Low'

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'scanner_available': SCANNER_AVAILABLE
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
