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

app = Flask(__name__, template_folder='templates', static_folder='static')
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

# ... rest of your api.py code
