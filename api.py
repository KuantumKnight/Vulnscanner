from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return "<h1>Smart Code Vulnerability Triage System</h1><p>Web server is running!</p>"

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "message": "Server is running"})

if __name__ == '__main__':
    print("Starting Flask server...")
    print("Access the web interface at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
