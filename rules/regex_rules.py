import re

REGEX_RULES = {
    # SQL Injection
    "SQL_INJECTION_PYTHON": {
        "pattern": r"(?i)(cursor\.execute|execute_query|raw|sql\.)\s*\([^)]*(\+|format|%)",
        "description": "Potential SQL Injection via string concatenation",
        "severity": "High",
        "languages": ["python"]
    },
    "SQL_INJECTION_JS": {
        "pattern": r"(?i)(query|execute|prepare)\s*\([^)]*(\+|\${)",
        "description": "Potential SQL Injection in JavaScript",
        "severity": "High",
        "languages": ["javascript"]
    },
    
    # XSS
    "XSS_PYTHON": {
        "pattern": r"(?i)(render_template_string|mark_safe|safe|html\.|flask\.|django\.).*request\.",
        "description": "Potential XSS via unsafe template rendering",
        "severity": "Medium",
        "languages": ["python"]
    },
    "XSS_JS": {
        "pattern": r"(?i)(innerHTML|document\.write|eval|setTimeout|setInterval).*\+",
        "description": "Potential XSS via DOM manipulation",
        "severity": "High",
        "languages": ["javascript"]
    },
    
    # Path Traversal
    "PATH_TRAVERSAL": {
        "pattern": r"(?i)(open|readFile|include|require).*\.\./",
        "description": "Potential Path Traversal vulnerability",
        "severity": "High",
        "languages": ["python", "javascript"]
    },
    
    # Command Injection
    "COMMAND_INJECTION_PYTHON": {
        "pattern": r"(?i)(os\.system|subprocess\.(call|run|Popen)|commands\.getoutput|popen).*\+",
        "description": "Potential Command Injection via shell commands",
        "severity": "Critical",
        "languages": ["python"]
    },
    "COMMAND_INJECTION_JS": {
        "pattern": r"(?i)(exec|spawn|execFile).*\+",
        "description": "Potential Command Injection in Node.js",
        "severity": "Critical",
        "languages": ["javascript"]
    },
    
    # Hardcoded Secrets
    "HARDCODED_SECRET": {
        "pattern": r"(?i)(password|secret|token|key|api_key)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']",
        "description": "Hardcoded credentials detected",
        "severity": "Critical",
        "languages": ["python", "javascript"]
    },
    
    # Insecure Deserialization
    "INSECURE_DESERIALIZATION_PYTHON": {
        "pattern": r"(?i)(pickle\.loads|yaml\.load|eval|exec).*request\.",
        "description": "Insecure deserialization detected",
        "severity": "High",
        "languages": ["python"]
    },
    "INSECURE_DESERIALIZATION_JS": {
        "pattern": r"(?i)(JSON\.parse|eval).*request\.",
        "description": "Potential insecure deserialization",
        "severity": "Medium",
        "languages": ["javascript"]
    },
    
    # Weak Cryptography
    "WEAK_CRYPTO": {
        "pattern": r"(?i)(md5|sha1|DES|RC4)",
        "description": "Weak cryptographic algorithm detected",
        "severity": "Medium",
        "languages": ["python", "javascript"]
    },
    
    # Debug Mode/Development Code
    "DEBUG_MODE": {
        "pattern": r"(?i)(debug\s*=\s*True|app\.run\(\s*debug\s*=\s*True)",
        "description": "Debug mode enabled in production code",
        "severity": "Medium",
        "languages": ["python"]
    }
}