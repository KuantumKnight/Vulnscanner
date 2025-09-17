SCAN_CONFIG = {
    'supported_extensions': ['py', 'js'],
    'default_severity_weights': {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1
    },
    'ai_threshold': 0.8,
    'max_file_size': 1024 * 1024,  # 1MB
    'excluded_dirs': ['.git', '__pycache__', 'node_modules', 'venv']
}