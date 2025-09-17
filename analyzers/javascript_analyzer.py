# analyzers/javascript_analyzer.py
try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False
    print("Warning: esprima not available for JavaScript analysis")

class JavaScriptAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.current_file = ""
    
    def analyze_file(self, file_path):
        if not ESPRIMA_AVAILABLE:
            return []
            
        self.current_file = file_path
        self.vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            ast = esprima.parseScript(content)
            self._traverse_ast(ast)
        except Exception as e:
            print(f"Error parsing JavaScript {file_path}: {e}")
        
        return self.vulnerabilities
    
    def _traverse_ast(self, node):
        if not ESPRIMA_AVAILABLE or not hasattr(node, 'type'):
            return
        
        # Check for eval usage
        if (hasattr(node, 'type') and node.type == 'CallExpression' and 
            hasattr(node, 'callee') and hasattr(node.callee, 'name') and node.callee.name == 'eval'):
            line_num = getattr(node, 'loc', None)
            line = line_num.start.line if line_num and hasattr(line_num, 'start') else 0
            self.vulnerabilities.append({
                'type': 'DANGEROUS_EVAL',
                'description': "Use of eval() detected",
                'severity': 'High',
                'line': line,
                'file': self.current_file
            })
        
        # Recursively traverse child nodes
        for key, value in vars(node).items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, '__dict__'):  # Check if it's an object with attributes
                        self._traverse_ast(item)
            elif hasattr(value, '__dict__'):  # Check if it's an object with attributes
                self._traverse_ast(value)
