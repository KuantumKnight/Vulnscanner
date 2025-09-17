import ast
import os

class PythonASTAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
        self.current_file = ""
    
    def analyze_file(self, file_path):
        self.current_file = file_path
        self.vulnerabilities = []  # Reset for each file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            self.visit(tree)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        return self.vulnerabilities
    
    def visit_Call(self, node):
        # Check for eval/exec
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    'type': 'DANGEROUS_FUNCTION_CALL',
                    'description': f"Use of {node.func.id} detected",
                    'severity': 'High',
                    'line': node.lineno,
                    'file': self.current_file
                })
        
        # Check for subprocess with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'Popen' and hasattr(node.func.value, 'id'):
                if node.func.value.id == 'subprocess':
                    for keyword in node.keywords:
                        if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                            if keyword.value.value:
                                self.vulnerabilities.append({
                                    'type': 'COMMAND_INJECTION',
                                    'description': "subprocess.Popen with shell=True detected",
                                    'severity': 'Critical',
                                    'line': node.lineno,
                                    'file': self.current_file
                                })
        
        # Check for dynamic SQL execution
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['execute', 'executemany'] and hasattr(node.func.value, 'id'):
                if node.func.value.id in ['cursor', 'conn']:
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.BinOp) or isinstance(first_arg, ast.JoinedStr):
                            self.vulnerabilities.append({
                                'type': 'SQL_INJECTION',
                                'description': "Dynamic SQL query construction detected",
                                'severity': 'High',
                                'line': node.lineno,
                                'file': self.current_file
                            })
        
        # Check for insecure deserialization
        dangerous_modules = ['pickle', 'yaml', 'json']
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['loads', 'load'] and hasattr(node.func.value, 'id'):
                if node.func.value.id in dangerous_modules:
                    self.vulnerabilities.append({
                        'type': 'INSECURE_DESERIALIZATION',
                        'description': f"Insecure deserialization with {node.func.value.id}",
                        'severity': 'High',
                        'line': node.lineno,
                        'file': self.current_file
                    })
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in ['pickle', 'yaml']:
                self.vulnerabilities.append({
                    'type': 'DANGEROUS_IMPORT',
                    'description': f"Dangerous module import: {alias.name}",
                    'severity': 'Medium',
                    'line': node.lineno,
                    'file': self.current_file
                })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        if node.module in ['pickle', 'yaml']:
            self.vulnerabilities.append({
                'type': 'DANGEROUS_IMPORT',
                'description': f"Dangerous module import: {node.module}",
                'severity': 'Medium',
                'line': node.lineno,
                'file': self.current_file
            })
        self.generic_visit(node)