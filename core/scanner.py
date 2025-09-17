import os
from pathlib import Path

from rules.regex_rules import REGEX_RULES
from analyzers.regex_scanner import RegexScanner
from analyzers.ast_analyzer import PythonASTAnalyzer
from analyzers.javascript_analyzer import JavaScriptAnalyzer

class CodeScanner:
    def __init__(self, ai_enabled=False):
        self.regex_scanner = RegexScanner()
        self.python_ast_analyzer = PythonASTAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.ai_enabled = ai_enabled
        
    def scan_file(self, file_path):
        findings = []
        
        # Regex scanning
        regex_findings = self.regex_scanner.scan_file(file_path)
        findings.extend(regex_findings)
        
        # Language-specific analysis
        if file_path.endswith('.py'):
            ast_findings = self.python_ast_analyzer.analyze_file(file_path)
            findings.extend(ast_findings)
        elif file_path.endswith('.js'):
            js_findings = self.js_analyzer.analyze_file(file_path)
            findings.extend(js_findings)
        
        # AI enhancement (placeholder)
        if self.ai_enabled:
            findings = self._enhance_with_ai(findings)
            
        return findings
    
    def _enhance_with_ai(self, findings):
        # Placeholder for AI integration
        # In a real implementation, this would call VulBERTa or similar
        return findings