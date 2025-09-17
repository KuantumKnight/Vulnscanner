import unittest
import tempfile
import os
from analyzers.regex_scanner import RegexScanner
from analyzers.ast_analyzer import PythonASTAnalyzer

class TestAnalyzers(unittest.TestCase):
    def test_regex_scanner_hardcoded_secret(self):
        scanner = RegexScanner()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('PASSWORD = "secret123"\n')
            temp_file = f.name
        
        try:
            findings = scanner.scan_file(temp_file)
            self.assertTrue(any('HARDCODED_SECRET' in str(f) for f in findings))
        finally:
            os.unlink(temp_file)
    
    def test_ast_analyzer_eval_detection(self):
        analyzer = PythonASTAnalyzer()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('result = eval(user_input)\n')
            temp_file = f.name
        
        try:
            findings = analyzer.analyze_file(temp_file)
            self.assertTrue(any('DANGEROUS_FUNCTION_CALL' in str(f) for f in findings))
        finally:
            os.unlink(temp_file)

if __name__ == '__main__':
    unittest.main()