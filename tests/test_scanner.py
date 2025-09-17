import unittest
import tempfile
import os
from core.scanner import CodeScanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CodeScanner()
        
    def test_python_file_scan(self):
        # Create a temporary Python file with known vulnerabilities
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('API_KEY = "test123"\n')
            f.write('eval(input())\n')
            temp_file = f.name
        
        try:
            findings = self.scanner.scan_file(temp_file)
            # Should detect hardcoded secret and eval usage
            self.assertGreater(len(findings), 0)
        finally:
            os.unlink(temp_file)
    
    def test_javascript_file_scan(self):
        # Create a temporary JavaScript file with known vulnerabilities
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const API_KEY = "test123";\n')
            f.write('eval(userInput);\n')
            temp_file = f.name
        
        try:
            findings = self.scanner.scan_file(temp_file)
            # Should detect hardcoded secret and eval usage
            self.assertGreater(len(findings), 0)
        finally:
            os.unlink(temp_file)

if __name__ == '__main__':
    unittest.main()