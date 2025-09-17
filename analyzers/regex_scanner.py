import re
from pathlib import Path
from rules.regex_rules import REGEX_RULES

class RegexScanner:
    def __init__(self):
        self.compiled_rules = {}
        for rule_name, rule_data in REGEX_RULES.items():
            self.compiled_rules[rule_name] = {
                'pattern': re.compile(rule_data['pattern'], re.IGNORECASE),
                'description': rule_data['description'],
                'severity': rule_data['severity'],
                'languages': rule_data['languages']
            }
    
    def scan_file(self, file_path):
        findings = []
        file_extension = Path(file_path).suffix[1:]  # Remove the dot
        
        language_map = {
            'py': 'python',
            'js': 'javascript'
        }
        
        target_language = language_map.get(file_extension)
        if not target_language:
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return findings
        
        for line_num, line in enumerate(lines, 1):
            for rule_name, rule_data in self.compiled_rules.items():
                if target_language in rule_data['languages']:
                    if rule_data['pattern'].search(line):
                        findings.append({
                            'type': rule_name,
                            'description': rule_data['description'],
                            'severity': rule_data['severity'],
                            'line': line_num,
                            'file': file_path,
                            'code_snippet': line.strip()
                        })
        
        return findings