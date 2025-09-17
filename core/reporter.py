import json
import os
from datetime import datetime
from jinja2 import Template

from rules.severity_weights import SEVERITY_COLORS

class ReportGenerator:
    def __init__(self):
        self.severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
    
    def calculate_triage_score(self, findings):
        if not findings:
            return 0.0
            
        total_weight = sum(self.severity_weights.get(f.get('severity', 'Low'), 1) for f in findings)
        max_possible = len(findings) * max(self.severity_weights.values())
        
        return (total_weight / max_possible) * 10 if max_possible > 0 else 0.0
    
    def generate_report(self, findings, output_dir, format_type='json'):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        if format_type == 'json':
            return self._generate_json_report(findings, output_dir, timestamp)
        elif format_type == 'html':
            return self._generate_html_report(findings, output_dir, timestamp)
    
    def _generate_json_report(self, findings, output_dir, timestamp):
        report_data = {
            'scan_timestamp': timestamp,
            'total_findings': len(findings),
            'findings': findings,
            'triage_score': self.calculate_triage_score(findings)
        }
        
        report_path = os.path.join(output_dir, f"{timestamp}_vulnerability_report.json")
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return report_path
    
    def _generate_html_report(self, findings, output_dir, timestamp):
        # HTML template
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report - Smart Code Triage</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 10px; 
            box-shadow: 0 0 20px rgba(0,0,0,0.1); 
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            text-align: center;
        }
        .header h1 { 
            margin: 0; 
            font-size: 2.5em; 
        }
        .stats { 
            display: flex; 
            justify-content: space-around; 
            padding: 20px; 
            background: #f8f9fa; 
            border-bottom: 1px solid #eee;
        }
        .stat-box { 
            text-align: center; 
        }
        .stat-value { 
            font-size: 2em; 
            font-weight: bold; 
        }
        .score-critical { color: #ff0000; }
        .score-high { color: #ff6600; }
        .score-medium { color: #ffcc00; }
        .score-low { color: #00cc00; }
        .findings-container { 
            padding: 20px; 
        }
        .finding { 
            border: 1px solid #ddd; 
            margin: 15px 0; 
            padding: 20px; 
            border-radius: 8px; 
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: transform 0.2s;
        }
        .finding:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .critical { border-left: 6px solid #ff0000; }
        .high { border-left: 6px solid #ff6600; }
        .medium { border-left: 6px solid #ffcc00; }
        .low { border-left: 6px solid #00cc00; }
        .finding h3 { 
            margin-top: 0; 
            color: #333;
        }
        .finding-details { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 10px; 
            margin-top: 10px;
        }
        .detail-item { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 5px;
        }
        .code-snippet { 
            background: #2d2d2d; 
            color: #f8f8f2; 
            padding: 15px; 
            border-radius: 5px; 
            font-family: 'Courier New', monospace; 
            margin-top: 10px;
            overflow-x: auto;
        }
        .footer { 
            text-align: center; 
            padding: 20px; 
            background: #f8f9fa; 
            border-top: 1px solid #eee;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Vulnerability Report</h1>
            <p>Smart Code Vulnerability Triage System</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{{ total_findings }}</div>
                <div>Total Findings</div>
            </div>
            <div class="stat-box">
                <div class="stat-value score-{{ risk_level.lower() }}">{{ "%.1f"|format(triage_score) }}/10</div>
                <div>Triage Score</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ timestamp }}</div>
                <div>Scan Time</div>
            </div>
        </div>
        
        <div class="findings-container">
            {% for finding in findings %}
            <div class="finding {{ finding.severity.lower() }}">
                <h3>{{ finding.type.replace('_', ' ').title() }}</h3>
                <p><strong>Description:</strong> {{ finding.description }}</p>
                
                <div class="finding-details">
                    <div class="detail-item">
                        <strong>Severity:</strong> {{ finding.severity }}
                    </div>
                    <div class="detail-item">
                        <strong>File:</strong> {{ finding.file }}
                    </div>
                    <div class="detail-item">
                        <strong>Line:</strong> {{ finding.line }}
                    </div>
                </div>
                
                {% if finding.code_snippet %}
                <div class="code-snippet">{{ finding.code_snippet }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by Smart Code Vulnerability Triage System</p>
        </div>
    </div>
</body>
</html>"""
        
        # Determine risk level based on triage score
        triage_score = self.calculate_triage_score(findings)
        if triage_score >= 8:
            risk_level = "Critical"
        elif triage_score >= 6:
            risk_level = "High"
        elif triage_score >= 4:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        template = Template(html_template)
        html_content = template.render(
            timestamp=timestamp,
            total_findings=len(findings),
            triage_score=triage_score,
            risk_level=risk_level,
            findings=findings
        )
        
        report_path = os.path.join(output_dir, f"{timestamp}_vulnerability_report.html")
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return report_path