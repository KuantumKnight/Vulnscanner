# 🔍 Smart Code Vulnerability Triage System

A comprehensive static analysis tool that automatically detects, scores, and prioritizes security vulnerabilities in Python and JavaScript code using regex patterns, AST analysis, and optional AI integration.

## 🌟 Features

- **Multi-language Support**: Python and JavaScript vulnerability detection
- **Dual Analysis Engine**: Regex pattern matching + AST-based deep analysis
- **Intelligent Triage**: Automated severity scoring and prioritization
- **AI Integration**: Optional VulBERTa model for probabilistic vulnerability scoring
- **Rich Reporting**: JSON and HTML report generation with detailed findings
- **Hackathon-Ready**: Modular design, easy setup, and demo-friendly output

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation
```bash
git clone https://github.com/KuantumKnight/Vulnscanner.git
cd Vulnscanner
pip install -r requirements.txt
pyhton api.py
```
### Usage
```bash
# Basic scan
python main.py --scan ./samples/

# Scan with AI integration
python main.py --scan ./samples/ --ai

# Generate detailed HTML report
python main.py --scan ./samples/ --report-format html
```
###🛠️ How It Works
Detection Methods
Regex Pattern Matching: Fast pattern detection for common vulnerabilities
AST Analysis: Deep code structure analysis for complex vulnerabilities
AI Enhancement: Optional machine learning scoring for improved accuracy
Supported Vulnerabilities
SQL Injection
Cross-Site Scripting (XSS)
Path Traversal
Command Injection
Hardcoded Secrets
Insecure Deserialization
Weak Cryptography
Dangerous Function Calls

###📊 Sample Output
```bash
🔍 Smart Code Vulnerability Triage System
Scanning: ./samples/vulnerable_python.py

🚨 CRITICAL: Hardcoded API key detected (Line 15)
🚨 HIGH: SQL Injection via string concatenation (Line 23)
⚠️  MEDIUM: Weak cryptographic algorithm (Line 31)

Triage Score: 8.2/10 (High Risk)

Report generated: reports/2024-01-15_vulnerability_report.json
```
###🏗️ Architecture
```bash
Input Code → [Regex Scanner] → [AST Analyzer] → [Triage Engine] → [Reporter] → Output
                    ↓              ↓              ↓              ↓
              Pattern Matching  Deep Analysis  Risk Scoring   JSON/HTML
                    ↓              ↓              ↓              ↓
                            [AI Integration (Optional)]
                                    ↓
                              Enhanced Scoring
```
🎯 Use Cases
Security Code Reviews: Automated pre-commit security checks
CI/CD Integration: Pipeline security scanning
Educational Tool: Teaching secure coding practices
Hackathon Projects: Rapid security assessment for prototypes
👥 Team
Lead Developer: [Your Name]
Security Researcher: [Team Member 1]
AI/ML Specialist: [Team Member 2]
UI/UX Designer: [Team Member 3]
🚀 Future Enhancements
Short Term
IDE Plugin (VS Code, PyCharm)
GitHub Actions Integration
Live Dashboard with Real-time Monitoring
Docker Containerization
Long Term
Additional Language Support (Java, Go, C#)
False Positive Reduction using ML
Integration with Popular SAST Tools
Cloud Deployment Options

###🙏 Acknowledgments

Inspired by popular SAST tools like Bandit and ESLint
Powered by Python's AST module and regex capabilities
AI integration concept based on VulBERT research

```bash
smart-code-triage/
├── README.md
├── requirements.txt
├── main.py
├── config/
│   └── settings.py
├── rules/
│   ├── __init__.py
│   ├── regex_rules.py
│   └── severity_weights.py
├── analyzers/
│   ├── __init__.py
│   ├── regex_scanner.py
│   ├── ast_analyzer.py
│   └── javascript_analyzer.py
├── core/
│   ├── __init__.py
│   ├── scanner.py
│   ├── triage_engine.py
│   └── reporter.py
├── ai_integration/
│   ├── __init__.py
│   └── vulberta_integration.py
├── templates/
│   └── report_template.html
├── reports/
│   └── .gitkeep
├── samples/
│   ├── vulnerable_python.py
│   └── vulnerable_javascript.js
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_analyzers.py
└── utils/
    ├── __init__.py
    └── helpers.py
```


