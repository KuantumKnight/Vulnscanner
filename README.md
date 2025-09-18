# 🔍 Vulnscanner
A comprehensive static analysis tool that automatically detects, scores, and prioritizes security vulnerabilities in Python and JavaScript code using regex patterns, AST analysis, and optional AI integration.
<img width="1280" height="709" alt="image" src="https://github.com/user-attachments/assets/c77f28ab-c414-48ab-b8ba-9ffada4aac91" />

## 🌟 *Features*

- *Multi-language Support*: Python and JavaScript vulnerability detection
- *Dual Analysis Engine*: Regex pattern matching + AST-based deep analysis
- *Intelligent Triage*: Automated severity scoring and prioritization
- *AI Integration*: Optional VulBERTa model for probabilistic vulnerability scoring
- *Rich Reporting*: JSON and HTML report generation with detailed findings
- *Hackathon-Ready*: Modular design, easy setup, and demo-friendly output

## 🚀 *Quick Start*

### *Prerequisites*
- Python 3.8+
- pip package manager

### Installation
```bash
git clone https://github.com/KuantumKnight/Vulnscanner.git
cd Vulnscanner
pip install -r requirements.txt
python api.py
```
### Usage
```bash
# Basic scan
python main.py --scan ./samples/

# Generate detailed HTML report
python main.py --scan ./samples/ --report-format html
```
### 🛠 How It Works
#### Detection Methods
- *Regex Pattern Matching:*  Fast pattern detection for common vulnerabilities
- *AST Analysis:*  Deep code structure analysis for complex vulnerabilities
- *AI Enhancement:*  Optional machine learning scoring for improved accuracy
### Supported Vulnerabilities
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Hardcoded Secrets
- Insecure Deserialization
- Weak Cryptography
- Dangerous Function Calls

## 🎯 Use Cases
- *Security Code Reviews:* Automated pre-commit security checks
- *CI/CD Integration:* Pipeline security scanning
- *Educational Tool:* Teaching secure coding practices
- *Hackathon Projects:* Rapid security assessment for prototypes
## 👥 Team
- Sarvesh M (25BCE5743)
- Jaydon JP (25BCE5725)
- Narain R K (25BCE1277)
- Saineeraj Saravanan (25BCE1066)
- Hariharan H (25BCE1311)
## 🚀 Future Enhancements
### Short Term
- IDE Plugin (VS Code, PyCharm)
- GitHub Actions Integration
- Live Dashboard with Real-time Monitoring
- Docker Containerization
### Long Term
- Additional Language Support (Java, Go, C#)
- False Positive Reduction using ML
- Integration with Popular SAST Tools
- Cloud Deployment Options

## 🙏 Acknowledgments

Inspired by popular SAST tools like Bandit and ESLint
Powered by Python's AST module and regex capabilities
