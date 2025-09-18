#  Vulnscanner
A comprehensive static analysis tool that automatically detects, scores, and prioritizes security vulnerabilities in Python and JavaScript code using regex patterns, AST analysis, and optional AI integration.
![WhatsApp Image 2025-09-18 at 05 21 32_1f96f373](https://github.com/user-attachments/assets/096925d4-3fa8-46c1-b872-5f607f85f921)
<img width="1734" height="927" alt="image" src="https://github.com/user-attachments/assets/f9e2e860-e2d7-4bfa-a01d-49aafc71930d" />



##  *Features*

- *Multi-language Support*: Python and JavaScript vulnerability detection
- *Dual Analysis Engine*: Regex pattern matching + AST-based deep analysis
- *Intelligent Triage*: Automated severity scoring and prioritization
- *AI Integration*: Optional VulBERTa model for probabilistic vulnerability scoring
- *Rich Reporting*: JSON and HTML report generation with detailed findings
- *Hackathon-Ready*: Modular design, easy setup, and demo-friendly output

##  *Quick Start*

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
###  How It Works
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

##  Use Cases
- *Security Code Reviews:* Automated pre-commit security checks
- *CI/CD Integration:* Pipeline security scanning
- *Educational Tool:* Teaching secure coding practices
- *Hackathon Projects:* Rapid security assessment for prototypes
##  Team
- Sarvesh M (25BCE5743)
- Jaydon JP (25BCE5725)
- Narain R K (25BCE1277)
- Saineeraj Saravanan (25BCE1066)
- Hariharan H (25BCE1311)
##  Future Enhancements
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

##  Acknowledgments

Inspired by popular SAST tools like Bandit and ESLint
Powered by Python's AST module and regex capabilities




