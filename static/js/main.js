document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scan-btn');
    const codeEditor = document.getElementById('code-editor');
    const loading = document.getElementById('loading');
    const resultsSection = document.getElementById('results-section');
    
    scanBtn.addEventListener('click', async function() {
        if (!codeEditor.value.trim()) {
            showToast('Please enter some code to scan', 'error');
            return;
        }
        
        showLoading(true);
        
        try {
            // Simple mock response for now - replace with actual API call
            setTimeout(() => {
                displayResults({
                    triage_score: 8.5,
                    total_findings: 2,
                    risk_level: 'High',
                    findings: [
                        {
                            type: 'HARDCODED_SECRET',
                            description: 'Hardcoded API key detected',
                            severity: 'Critical',
                            line: 2,
                            code_snippet: 'API_KEY = "sk-1234567890abcdef1234567890abcdef"'
                        },
                        {
                            type: 'DANGEROUS_EVAL',
                            description: 'Use of eval() detected',
                            severity: 'High',
                            line: 5,
                            code_snippet: 'return eval(user_input)'
                        }
                    ]
                });
                showLoading(false);
            }, 1500);
            
        } catch (error) {
            showToast('Error scanning code: ' + error.message, 'error');
            showLoading(false);
        }
    });
    
    function showLoading(show) {
        if (show) {
            loading.style.display = 'block';
            scanBtn.disabled = true;
        } else {
            loading.style.display = 'none';
            scanBtn.disabled = false;
        }
    }
    
    function displayResults(result) {
        document.getElementById('score-badge').textContent = `${result.triage_score.toFixed(1)}/10`;
        document.getElementById('total-findings').textContent = result.total_findings;
        document.getElementById('risk-level').textContent = result.risk_level;
        
        const findingsList = document.getElementById('findings-list');
        findingsList.innerHTML = '';
        
        result.findings.forEach(finding => {
            const findingElement = document.createElement('div');
            findingElement.className = `finding ${finding.severity.toLowerCase()}`;
            findingElement.innerHTML = `
                <div class="finding-header">
                    <h4 class="finding-title">${finding.type.replace(/_/g, ' ')}</h4>
                    <span class="finding-severity severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Description:</strong> ${finding.description}</p>
                    <p><strong>Location:</strong> Line ${finding.line}</p>
                </div>
                <div class="finding-code">${finding.code_snippet}</div>
            `;
            findingsList.appendChild(findingElement);
        });
        
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
        showToast(`Scan complete! Found ${result.total_findings} issues.`, 'success');
    }
    
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        const toastContainer = document.getElementById('toast-container');
        toastContainer.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
});
