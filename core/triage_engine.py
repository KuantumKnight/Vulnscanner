from rules.severity_weights import SEVERITY_WEIGHTS

class TriageEngine:
    def __init__(self):
        self.severity_weights = SEVERITY_WEIGHTS
    
    def calculate_triage_score(self, findings):
        if not findings:
            return 0.0
            
        total_weight = sum(self.severity_weights.get(f.get('severity', 'Low'), 1) for f in findings)
        max_possible = len(findings) * max(self.severity_weights.values())
        
        return (total_weight / max_possible) * 10 if max_possible > 0 else 0.0
    
    def prioritize_findings(self, findings):
        # Sort by severity (Critical -> High -> Medium -> Low)
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        return sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'Low'), 0), reverse=True)