from dataclasses import dataclass, field
from typing import List
from .finding import Finding

@dataclass
class ScanResult:
    total_files: int = 0
    scanned_files: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
    
    def get_risk_score(self) -> int:
        if not self.findings:
            return 0
        
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2
        }
        
        total_score = sum(
            severity_weights.get(f.severity, 0) * (f.confidence / 100)
            for f in self.findings
        )
        
        return min(100, int(total_score))
    
    def get_findings_by_severity(self):
        result = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            result[finding.severity] = result.get(finding.severity, 0) + 1
        return result
    
    def get_findings_by_detector(self):
        result = {}
        for finding in self.findings:
            result[finding.detector] = result.get(finding.detector, 0) + 1
        return result
