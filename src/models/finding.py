from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    file_path: str
    line_number: int
    severity: str
    confidence: float
    title: str
    description: str
    code_snippet: str
    recommendation: str
    detector: str
    
    def to_dict(self):
        return {
            'file_path': self.file_path,
            'line_number': self.line_number,
            'severity': self.severity,
            'confidence': self.confidence,
            'title': self.title,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'recommendation': self.recommendation,
            'detector': self.detector
        }
