from abc import ABC, abstractmethod
from typing import List
from src.models.finding import Finding

class BaseDetector(ABC):
    @abstractmethod
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        pass
        
    def create_finding(self, file_path: str, line_number: int, severity: str,
                      confidence: float, title: str, description: str,
                      code_snippet: str, recommendation: str, detector: str) -> Finding:
        return Finding(
            file_path=file_path,
            line_number=line_number,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            code_snippet=code_snippet,
            recommendation=recommendation,
            detector=detector
        )
        
    def get_code_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        snippet_lines = []
        
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{lines[i]}")
            
        return '\n'.join(snippet_lines)
