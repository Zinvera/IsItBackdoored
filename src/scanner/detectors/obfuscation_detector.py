import re
import base64
import math
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class ObfuscationDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        findings.extend(self._detect_base64_with_exec(file_path, lines))
        findings.extend(self._detect_hex_encoding(file_path, lines))
        findings.extend(self._detect_high_entropy(file_path, lines))
        findings.extend(self._detect_unicode_tricks(file_path, lines))
        findings.extend(self._detect_string_reversals(file_path, lines))
        findings.extend(self._detect_variable_functions(file_path, lines))
        
        return findings
        
    def _detect_base64_with_exec(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        patterns = [
            (r'base64\.b64decode.*(?:eval|exec|compile)', 'Base64 decode with execution'),
            (r'atob.*eval', 'Base64 decode with eval (JS)'),
            (r'base64_decode.*eval', 'Base64 decode with eval (PHP)'),
            (r'fromCharCode.*eval', 'CharCode obfuscation with eval'),
            (r'unescape.*eval', 'Unescape with eval'),
            (r'decodeURIComponent.*eval', 'URI decode with eval'),
            (r'Buffer\.from\([^)]*base64[^)]*\).*exec', 'Node.js Buffer decode with exec'),
            (r'codecs\.decode.*exec', 'Python codecs decode with exec'),
            (r'binascii\..*decode.*exec', 'Binary decode with exec'),
            (r'rot13|rot_13.*(?:eval|exec)', 'ROT13 with execution'),
            (r'str_rot13.*eval', 'PHP ROT13 with eval'),
            (r'gzinflate.*eval', 'PHP gzinflate with eval'),
            (r'gzuncompress.*eval', 'PHP gzuncompress with eval'),
            (r'str_replace.*eval', 'String replacement with eval'),
            (r'preg_replace.*\/e', 'PHP preg_replace /e modifier'),
            (r'create_function', 'PHP create_function (deprecated/dangerous)'),
            (r'assert.*\$', 'PHP assert with variable'),
            (r'eval\s*\(\s*(?:str_replace|base64_decode|gzinflate)', 'Nested obfuscation with eval')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    confidence = 90
                    if 'eval' in line and 'base64' in line:
                        confidence = 95
                    if line.count('decode') > 1 or line.count('eval') > 1:
                        confidence = 98
                        
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=confidence,
                        title=desc,
                        description=f'Detected {desc.lower()} which is commonly used to hide malicious code',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Review the decoded content. Avoid dynamic code execution with encoded strings.',
                        detector='ObfuscationDetector'
                    ))
                    
        return findings
        
    def _detect_hex_encoding(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            hex_matches = re.findall(r'\\x[0-9a-fA-F]{2}', line)
            if len(hex_matches) > 15:
                confidence = min(95, 70 + len(hex_matches) // 5)
                
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=confidence,
                    title='Heavy hex encoding detected',
                    description=f'Found {len(hex_matches)} hex-encoded bytes',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Decode and review the hex string content',
                    detector='ObfuscationDetector'
                ))
            
            if re.search(r'0x[0-9a-fA-F]{16,}', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=70,
                    title='Long hex literal detected',
                    description='Very long hexadecimal literal may contain encoded data',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify the purpose of this hex data',
                    detector='ObfuscationDetector'
                ))
            
            chr_matches = re.findall(r'chr\s*\(\s*\d+\s*\)', line)
            if len(chr_matches) > 5:
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Character code obfuscation',
                    description=f'Found {len(chr_matches)} chr() calls to construct strings',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Decode the character sequence',
                    detector='ObfuscationDetector'
                ))
                
        return findings
        
    def _detect_high_entropy(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
                
            strings = re.findall(r'["\']([^"\']{50,})["\']', line)
            for s in strings:
                if re.search(r'^[a-zA-Z0-9+/=]+$', s) and len(s) > 50:
                    entropy = self._calculate_entropy(s)
                    if entropy > 5.0:
                        confidence = min(95, int((entropy - 5.0) * 50 + 70))
                        
                        findings.append(self.create_finding(
                            file_path=file_path,
                            line_number=line_num,
                            severity='MEDIUM',
                            confidence=confidence,
                            title='High entropy string detected',
                            description=f'String with entropy {entropy:.2f} may be encoded data',
                            code_snippet=self.get_code_snippet(lines, line_num),
                            recommendation='Verify if this is legitimate encoded data',
                            detector='ObfuscationDetector'
                        ))
                    
        return findings
        
    def _detect_unicode_tricks(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if line_num == 1 and '\ufeff' in line:
                continue
            
            if re.search(r'[\u200b-\u200f\u202a-\u202e]', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Unicode obfuscation: Zero-width/directional characters',
                    description='Detected zero-width or directional unicode characters',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Review for homograph attacks or hidden characters',
                    detector='ObfuscationDetector'
                ))
            
            if re.search(r'[а-яА-Я]', line):
                if re.search(r'[a-zA-Z]', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=85,
                        title='Unicode obfuscation: Cyrillic lookalike characters',
                        description='Mixed Latin and Cyrillic characters (homograph attack)',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Check for homograph attacks using lookalike characters',
                        detector='ObfuscationDetector'
                    ))
            
            if re.search(r'\\u[0-9a-fA-F]{4}', line):
                unicode_count = len(re.findall(r'\\u[0-9a-fA-F]{4}', line))
                if unicode_count > 10:
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=75,
                        title='Heavy unicode escaping',
                        description=f'Found {unicode_count} unicode escape sequences',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Decode unicode sequences to reveal actual content',
                        detector='ObfuscationDetector'
                    ))
                    
        return findings
        
    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0
        entropy = 0
        for x in range(256):
            p_x = s.count(chr(x)) / len(s)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _detect_string_reversals(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'[::-1].*(?:eval|exec|compile)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=90,
                    title='String reversal with code execution',
                    description='Reversed string used with eval/exec to hide code',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Decode the reversed string and review',
                    detector='ObfuscationDetector'
                ))
            
            if re.search(r'strrev\s*\(.*(?:eval|assert)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=90,
                    title='PHP strrev with code execution',
                    description='strrev() used to obfuscate code before execution',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Decode and inspect the reversed string',
                    detector='ObfuscationDetector'
                ))
                
        return findings
    
    def _detect_variable_functions(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'\$[a-zA-Z_]+\s*\([^)]*\$_', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='PHP variable function with user input',
                    description='Variable function call with user-supplied data',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Avoid variable functions with user input',
                    detector='ObfuscationDetector'
                ))
            
            if re.search(r'\$\{[^}]+\}\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Dynamic function call',
                    description='Function name constructed dynamically',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use explicit function calls',
                    detector='ObfuscationDetector'
                ))
                
        return findings
