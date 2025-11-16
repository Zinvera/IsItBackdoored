import re
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class CryptoDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        findings.extend(self._detect_weak_crypto(file_path, lines))
        findings.extend(self._detect_hardcoded_keys(file_path, lines))
        findings.extend(self._detect_custom_crypto(file_path, lines))
        findings.extend(self._detect_crypto_mining(file_path, lines))
        
        return findings
        
    def _detect_weak_crypto(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*|\*', line):
                continue
            
            if re.search(r'\bmd5\s*\(', line, re.IGNORECASE):
                if not re.search(r'checksum|hash|fingerprint|etag', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=85,
                        title='Weak algorithm: MD5',
                        description='MD5 is cryptographically broken',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use SHA-256 or SHA-3 for security purposes',
                        detector='CryptoDetector'
                    ))
            
            if re.search(r'\bsha1\s*\(', line, re.IGNORECASE):
                if not re.search(r'git|legacy|compatibility', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=80,
                        title='Weak algorithm: SHA1',
                        description='SHA1 is deprecated for security use',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use SHA-256 or SHA-3',
                        detector='CryptoDetector'
                    ))
            
            if re.search(r'\bDES\b|DES\.new|DES_', line):
                if not re.search(r'describe|design|desktop|destination', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=90,
                        title='Weak algorithm: DES',
                        description='DES has a small key size and is broken',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use AES instead',
                        detector='CryptoDetector'
                    ))
                    
        return findings
        
    def _detect_hardcoded_keys(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        key_patterns = [
            (r'(?:key|password|secret)\s*=\s*["\']([a-zA-Z0-9+/=]{16,})["\']', 'Hardcoded key/password'),
            (r'(?:api[_-]?key|token)\s*=\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Hardcoded API key/token'),
            (r'-----BEGIN (?:RSA |)PRIVATE KEY-----', 'Embedded private key')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in key_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=85,
                        title=desc,
                        description='Hardcoded cryptographic keys or secrets detected in source code',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Move secrets to environment variables or secure key management systems',
                        detector='CryptoDetector'
                    ))
                    
        return findings
        
    def _detect_custom_crypto(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        is_code = file_ext in ['py', 'js', 'php', 'go', 'java', 'c', 'cpp', 'cc', 'cxx']
        
        if not is_code:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*|\*', line):
                continue
            
            if re.search(r'\bdef\s+(?:encrypt|decrypt|cipher)\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=65,
                    title='Custom encryption function',
                    description='Custom cryptographic implementation detected',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use established crypto libraries like OpenSSL, libsodium',
                    detector='CryptoDetector'
                ))
            
            if re.search(r'\b(?:xor|XOR)\s*\(.*(?:encrypt|decrypt|key)', line, re.IGNORECASE):
                if not re.search(r'^\s*\/\/|^\s*\*', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=70,
                        title='XOR-based encryption',
                        description='XOR encryption is weak and easily broken',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use proper encryption algorithms like AES',
                        detector='CryptoDetector'
                    ))
                    
        return findings

    def _detect_crypto_mining(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        mining_patterns = [
            (r'stratum\+tcp|stratum\+ssl', 'Stratum mining protocol'),
            (r'xmrig|cpuminer|ccminer|ethminer', 'Cryptocurrency miner'),
            (r'monero|bitcoin|ethereum.*mining', 'Crypto mining keywords'),
            (r'coinhive|cryptonight|randomx', 'Mining algorithms'),
            (r'pool\..*\.com:\d{4,5}', 'Mining pool connection'),
            (r'wallet.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 'Bitcoin wallet address'),
            (r'0x[a-fA-F0-9]{40}', 'Ethereum wallet address')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in mining_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=90,
                        title=f'Cryptocurrency mining: {desc}',
                        description='Detected cryptocurrency mining related code',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Remove unauthorized cryptocurrency mining code',
                        detector='CryptoDetector'
                    ))
                    
        return findings
