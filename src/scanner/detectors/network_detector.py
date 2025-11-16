import re
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class NetworkDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        findings.extend(self._detect_hardcoded_ips(file_path, lines))
        findings.extend(self._detect_suspicious_domains(file_path, lines))
        findings.extend(self._detect_raw_sockets(file_path, lines))
        findings.extend(self._detect_data_exfiltration(file_path, lines))
        findings.extend(self._detect_port_binding(file_path, lines))
        
        return findings
        
    def _detect_hardcoded_ips(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*|\*', line):
                continue
            
            if re.search(r'(127\.0\.0\.1|localhost|0\.0\.0\.0|255\.255\.255)', line):
                continue
            
            if re.search(r'version|example|test|sample|\.\.\.', line, re.IGNORECASE):
                continue
                
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                octets = [int(x) for x in ip.split('.')]
                if all(0 <= x <= 255 for x in octets):
                    if octets[0] in [10, 172, 192, 169]:
                        continue
                    
                    if octets == [8, 8, 8, 8] or octets == [1, 1, 1, 1]:
                        continue
                        
                    confidence = 70
                    if any(keyword in line.lower() for keyword in ['connect', 'socket', 'send', 'recv']):
                        confidence = 85
                        
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=confidence,
                        title=f'Hardcoded IP address: {ip}',
                        description='Hardcoded IP address detected',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use configuration files for IP addresses',
                        detector='NetworkDetector'
                    ))
                    
        return findings
        
    def _detect_suspicious_domains(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.pw']
        domain_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*|\*', line):
                continue
            
            domains = re.findall(domain_pattern, line)
            for domain in domains:
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=70,
                        title=f'Suspicious domain TLD: {domain}',
                        description='Domain uses a TLD commonly associated with malicious activity',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify the legitimacy of this domain',
                        detector='NetworkDetector'
                    ))
            
            if re.search(r'pastebin\.com|hastebin\.com|paste\.ee|dpaste\.com', line, re.IGNORECASE):
                if not re.search(r'^\s*\/\/|^\s*\*|example|test', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=75,
                        title='Pastebin service detected',
                        description='Code references pastebin services',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify the purpose of accessing pastebin services',
                        detector='NetworkDetector'
                    ))
            
            if re.search(r'\.onion\b', line):
                if not re.search(r'^\s*\/\/|^\s*\*', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=90,
                        title='Tor hidden service (.onion)',
                        description='Reference to Tor hidden service',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Investigate the purpose of Tor network usage',
                        detector='NetworkDetector'
                    ))
            
            if re.search(r'ngrok\.io|serveo\.net|localhost\.run', line):
                if not re.search(r'^\s*\/\/|^\s*\*', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=70,
                        title='Tunneling service detected',
                        description='Reference to tunneling service',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify legitimate use of tunneling services',
                        detector='NetworkDetector'
                    ))
                    
        return findings
        
    def _detect_raw_sockets(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'#.*import|#.*test|#.*example', line, re.IGNORECASE):
                continue
                
            if re.search(r'socket\.socket\s*\(.*SOCK_RAW', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Raw socket creation',
                    description='Raw socket usage detected which can be used for packet manipulation',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify if raw socket access is necessary',
                    detector='NetworkDetector'
                ))
            
            if re.search(r'socket\.AF_PACKET', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Packet socket usage',
                    description='AF_PACKET socket for packet-level access',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify packet-level access requirement',
                    detector='NetworkDetector'
                ))
            
            if re.search(r'\breverse_tcp\b|\breverse_shell\b', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Reverse shell indicator',
                    description='Reverse shell pattern detected',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Investigate reverse shell usage immediately',
                    detector='NetworkDetector'
                ))
            
            if re.search(r'\bbind_tcp\b|\bbind_shell\b', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Bind shell indicator',
                    description='Bind shell pattern detected',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Investigate bind shell usage immediately',
                    detector='NetworkDetector'
                ))
                    
        return findings

    def _detect_data_exfiltration(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'(?:requests\.post|urllib\.request\.urlopen|curl).*(?:password|token|key|secret|credential)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Potential data exfiltration',
                    description='Sensitive data being sent over network',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify destination and encryption',
                    detector='NetworkDetector'
                ))
            
            if re.search(r'(?:socket\.send|sendall|write).*(?:os\.environ|getenv)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=80,
                    title='Environment variable exfiltration',
                    description='Environment variables being sent over socket',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Review what data is being transmitted',
                    detector='NetworkDetector'
                ))
                
        return findings
    
    def _detect_port_binding(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'bind\s*\(\s*[^)]*(?:0\.0\.0\.0|INADDR_ANY)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=75,
                    title='Socket binding to all interfaces',
                    description='Server listening on 0.0.0.0 (all interfaces)',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Bind to specific interface if possible',
                    detector='NetworkDetector'
                ))
            
            if re.search(r'listen\s*\(\s*\d+\s*\)', line):
                if re.search(r'(?:4444|5555|6666|7777|8888|9999|31337)', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=80,
                        title='Suspicious port number',
                        description='Listening on commonly used backdoor port',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify legitimate use of this port',
                        detector='NetworkDetector'
                    ))
                
        return findings
