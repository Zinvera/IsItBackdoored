import re
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class FileOperationDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        findings.extend(self._detect_sensitive_file_writes(file_path, lines))
        findings.extend(self._detect_secret_reads(file_path, lines))
        findings.extend(self._detect_file_deletion(file_path, lines))
        findings.extend(self._detect_registry_access(file_path, lines))
        findings.extend(self._detect_environment_manipulation(file_path, lines))
        findings.extend(self._detect_log_tampering(file_path, lines))
        findings.extend(self._detect_persistence_mechanisms(file_path, lines))
        
        return findings
        
    def _detect_sensitive_file_writes(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        sensitive_paths = [
            (r'/etc/', 'System configuration directory'),
            (r'\.ssh/', 'SSH configuration directory'),
            (r'/root/', 'Root user directory'),
            (r'\.bashrc|\.bash_profile|\.zshrc', 'Shell configuration files'),
            (r'authorized_keys', 'SSH authorized keys'),
            (r'/usr/bin/|/usr/local/bin/', 'System binary directories')
        ]
        
        write_patterns = [
            r'open\s*\([^)]*["\']([^"\']+)["\'][^)]*["\']w',
            r'fopen\s*\([^)]*["\']([^"\']+)["\'][^)]*["\']w',
            r'file_put_contents\s*\([^)]*["\']([^"\']+)["\']',
            r'FileWriter\s*\([^)]*["\']([^"\']+)["\']'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for write_pattern in write_patterns:
                matches = re.findall(write_pattern, line)
                for match in matches:
                    for path_pattern, desc in sensitive_paths:
                        if re.search(path_pattern, match):
                            findings.append(self.create_finding(
                                file_path=file_path,
                                line_number=line_num,
                                severity='CRITICAL',
                                confidence=90,
                                title=f'Write to sensitive location: {desc}',
                                description=f'Detected write operation to {match} which is a sensitive system location',
                                code_snippet=self.get_code_snippet(lines, line_num),
                                recommendation='Verify if this write operation is legitimate and properly authorized',
                                detector='FileOperationDetector'
                            ))
                            
        return findings
        
    def _detect_secret_reads(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        secret_patterns = [
            (r'\.env', 'Environment file'),
            (r'\.aws/credentials', 'AWS credentials'),
            (r'\.ssh/id_rsa', 'SSH private key'),
            (r'password|passwd|secret|token|api[_-]?key', 'Credential keywords')
        ]
        
        read_patterns = [
            r'open\s*\([^)]*["\']([^"\']+)["\'][^)]*["\']r',
            r'fopen\s*\([^)]*["\']([^"\']+)["\'][^)]*["\']r',
            r'file_get_contents\s*\([^)]*["\']([^"\']+)["\']',
            r'readFile\s*\([^)]*["\']([^"\']+)["\']'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for read_pattern in read_patterns:
                matches = re.findall(read_pattern, line, re.IGNORECASE)
                for match in matches:
                    for secret_pattern, desc in secret_patterns:
                        if re.search(secret_pattern, match, re.IGNORECASE):
                            findings.append(self.create_finding(
                                file_path=file_path,
                                line_number=line_num,
                                severity='HIGH',
                                confidence=80,
                                title=f'Reading sensitive file: {desc}',
                                description=f'Detected read operation on {match} which may contain secrets',
                                code_snippet=self.get_code_snippet(lines, line_num),
                                recommendation='Ensure proper access controls and verify the necessity of reading this file',
                                detector='FileOperationDetector'
                            ))
                            
        return findings
        
    def _detect_file_deletion(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'shutil\.rmtree', line):
                if re.search(r'input|request|argv|\$_GET|\$_POST', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=85,
                        title='Recursive directory deletion with user input',
                        description='rmtree with user-controlled path',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Validate and sanitize paths before deletion',
                        detector='FileOperationDetector'
                    ))
                    
        return findings

    def _detect_registry_access(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        registry_patterns = [
            (r'winreg|_winreg', 'Windows Registry access'),
            (r'HKEY_LOCAL_MACHINE|HKLM', 'HKLM registry access'),
            (r'HKEY_CURRENT_USER|HKCU', 'HKCU registry access'),
            (r'RegOpenKey|RegSetValue|RegDeleteKey', 'Registry manipulation'),
            (r'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 'Startup registry key')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in registry_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = 'HIGH' if 'Run' in line or 'Delete' in line else 'MEDIUM'
                    confidence = 85 if 'Run' in line else 70
                    
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity=severity,
                        confidence=confidence,
                        title=desc,
                        description='Windows Registry access detected which may be used for persistence',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify the necessity of registry modifications',
                        detector='FileOperationDetector'
                    ))
                    
        return findings
    
    def _detect_environment_manipulation(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        env_patterns = [
            (r'os\.environ\[.*\]\s*=', 'Environment variable modification'),
            (r'putenv\s*\(', 'putenv usage'),
            (r'setenv\s*\(', 'setenv usage'),
            (r'\$_ENV\[.*\]\s*=', 'PHP environment modification'),
            (r'process\.env\[.*\]\s*=', 'Node.js environment modification'),
            (r'System\.setProperty', 'Java system property modification')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in env_patterns:
                if re.search(pattern, line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=70,
                        title=desc,
                        description='Environment variable manipulation detected',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify the purpose of environment modifications',
                        detector='FileOperationDetector'
                    ))
                    
        return findings

    def _detect_log_tampering(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'(?:rm|unlink|delete).*\.log', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=70,
                    title='Log file deletion',
                    description='Deleting log files may hide evidence',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify legitimate log rotation',
                    detector='FileOperationDetector'
                ))
            
            if re.search(r'truncate.*\.log|>.*\.log', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=65,
                    title='Log file truncation',
                    description='Clearing log files',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Ensure proper log management',
                    detector='FileOperationDetector'
                ))
                
        return findings
    
    def _detect_persistence_mechanisms(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'crontab|/etc/cron|\.bashrc|\.bash_profile|\.zshrc', line):
                if re.search(r'write|append|>>|echo.*>', line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=85,
                        title='Persistence mechanism',
                        description='Modifying startup/cron files for persistence',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Verify legitimate system configuration',
                        detector='FileOperationDetector'
                    ))
            
            if re.search(r'/etc/rc\.local|/etc/init\.d|systemd.*enable', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='System service persistence',
                    description='Creating or modifying system services',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Review service configuration',
                    detector='FileOperationDetector'
                ))
                
        return findings
