import re
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class SuspiciousPatternDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        findings.extend(self._detect_dangerous_functions(file_path, lines))
        findings.extend(self._detect_sql_injection(file_path, lines))
        findings.extend(self._detect_command_injection(file_path, lines))
        findings.extend(self._detect_deserialization(file_path, lines))
        findings.extend(self._detect_path_traversal(file_path, lines))
        findings.extend(self._detect_xxe(file_path, lines))
        findings.extend(self._detect_ssrf(file_path, lines))
        findings.extend(self._detect_timing_attacks(file_path, lines))
        findings.extend(self._detect_anti_debugging(file_path, lines))
        findings.extend(self._detect_process_injection(file_path, lines))
        
        return findings

    def _detect_dangerous_functions(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        is_php = file_ext in ['php', 'php3', 'php4', 'php5', 'phtml']
        is_python = file_ext in ['py', 'pyw']
        is_js = file_ext in ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'\beval\s*\(', line):
                if is_python or is_js or is_php:
                    confidence = 85
                    if re.search(r'input|request|argv|\$_GET|\$_POST', line, re.IGNORECASE):
                        confidence = 98
                    if re.search(r'base64|decode|unescape', line, re.IGNORECASE):
                        confidence = 98
                        
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=confidence,
                        title='Dangerous function: eval()',
                        description='eval() can execute arbitrary code',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Avoid eval(). Use safer alternatives',
                        detector='SuspiciousPatternDetector'
                    ))
            
            if is_python and re.search(r'\bexec\s*\(', line) and not re.search(r'subprocess|execute|executor', line, re.IGNORECASE):
                confidence = 85
                if re.search(r'input|request|argv|\$_GET|\$_POST', line, re.IGNORECASE):
                    confidence = 98
                    
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=confidence,
                    title='Dangerous function: exec()',
                    description='exec() can execute arbitrary code',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Avoid exec(). Refactor to use safer alternatives',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_php and re.search(r'create_function\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='PHP create_function()',
                    description='create_function() is deprecated and dangerous in PHP',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use anonymous functions or closures instead',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_php and re.search(r'preg_replace.*["\'].*\/.*e["\']', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='preg_replace /e modifier',
                    description='The /e modifier allows code execution',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use preg_replace_callback instead',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_php and re.search(r'assert\s*\(.*\$_', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=90,
                    title='PHP assert() with user input',
                    description='assert() with user input can execute code',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Never use assert() with user-controlled data',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_python and re.search(r'__builtins__\[', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='__builtins__ manipulation',
                    description='Direct __builtins__ access can bypass restrictions',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Avoid manipulating __builtins__',
                    detector='SuspiciousPatternDetector'
                ))
                    
        return findings

    def _detect_sql_injection(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        is_web_lang = file_ext in ['php', 'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'go']
        
        if not is_web_lang:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%|\.format).*(?:request|input|argv|\$_GET|\$_POST)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='SQL injection: String concatenation with user input',
                    description='SQL query built with string concatenation and user input',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use parameterized queries or prepared statements',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=98,
                    title='SQL injection: Direct user input in query',
                    description='Database query with direct user input from superglobals',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use prepared statements with parameter binding',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'(?:execute|query)\s*\([^)]*f["\'].*SELECT.*\{', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=90,
                    title='SQL injection: f-string in SQL query',
                    description='SQL query using f-string formatting',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use parameterized queries instead of f-strings',
                    detector='SuspiciousPatternDetector'
                ))
                    
        return findings

    def _detect_command_injection(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        is_python = file_ext in ['py', 'pyw']
        is_php = file_ext in ['php', 'php3', 'php4', 'php5', 'phtml']
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if is_python and re.search(r'os\.system\s*\([^)]*(?:\+|%|f["\'])', line):
                if re.search(r'input|request|argv|\$_GET|\$_POST', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=95,
                        title='Command injection: os.system with user input',
                        description='os.system with string concatenation and user input',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use subprocess with argument list instead',
                        detector='SuspiciousPatternDetector'
                    ))
            
            if is_python and re.search(r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', line):
                if re.search(r'input|request|argv|\$_GET|\$_POST|\+|%|f["\']', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=95,
                        title='Command injection: subprocess with shell=True',
                        description='subprocess with shell=True and dynamic input',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Remove shell=True and use argument list',
                        detector='SuspiciousPatternDetector'
                    ))
            
            if is_php and re.search(r'(?:shell_exec|system|passthru|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=98,
                    title='Command injection: PHP shell function with user input',
                    description='PHP shell function with direct user input',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Sanitize input and use escapeshellarg()',
                    detector='SuspiciousPatternDetector'
                ))
                    
        return findings

    def _detect_deserialization(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        is_python = file_ext in ['py', 'pyw']
        is_php = file_ext in ['php', 'php3', 'php4', 'php5', 'phtml']
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*|^\s*import|^\s*from', line):
                continue
            
            if is_python and re.search(r'pickle\.loads?\s*\(', line):
                confidence = 80
                if re.search(r'request|input|recv|socket|\$_', line, re.IGNORECASE):
                    confidence = 95
                    
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=confidence,
                    title='Unsafe deserialization: pickle.load()',
                    description='Pickle deserialization can execute arbitrary code',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Avoid pickle for untrusted data. Use JSON instead',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_python and re.search(r'yaml\.load\s*\([^)]*\)', line) and not re.search(r'SafeLoader|safe_load', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Unsafe deserialization: yaml.load() without SafeLoader',
                    description='yaml.load() without SafeLoader can execute code',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use yaml.safe_load() instead',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_php and re.search(r'unserialize\s*\([^)]*\$_', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Unsafe deserialization: unserialize() with user input',
                    description='PHP unserialize() with user input can lead to RCE',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Avoid unserialize() with user data. Use JSON',
                    detector='SuspiciousPatternDetector'
                ))
            
            if is_python and re.search(r'marshal\.loads?\s*\(', line):
                if re.search(r'request|input|recv|\$_', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=95,
                        title='Unsafe deserialization: marshal.loads()',
                        description='marshal.loads() with untrusted data can execute code',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Never use marshal with untrusted data',
                        detector='SuspiciousPatternDetector'
                    ))
                    
        return findings
    
    def _detect_path_traversal(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'(?:open|read|write|include|require|file_get_contents)\s*\([^)]*(?:\.\./|\.\.\\)', line, re.IGNORECASE):
                if re.search(r'request|input|argv|\$_GET|\$_POST', line, re.IGNORECASE):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='HIGH',
                        confidence=90,
                        title='Path traversal with user input',
                        description='File operation with ../ and user input',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Validate paths and use os.path.abspath()',
                        detector='SuspiciousPatternDetector'
                    ))
                    
        return findings
    
    def _detect_xxe(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'<!ENTITY.*SYSTEM', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=90,
                    title='XXE: XML external entity declaration',
                    description='XML entity with SYSTEM keyword detected',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Disable external entity processing in XML parser',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'setFeature.*FEATURE.*false', line) and re.search(r'EXTERNAL|DTD', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='XXE: Disabled XML security features',
                    description='XML parser security features disabled',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Keep XML security features enabled',
                    detector='SuspiciousPatternDetector'
                ))
                    
        return findings
    
    def _detect_ssrf(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'^\s*#|^\s*\/\/|^\s*\/\*', line):
                continue
            
            if re.search(r'requests\.(?:get|post|put|delete)\s*\([^)]*(?:request\.|input\(|\$_GET|\$_POST)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='SSRF: HTTP request with user-controlled URL',
                    description='HTTP request using user-supplied URL',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Validate and whitelist allowed URLs/domains',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'urllib\.request\.urlopen\s*\([^)]*(?:request\.|input\(|\$_)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='SSRF: urlopen with user input',
                    description='urlopen() with user-controlled URL',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Validate URLs against whitelist',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'file_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=90,
                    title='SSRF: file_get_contents with user input',
                    description='PHP file_get_contents with user-supplied URL',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Validate and restrict allowed protocols',
                    detector='SuspiciousPatternDetector'
                ))
                    
        return findings

    def _detect_timing_attacks(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'sleep\s*\(\s*\d{2,}\s*\)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=70,
                    title='Long sleep duration',
                    description='Sleep for extended period may indicate timing attack or evasion',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify legitimate use of long sleep',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'time\.sleep.*random', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=65,
                    title='Random sleep timing',
                    description='Random sleep intervals may indicate evasion technique',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Review purpose of randomized delays',
                    detector='SuspiciousPatternDetector'
                ))
                
        return findings
    
    def _detect_anti_debugging(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Anti-debugging technique',
                    description='Code checks for debugger presence',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Legitimate software rarely needs debugger detection',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'sys\.gettrace|sys\.settrace', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=75,
                    title='Trace function manipulation',
                    description='Modifying Python trace function',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='May be used for anti-debugging or code hiding',
                    detector='SuspiciousPatternDetector'
                ))
                
        return findings
    
    def _detect_process_injection(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            if re.search(r'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread', line, re.IGNORECASE):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Process injection API',
                    description='Windows API for process injection detected',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Process injection is a common malware technique',
                    detector='SuspiciousPatternDetector'
                ))
            
            if re.search(r'ptrace.*PTRACE_POKETEXT|PTRACE_POKEDATA', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Linux process injection',
                    description='ptrace used for process memory manipulation',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Verify legitimate debugging purpose',
                    detector='SuspiciousPatternDetector'
                ))
                
        return findings
