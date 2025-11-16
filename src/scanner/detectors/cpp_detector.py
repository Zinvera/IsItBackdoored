import re
from typing import List
from .base_detector import BaseDetector
from src.models.finding import Finding

class CppDetector(BaseDetector):
    def detect(self, file_path: str, content: str, lines: List[str], tree) -> List[Finding]:
        findings = []
        
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        if file_ext not in ['c', 'cpp', 'cc', 'cxx', 'c++', 'h', 'hpp', 'hh', 'hxx']:
            return findings
        
        findings.extend(self._detect_buffer_overflows(file_path, lines))
        findings.extend(self._detect_memory_issues(file_path, lines))
        findings.extend(self._detect_format_string_vulns(file_path, lines))
        findings.extend(self._detect_integer_overflows(file_path, lines))
        findings.extend(self._detect_unsafe_functions(file_path, lines))
        findings.extend(self._detect_race_conditions(file_path, lines))
        
        return findings
    
    def _detect_buffer_overflows(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if re.search(r'\bstrcpy\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=90,
                    title='Unsafe function: strcpy()',
                    description='strcpy() does not check buffer bounds and can cause buffer overflow',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use strncpy() or strlcpy() with proper size checks',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bstrcat\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=90,
                    title='Unsafe function: strcat()',
                    description='strcat() does not check buffer bounds',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use strncat() or strlcat() with proper size checks',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bsprintf\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=85,
                    title='Unsafe function: sprintf()',
                    description='sprintf() does not check buffer bounds',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use snprintf() with proper size parameter',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bgets\s*\(', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=95,
                    title='Unsafe function: gets()',
                    description='gets() is extremely dangerous and deprecated',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use fgets() instead',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bscanf\s*\([^)]*%s', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=80,
                    title='Unsafe scanf with %s',
                    description='scanf() with %s can cause buffer overflow',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use width specifier like %99s or use fgets()',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bmemcpy\s*\([^)]*sizeof\s*\([^)]*\*', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=75,
                    title='Suspicious memcpy with sizeof pointer',
                    description='Using sizeof on pointer may not give expected size',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Ensure sizeof is used on the actual type, not pointer',
                    detector='CppDetector'
                ))
                
        return findings
    
    def _detect_memory_issues(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        deleted_vars = {}
        freed_vars = {}
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            delete_match = re.search(r'\bdelete\s+(\w+)', line)
            if delete_match:
                var_name = delete_match.group(1)
                if var_name in deleted_vars:
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=90,
                        title='Double free detected',
                        description=f'Variable "{var_name}" deleted twice',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Set pointer to nullptr after delete',
                        detector='CppDetector'
                    ))
                deleted_vars[var_name] = line_num
            
            free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                if var_name in freed_vars:
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='CRITICAL',
                        confidence=90,
                        title='Double free detected',
                        description=f'Variable "{var_name}" freed twice',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Set pointer to NULL after free',
                        detector='CppDetector'
                    ))
                freed_vars[var_name] = line_num
            
            if re.search(r'\bmalloc\s*\([^)]*\)', line):
                if not re.search(r'if\s*\(.*==\s*NULL\)|if\s*\(.*==\s*nullptr\)', '\n'.join(lines[line_num:line_num+3])):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='MEDIUM',
                        confidence=70,
                        title='Unchecked malloc return',
                        description='malloc() return value should be checked for NULL',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Always check if malloc returned NULL',
                        detector='CppDetector'
                    ))
            
            if re.search(r'\bnew\s+\w+(?:\[|\()', line):
                if not re.search(r'try\s*\{|catch\s*\(', '\n'.join(lines[max(0,line_num-5):line_num+5])):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity='LOW',
                        confidence=60,
                        title='Unchecked new allocation',
                        description='new can throw std::bad_alloc',
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation='Use try-catch or check for exceptions',
                        detector='CppDetector'
                    ))
                
        return findings
    
    def _detect_format_string_vulns(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if re.search(r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=85,
                    title='Format string vulnerability',
                    description='printf() with variable as format string',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use printf("%s", variable) instead',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bfprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='CRITICAL',
                    confidence=85,
                    title='Format string vulnerability',
                    description='fprintf() with variable as format string',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use fprintf(file, "%s", variable) instead',
                    detector='CppDetector'
                ))
                
        return findings
    
    def _detect_integer_overflows(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if re.search(r'\bmalloc\s*\([^)]*\*[^)]*\)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=75,
                    title='Potential integer overflow in malloc',
                    description='Multiplication in malloc size can overflow',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Check for overflow before multiplication or use calloc',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bnew\s+\w+\[[^]]*\*[^]]*\]', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='HIGH',
                    confidence=75,
                    title='Potential integer overflow in array allocation',
                    description='Multiplication in array size can overflow',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Validate size calculation before allocation',
                    detector='CppDetector'
                ))
                
        return findings
    
    def _detect_unsafe_functions(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        unsafe_funcs = [
            (r'\bstrtok\s*\(', 'strtok()', 'Not thread-safe', 'Use strtok_r() or strtok_s()', 'MEDIUM', 70),
            (r'\basctime\s*\(', 'asctime()', 'Not thread-safe', 'Use asctime_r() or strftime()', 'MEDIUM', 70),
            (r'\bctime\s*\(', 'ctime()', 'Not thread-safe', 'Use ctime_r() or strftime()', 'MEDIUM', 70),
            (r'\btmpnam\s*\(', 'tmpnam()', 'Race condition vulnerability', 'Use mkstemp() instead', 'HIGH', 80),
            (r'\btempnam\s*\(', 'tempnam()', 'Race condition vulnerability', 'Use mkstemp() instead', 'HIGH', 80),
            (r'\bsystem\s*\(', 'system()', 'Command injection risk', 'Use execve() or safer alternatives', 'HIGH', 85),
        ]
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            for pattern, func, desc, rec, severity, confidence in unsafe_funcs:
                if re.search(pattern, line):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        line_number=line_num,
                        severity=severity,
                        confidence=confidence,
                        title=f'Unsafe function: {func}',
                        description=desc,
                        code_snippet=self.get_code_snippet(lines, line_num),
                        recommendation=rec,
                        detector='CppDetector'
                    ))
                    
        return findings
    
    def _detect_race_conditions(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if re.search(r'\baccess\s*\([^)]+,\s*[RF]_OK\)', line):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=75,
                    title='TOCTOU race condition',
                    description='Time-of-check to time-of-use race condition with access()',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Open file directly and check errno instead',
                    detector='CppDetector'
                ))
            
            if re.search(r'\bstat\s*\([^)]+\).*open\s*\(', '\n'.join(lines[line_num-1:line_num+3])):
                findings.append(self.create_finding(
                    file_path=file_path,
                    line_number=line_num,
                    severity='MEDIUM',
                    confidence=70,
                    title='TOCTOU race condition',
                    description='stat() followed by open() creates race condition',
                    code_snippet=self.get_code_snippet(lines, line_num),
                    recommendation='Use open() with O_CREAT|O_EXCL flags',
                    detector='CppDetector'
                ))
                
        return findings
