import os
from typing import List, Callable
from src.models.finding import Finding
from src.models.scan_result import ScanResult
from .detectors.obfuscation_detector import ObfuscationDetector
from .detectors.network_detector import NetworkDetector
from .detectors.file_operation_detector import FileOperationDetector
from .detectors.crypto_detector import CryptoDetector
from .detectors.suspicious_pattern_detector import SuspiciousPatternDetector
from .detectors.cpp_detector import CppDetector
from .parsers.code_parser import CodeParser

class Scanner:
    def __init__(self, options: dict):
        self.options = options
        self.detectors = [
            ObfuscationDetector(),
            NetworkDetector(),
            FileOperationDetector(),
            CryptoDetector(),
            SuspiciousPatternDetector(),
            CppDetector()
        ]
        self.parser = CodeParser()
        self.cancelled = False
        
    def cancel(self):
        self.cancelled = True
        
    def scan(self, target_path: str, progress_callback: Callable = None) -> ScanResult:
        result = ScanResult()
        
        if os.path.isfile(target_path):
            files = [target_path]
        else:
            files = self._collect_files(target_path)
        
        result.total_files = len(files)
        
        if len(files) == 0:
            return result
        
        for idx, file_path in enumerate(files):
            if self.cancelled:
                break
                
            try:
                findings = self._scan_file(file_path)
                
                filtered_findings = [f for f in findings if f.confidence >= self.options.get('min_confidence', 0)]
                
                for finding in filtered_findings:
                    result.add_finding(finding)
                        
                result.scanned_files += 1
                
                if progress_callback:
                    progress = int((idx + 1) / len(files) * 100)
                    progress_callback(progress, file_path, result.scanned_files, filtered_findings)
                    
            except Exception as e:
                result.errors.append(f"{file_path}: {str(e)}")
                result.scanned_files += 1
                
        return result
        
    def _collect_files(self, root_path: str) -> List[str]:
        files = []
        extensions = self._get_extensions()
        
        if not extensions:
            return files
        
        for dirpath, dirnames, filenames in os.walk(root_path):
            if not self.options.get('include_hidden', False):
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                filenames = [f for f in filenames if not f.startswith('.')]
                
            if not self.options.get('follow_symlinks', False):
                dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
                
            if not self.options.get('scan_dependencies', False):
                dirnames[:] = [d for d in dirnames if d not in ['node_modules', 'vendor', 'venv', '__pycache__', 'dist', 'build', '.git', '.svn']]
                
            for filename in filenames:
                if any(filename.endswith(ext) for ext in extensions):
                    full_path = os.path.join(dirpath, filename)
                    files.append(full_path)
                    
        return files
        
    def _get_extensions(self) -> List[str]:
        lang_extensions = {
            'Python': ['.py', '.pyw'],
            'JavaScript': ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
            'PHP': ['.php', '.php3', '.php4', '.php5', '.phtml'],
            'Go': ['.go'],
            'Java': ['.java'],
            'C/C++': ['.c', '.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hh', '.hxx']
        }
        
        extensions = []
        languages = self.options.get('languages', [])
        
        for lang in languages:
            if lang in lang_extensions:
                extensions.extend(lang_extensions[lang])
            
        return extensions
        
    def _scan_file(self, file_path: str) -> List[Finding]:
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return findings
        
        if not content or len(content.strip()) == 0:
            return findings
            
        lines = content.split('\n')
        
        tree = None
        try:
            tree = self.parser.parse(file_path, content)
        except:
            pass
        
        for detector in self.detectors:
            try:
                detector_findings = detector.detect(file_path, content, lines, tree)
                if detector_findings:
                    findings.extend(detector_findings)
            except Exception as e:
                pass
            
        return findings
