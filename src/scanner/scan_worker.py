from PyQt6.QtCore import QThread, pyqtSignal
from src.models.scan_result import ScanResult
from src.models.finding import Finding
from .scanner import Scanner

class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, str, int)
    finding_discovered = pyqtSignal(Finding)
    scan_completed = pyqtSignal(ScanResult)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target_path: str, options: dict):
        super().__init__()
        self.target_path = target_path
        self.options = options
        self.scanner = Scanner(options)
        
    def run(self):
        try:
            def progress_callback(progress, file_path, files_scanned, findings):
                self.progress_updated.emit(progress, file_path, files_scanned)
                for finding in findings:
                    self.finding_discovered.emit(finding)
                    
            result = self.scanner.scan(self.target_path, progress_callback)
            self.scan_completed.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def cancel(self):
        self.scanner.cancel()
