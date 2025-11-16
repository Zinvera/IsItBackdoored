from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QProgressBar, QPushButton, QTextEdit)
from PyQt6.QtCore import Qt, pyqtSignal
from .styles import DARK_STYLE

class ProgressDialog(QDialog):
    cancelled = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Scanning...")
        self.setModal(True)
        self.setFixedSize(600, 400)
        self.setStyleSheet(DARK_STYLE)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        title = QLabel("Scan in Progress")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        self.current_file_label = QLabel("Initializing...")
        self.current_file_label.setStyleSheet("color: #888888;")
        self.current_file_label.setWordWrap(True)
        layout.addWidget(self.current_file_label)
        
        stats_layout = QHBoxLayout()
        
        self.files_label = QLabel("Files: 0")
        self.files_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.files_label)
        
        stats_layout.addStretch()
        
        self.findings_label = QLabel("Findings: 0")
        self.findings_label.setStyleSheet("font-weight: bold; color: #ff6b6b;")
        stats_layout.addWidget(self.findings_label)
        
        layout.addLayout(stats_layout)
        
        findings_title = QLabel("Recent Findings:")
        findings_title.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(findings_title)
        
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.findings_text.setMaximumHeight(150)
        self.findings_text.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 5px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.findings_text)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.on_cancel)
        layout.addWidget(self.cancel_btn)
        
        self.files_scanned = 0
        self.findings_count = 0
        
    def update_progress(self, progress, current_file, files_scanned):
        self.progress_bar.setValue(progress)
        self.current_file_label.setText(f"Scanning: {current_file}")
        self.files_scanned = files_scanned
        self.files_label.setText(f"Files: {files_scanned}")
        
    def add_finding(self, finding):
        self.findings_count += 1
        self.findings_label.setText(f"Findings: {self.findings_count}")
        
        severity_colors = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6b6b',
            'MEDIUM': '#ffa500',
            'LOW': '#ffff00'
        }
        color = severity_colors.get(finding.severity, '#ffffff')
        
        finding_text = f'<span style="color: {color};">[{finding.severity}]</span> {finding.title} - {finding.file_path}:{finding.line_number}'
        self.findings_text.append(finding_text)
        
    def on_cancel(self):
        self.cancelled.emit()
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelling...")
