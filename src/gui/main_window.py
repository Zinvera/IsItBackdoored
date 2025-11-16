from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QLineEdit, QFileDialog,
                             QCheckBox, QSlider, QComboBox, QGroupBox, QMessageBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
from .styles import DARK_STYLE
from .progress_dialog import ProgressDialog
from src.scanner.scan_worker import ScanWorker
import os

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("IsItBackdoored - Backdoor Detection Tool")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet(DARK_STYLE)
        self.setAcceptDrops(True)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        title = QLabel("IsItBackdoored")
        title.setStyleSheet("font-size: 32px; font-weight: bold; color: #0d7377;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("Detect backdoors and malicious code in your source files")
        subtitle.setStyleSheet("font-size: 14px; color: #888888;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        path_group = QGroupBox("Target Selection")
        path_layout = QVBoxLayout()
        
        path_input_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select folder or file to scan (or drag & drop here)")
        self.path_input.setMinimumHeight(40)
        path_input_layout.addWidget(self.path_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_path)
        browse_btn.setFixedWidth(100)
        path_input_layout.addWidget(browse_btn)
        
        path_layout.addLayout(path_input_layout)
        path_group.setLayout(path_layout)
        layout.addWidget(path_group)
        
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        self.hidden_files_cb = QCheckBox("Include hidden files")
        self.hidden_files_cb.setChecked(True)
        options_layout.addWidget(self.hidden_files_cb)
        
        self.symlinks_cb = QCheckBox("Follow symlinks")
        options_layout.addWidget(self.symlinks_cb)
        
        self.dependencies_cb = QCheckBox("Scan dependencies")
        options_layout.addWidget(self.dependencies_cb)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        confidence_group = QGroupBox("Minimum Confidence Level")
        confidence_layout = QVBoxLayout()
        
        slider_layout = QHBoxLayout()
        self.confidence_slider = QSlider(Qt.Orientation.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(100)
        self.confidence_slider.setValue(50)
        self.confidence_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.confidence_slider.setTickInterval(10)
        slider_layout.addWidget(self.confidence_slider)
        
        self.confidence_label = QLabel("50%")
        self.confidence_label.setFixedWidth(50)
        self.confidence_label.setStyleSheet("font-weight: bold; font-size: 16px;")
        slider_layout.addWidget(self.confidence_label)
        
        self.confidence_slider.valueChanged.connect(
            lambda v: self.confidence_label.setText(f"{v}%")
        )
        
        confidence_layout.addLayout(slider_layout)
        confidence_group.setLayout(confidence_layout)
        layout.addWidget(confidence_group)
        
        lang_group = QGroupBox("Target Languages")
        lang_layout = QHBoxLayout()
        
        self.lang_checkboxes = {}
        languages = ["Python", "JavaScript", "PHP", "Go", "Java", "C/C++"]
        for lang in languages:
            cb = QCheckBox(lang)
            cb.setChecked(True)
            self.lang_checkboxes[lang] = cb
            lang_layout.addWidget(cb)
        
        lang_group.setLayout(lang_layout)
        layout.addWidget(lang_group)
        
        layout.addStretch()
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setMinimumHeight(50)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                font-weight: bold;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            
    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.path_input.setText(path)
            
    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if not path:
            path = QFileDialog.getOpenFileName(self, "Select File")[0]
        if path:
            self.path_input.setText(path)
            
    def start_scan(self):
        target_path = self.path_input.text().strip()
        
        if not target_path:
            QMessageBox.warning(self, "Error", "Please select a target path")
            return
            
        if not os.path.exists(target_path):
            QMessageBox.warning(self, "Error", "Selected path does not exist")
            return
        
        selected_languages = [lang for lang, cb in self.lang_checkboxes.items() if cb.isChecked()]
        if not selected_languages:
            QMessageBox.warning(self, "Error", "Please select at least one language")
            return
        
        options = {
            'include_hidden': self.hidden_files_cb.isChecked(),
            'follow_symlinks': self.symlinks_cb.isChecked(),
            'scan_dependencies': self.dependencies_cb.isChecked(),
            'min_confidence': self.confidence_slider.value(),
            'languages': selected_languages
        }
        
        self.scan_btn.setEnabled(False)
        
        progress_dialog = ProgressDialog(self)
        
        self.scan_worker = ScanWorker(target_path, options)
        self.scan_worker.progress_updated.connect(progress_dialog.update_progress)
        self.scan_worker.finding_discovered.connect(progress_dialog.add_finding)
        self.scan_worker.scan_completed.connect(lambda result: self.on_scan_completed(result, progress_dialog))
        self.scan_worker.error_occurred.connect(lambda error: self.on_scan_error(error, progress_dialog))
        
        progress_dialog.cancelled.connect(self.scan_worker.cancel)
        
        self.scan_worker.start()
        progress_dialog.exec()
        
    def on_scan_completed(self, result, progress_dialog):
        progress_dialog.close()
        self.scan_btn.setEnabled(True)
        
        if result.total_files == 0:
            QMessageBox.warning(
                self,
                "No Files Found",
                f"No files were found to scan.\n\n"
                f"Make sure:\n"
                f"- The selected languages match your files\n"
                f"- Files have correct extensions (.py, .js, .php, .c, .cpp, etc.)\n"
                f"- 'Include hidden files' is checked if needed"
            )
            return
        
        if result.scanned_files == 0:
            error_msg = "Files were found but could not be scanned.\n\n"
            if result.errors:
                error_msg += f"Errors encountered:\n" + "\n".join(result.errors[:5])
                if len(result.errors) > 5:
                    error_msg += f"\n... and {len(result.errors) - 5} more errors"
            
            QMessageBox.warning(self, "Scan Failed", error_msg)
            return
        
        from src.reporter.html_generator import HTMLGenerator
        generator = HTMLGenerator(result)
        report_path = generator.generate()
        
        import webbrowser
        webbrowser.open(f'file://{os.path.abspath(report_path)}')
        
        error_info = ""
        if result.errors:
            error_info = f"\nErrors: {len(result.errors)}"
        
        QMessageBox.information(
            self,
            "Scan Complete",
            f"Scan completed!\n\nFiles scanned: {result.scanned_files}\n"
            f"Findings: {len(result.findings)}\n"
            f"Risk Score: {result.get_risk_score()}/100{error_info}\n\n"
            f"Report opened in browser."
        )
        
    def on_scan_error(self, error, progress_dialog):
        progress_dialog.close()
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{error}")
