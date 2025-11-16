DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #1e1e1e;
    color: #e0e0e0;
}

QLabel {
    color: #e0e0e0;
    font-size: 13px;
}

QPushButton {
    background-color: #0d7377;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    font-size: 14px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #14a085;
}

QPushButton:pressed {
    background-color: #0a5f62;
}

QPushButton:disabled {
    background-color: #3a3a3a;
    color: #666666;
}

QLineEdit {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #3a3a3a;
    padding: 8px;
    border-radius: 4px;
    font-size: 13px;
}

QLineEdit:focus {
    border: 1px solid #0d7377;
}

QCheckBox {
    color: #e0e0e0;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 2px solid #3a3a3a;
    background-color: #2d2d2d;
}

QCheckBox::indicator:checked {
    background-color: #0d7377;
    border-color: #0d7377;
}

QSlider::groove:horizontal {
    height: 6px;
    background: #3a3a3a;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background: #0d7377;
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}

QSlider::handle:horizontal:hover {
    background: #14a085;
}

QComboBox {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #3a3a3a;
    padding: 8px;
    border-radius: 4px;
}

QComboBox::drop-down {
    border: none;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid #e0e0e0;
    margin-right: 10px;
}

QComboBox QAbstractItemView {
    background-color: #2d2d2d;
    color: #e0e0e0;
    selection-background-color: #0d7377;
    border: 1px solid #3a3a3a;
}

QProgressBar {
    background-color: #2d2d2d;
    border: 1px solid #3a3a3a;
    border-radius: 5px;
    text-align: center;
    color: #e0e0e0;
}

QProgressBar::chunk {
    background-color: #0d7377;
    border-radius: 4px;
}

QGroupBox {
    color: #e0e0e0;
    border: 2px solid #3a3a3a;
    border-radius: 5px;
    margin-top: 10px;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}
"""
