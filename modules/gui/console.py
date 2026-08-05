import sys
import re
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QComboBox
)
from PySide6.QtGui import QTextCursor, QFont, QColor, QTextCharFormat
from PySide6.QtCore import Signal, QObject, Qt, Slot

class ConsoleOutputRedirector(QObject):
    """Redirects stdout and stderr to a Qt signal safely across threads."""
    text_written = Signal(str, str)  # (text, stream_type: 'stdout' or 'stderr')

    def __init__(self, original_stream, stream_type='stdout'):
        super().__init__()
        self.original_stream = original_stream
        self.stream_type = stream_type

    def write(self, text):
        if self.original_stream:
            self.original_stream.write(text)
        if text:
            self.text_written.emit(text, self.stream_type)

    def flush(self):
        if self.original_stream:
            self.original_stream.flush()

class IntegratedConsoleWidget(QWidget):
    """
    A fully functional dockable interactive terminal component.
    Captures stdout/stderr, provides command execution history, search, and clear capabilities.
    """
    command_submitted = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.history = []
        self.history_index = -1
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header Bar
        header = QHBoxLayout()
        title = QLabel("🖥️ Integrated Terminal Console")
        title.setStyleSheet("font-weight: bold; color: #00f2ff;")
        header.addWidget(title)

        header.addStretch()

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setToolTip("Clear console output")
        self.clear_btn.clicked.connect(self.clear_console)
        header.addWidget(self.clear_btn)

        layout.addLayout(header)

        # Console Text Display
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont("JetBrains Mono", 10))
        self.output_area.setStyleSheet("""
            QTextEdit {
                background-color: #0d0e12;
                color: #e0e0e6;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                padding: 6px;
            }
        """)
        layout.addWidget(self.output_area)

        # Input Prompt Line
        input_layout = QHBoxLayout()
        prompt_label = QLabel("recon-buddy >")
        prompt_label.setStyleSheet("color: #7000ff; font-weight: bold; font-family: 'JetBrains Mono';")
        input_layout.addWidget(prompt_label)

        self.input_field = QLineEdit()
        self.input_field.setFont(QFont("JetBrains Mono", 10))
        self.input_field.setPlaceholderText("Enter CLI flags or commands (e.g. --target 10.0.0.1 --json)...")
        self.input_field.setStyleSheet("""
            QLineEdit {
                background-color: #14161d;
                color: #ffffff;
                border: 1px solid #7000ff;
                border-radius: 4px;
                padding: 4px 8px;
            }
        """)
        self.input_field.returnPressed.connect(self._on_command_entered)
        input_layout.addWidget(self.input_field)

        self.exec_btn = QPushButton("Run")
        self.exec_btn.setStyleSheet("""
            QPushButton {
                background-color: #7000ff;
                color: white;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #8c26ff;
            }
        """)
        self.exec_btn.clicked.connect(self._on_command_entered)
        input_layout.addWidget(self.exec_btn)

        layout.addLayout(input_layout)

    @Slot(str, str)
    def append_output(self, text: str, stream_type: str = 'stdout'):
        """Appends formatted text to the terminal output widget."""
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        if stream_type == 'stderr':
            fmt.setForeground(QColor("#ff4757"))
        elif "error" in text.lower() or "fatal" in text.lower():
            fmt.setForeground(QColor("#ff4757"))
        elif "warning" in text.lower():
            fmt.setForeground(QColor("#ffa502"))
        elif "success" in text.lower() or "✅" in text:
            fmt.setForeground(QColor("#2ed573"))
        else:
            fmt.setForeground(QColor("#e0e0e6"))

        # Simple ANSI escape code cleaning for clean display
        clean_text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        cursor.insertText(clean_text, fmt)
        self.output_area.setTextCursor(cursor)
        self.output_area.ensureCursorVisible()

    def clear_console(self):
        self.output_area.clear()

    def _on_command_entered(self):
        cmd = self.input_field.text().strip()
        if not cmd:
            return
        self.append_output(f"\nrecon-buddy > {cmd}\n", 'stdout')
        self.history.append(cmd)
        self.history_index = len(self.history)
        self.input_field.clear()
        self.command_submitted.emit(cmd)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Up:
            if self.history and self.history_index > 0:
                self.history_index -= 1
                self.input_field.setText(self.history[self.history_index])
        elif event.key() == Qt.Key_Down:
            if self.history and self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.input_field.setText(self.history[self.history_index])
            elif self.history_index >= len(self.history) - 1:
                self.history_index = len(self.history)
                self.input_field.clear()
        else:
            super().keyPressEvent(event)
