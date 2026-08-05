import os
import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QSpinBox, QComboBox,
    QCheckBox, QRadioButton, QButtonGroup, QTableWidget, QTableWidgetItem,
    QFileDialog, QHeaderView, QMessageBox
)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Signal, Slot, Qt

class TargetControlScreen(QWidget):
    """
    Screen 1: Target & Campaign Control Center.
    Handles target selection (IP/CIDR/Domain/File), scan options, API configuration,
    and real-time scan execution monitoring.
    """
    start_scan_requested = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Left Panel: Configuration & Tool Control
        left_panel = QVBoxLayout()
        left_panel.setSpacing(10)

        # Target Specification Group
        target_group = QGroupBox("🎯 Target Definition Scope")
        target_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; margin-top: 6px; padding-top: 10px; }")
        t_layout = QVBoxLayout(target_group)

        t_input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1, scanme.nmap.org, or 10.0.0.0/24")
        self.target_input.setStyleSheet("padding: 6px; border: 1px solid #333; border-radius: 4px; background: #14161d; color: white;")
        t_input_layout.addWidget(self.target_input)

        self.file_btn = QPushButton("📁 Browse File...")
        self.file_btn.clicked.connect(self._select_targets_file)
        t_input_layout.addWidget(self.file_btn)
        t_layout.addLayout(t_input_layout)

        self.file_path_label = QLabel("No targets file selected")
        self.file_path_label.setStyleSheet("color: #a0a0ab; font-size: 11px;")
        t_layout.addWidget(self.file_path_label)
        left_panel.addWidget(target_group)

        # Scan Parameters Group
        param_group = QGroupBox("⚙️ Execution & Performance Parameters")
        param_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; margin-top: 6px; padding-top: 10px; }")
        p_layout = QGridLayout(param_group)

        p_layout.addWidget(QLabel("Concurrency Workers:"), 0, 0)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 20)
        self.concurrency_spin.setValue(5)
        p_layout.addWidget(self.concurrency_spin, 0, 1)

        p_layout.addWidget(QLabel("Report Format:"), 1, 0)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["markdown", "html", "both"])
        p_layout.addWidget(self.format_combo, 1, 1)

        p_layout.addWidget(QLabel("AI Model (Ollama):"), 2, 0)
        self.model_input = QLineEdit("llama3")
        self.model_input.setPlaceholderText("e.g. llama3, mistral")
        p_layout.addWidget(self.model_input, 2, 1)

        left_panel.addWidget(param_group)

        # Notification & Output Mode Group
        notify_group = QGroupBox("🔔 Notifications & Output Modes")
        notify_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; margin-top: 6px; padding-top: 10px; }")
        n_layout = QVBoxLayout(notify_group)

        n_checkbox_layout = QHBoxLayout()
        self.slack_cb = QCheckBox("Slack")
        self.discord_cb = QCheckBox("Discord")
        self.email_cb = QCheckBox("Email")
        n_checkbox_layout.addWidget(self.slack_cb)
        n_checkbox_layout.addWidget(self.discord_cb)
        n_checkbox_layout.addWidget(self.email_cb)
        n_layout.addLayout(n_checkbox_layout)

        self.json_mode_cb = QCheckBox("JSON Pipeline Mode (--json)")
        n_layout.addWidget(self.json_mode_cb)
        left_panel.addWidget(notify_group)

        # Execution Controls
        self.run_btn = QPushButton("🚀 LAUNCH RECON CAMPAIGN")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #00f2ff, #7000ff);
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #33f5ff, #8c26ff);
            }
        """)
        self.run_btn.clicked.connect(self._on_launch_clicked)
        left_panel.addWidget(self.run_btn)
        left_panel.addStretch()

        main_layout.addLayout(left_panel, 40)

        # Right Panel: Campaign Monitor & Target Host Status
        right_panel = QVBoxLayout()

        monitor_group = QGroupBox("📊 Active Campaign Target Host Status")
        monitor_group.setStyleSheet("QGroupBox { font-weight: bold; color: #7000ff; border: 1px solid rgba(112, 0, 255, 0.3); border-radius: 8px; margin-top: 6px; padding-top: 10px; }")
        m_layout = QVBoxLayout(monitor_group)

        self.status_table = QTableWidget(0, 4)
        self.status_table.setHorizontalHeaderLabels(["Target Host", "Status", "Open Ports", "CVE Vulnerabilities"])
        self.status_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.status_table.setStyleSheet("QTableWidget { background-color: #0d0e12; color: #ffffff; gridline-color: #222; }")
        m_layout.addWidget(self.status_table)

        right_panel.addWidget(monitor_group)
        main_layout.addLayout(right_panel, 60)

    def _select_targets_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Targets File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.file_path_label.setText(file_path)

    def _on_launch_clicked(self):
        target = self.target_input.text().strip()
        targets_file = self.file_path_label.text() if self.file_path_label.text() != "No targets file selected" else ""

        if not target and not targets_file:
            QMessageBox.warning(self, "Input Required", "Please specify a target host/CIDR or choose a targets file.")
            return

        notifiers = []
        if self.slack_cb.isChecked(): notifiers.append("slack")
        if self.discord_cb.isChecked(): notifiers.append("discord")
        if self.email_cb.isChecked(): notifiers.append("email")

        config = {
            "target": target,
            "targets_file": targets_file,
            "concurrency": self.concurrency_spin.value(),
            "format": self.format_combo.currentText(),
            "model": self.model_input.text().strip(),
            "notify": ",".join(notifiers),
            "json": self.json_mode_cb.isChecked(),
            "output_dir": "reports"
        }
        self.start_scan_requested.emit(config)

    @Slot(str, str, int, int)
    def update_host_status(self, target: str, status: str, ports_count: int, cve_count: int):
        """Adds or updates a row in the active scan monitoring table."""
        items = self.status_table.findItems(target, Qt.MatchExactly)
        if items:
            row = items[0].row()
        else:
            row = self.status_table.rowCount()
            self.status_table.insertRow(row)
            self.status_table.setItem(row, 0, QTableWidgetItem(target))

        self.status_table.setItem(row, 1, QTableWidgetItem(status))
        self.status_table.setItem(row, 2, QTableWidgetItem(str(ports_count)))
        self.status_table.setItem(row, 3, QTableWidgetItem(str(cve_count)))
