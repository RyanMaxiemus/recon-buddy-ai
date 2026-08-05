import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QSplitter
)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Qt, Slot

from modules.history import ScanHistory

class HistoryDiffScreen(QWidget):
    """
    Screen 2: Persistent History & Security Diff Analyzer.
    Lists scan iterations from ~/.recon-buddy/history.db and displays detailed scan comparisons.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.history_mgr = ScanHistory()
        self._init_ui()
        self.refresh_history()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Search Bar & Refresh
        top_bar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter history by target IP or domain...")
        self.search_input.textChanged.connect(self._filter_history)
        top_bar.addWidget(self.search_input)

        self.refresh_btn = QPushButton("🔄 Refresh History")
        self.refresh_btn.clicked.connect(self.refresh_history)
        top_bar.addWidget(self.refresh_btn)

        layout.addLayout(top_bar)

        # Splitter: Top (History Table), Bottom (Details & Diff)
        splitter = QSplitter(Qt.Vertical)

        # Master Table
        history_group = QGroupBox("📜 Scan Iteration History")
        history_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; }")
        h_layout = QVBoxLayout(history_group)

        self.history_table = QTableWidget(0, 3)
        self.history_table.setHorizontalHeaderLabels(["ID", "Target", "Timestamp"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.cellClicked.connect(self._on_history_selected)
        h_layout.addWidget(self.history_table)

        splitter.addWidget(history_group)

        # Detail/Summary Display
        detail_group = QGroupBox("🔍 Scan Summary & Security Insights")
        detail_group.setStyleSheet("QGroupBox { font-weight: bold; color: #7000ff; border: 1px solid rgba(112, 0, 255, 0.3); border-radius: 8px; }")
        d_layout = QVBoxLayout(detail_group)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("JetBrains Mono", 10))
        self.detail_text.setStyleSheet("background-color: #0d0e12; color: #e0e0e6; border: 1px solid #333;")
        d_layout.addWidget(self.detail_text)

        splitter.addWidget(detail_group)
        layout.addWidget(splitter)

    def refresh_history(self):
        """Loads scan records from SQLite database."""
        rows = self.history_mgr.list_history()
        self.history_table.setRowCount(0)

        for row in rows:
            r = self.history_table.rowCount()
            self.history_table.insertRow(r)
            self.history_table.setItem(r, 0, QTableWidgetItem(str(row[0])))
            self.history_table.setItem(r, 1, QTableWidgetItem(row[1]))
            self.history_table.setItem(r, 2, QTableWidgetItem(row[2]))

    def _filter_history(self, filter_text: str):
        rows = self.history_mgr.list_history(target_filter=filter_text if filter_text.strip() else None)
        self.history_table.setRowCount(0)
        for row in rows:
            r = self.history_table.rowCount()
            self.history_table.insertRow(r)
            self.history_table.setItem(r, 0, QTableWidgetItem(str(row[0])))
            self.history_table.setItem(r, 1, QTableWidgetItem(row[1]))
            self.history_table.setItem(r, 2, QTableWidgetItem(row[2]))

    def _on_history_selected(self, row: int, column: int):
        target = self.history_table.item(row, 1).text()
        last_scan = self.history_mgr.get_last_scan(target)

        if last_scan:
            summary = f"=== TARGET: {last_scan.get('target')} ===\n"
            summary += f"Timestamp: {last_scan.get('timestamp')}\n\n"
            summary += f"--- AI SUMMARY ---\n{last_scan.get('ai_summary')}\n\n"
            summary += f"--- DNS RECORDS ---\n{last_scan.get('dns_data')}\n"
            self.detail_text.setText(summary)
