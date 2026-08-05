from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QCheckBox, QSplitter
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt, Slot

class NetworkProxyScreen(QWidget):
    """
    Section 2: PortSwigger-like Network Data Manipulation Screen.
    Allows capturing, inspecting, filtering, and dynamically modifying HTTP/HTTPS requests and responses in real-time.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Top Control Bar: Proxy Status & Intercept Toggle
        top_bar = QHBoxLayout()

        self.status_label = QLabel("Proxy Status: ⏹️ STOPPED (Port 8080)")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff4757;")
        top_bar.addWidget(self.status_label)

        self.toggle_proxy_btn = QPushButton("▶️ Start Proxy")
        self.toggle_proxy_btn.setStyleSheet("background-color: #2ed573; color: black; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.toggle_proxy_btn.clicked.connect(self._toggle_proxy)
        top_bar.addWidget(self.toggle_proxy_btn)

        self.intercept_cb = QCheckBox("⏸️ Enable Real-Time Intercept")
        self.intercept_cb.setChecked(True)
        top_bar.addWidget(self.intercept_cb)

        top_bar.addStretch()

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter HTTP traffic by domain or MIME type...")
        top_bar.addWidget(self.filter_input)

        layout.addLayout(top_bar)

        # Main Splitter: Traffic Log Table (Top) vs Data Inspector & Editor (Bottom)
        splitter = QSplitter(Qt.Vertical)

        # Traffic History Table
        traffic_group = QGroupBox("🌐 Intercepted HTTP/HTTPS Sessions")
        traffic_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; }")
        t_layout = QVBoxLayout(traffic_group)

        self.traffic_table = QTableWidget(0, 5)
        self.traffic_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Content-Type"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.cellClicked.connect(self._on_session_selected)
        t_layout.addWidget(self.traffic_table)

        splitter.addWidget(traffic_group)

        # Inspection & Real-time Modification Editor
        editor_group = QGroupBox("✏️ Standardized Payload Inspector & Content Manipulator")
        editor_group.setStyleSheet("QGroupBox { font-weight: bold; color: #7000ff; border: 1px solid rgba(112, 0, 255, 0.3); border-radius: 8px; }")
        e_layout = QHBoxLayout(editor_group)

        # Left: Request Inspector
        req_box = QVBoxLayout()
        req_box.addWidget(QLabel("Request Headers & Body (Editable):"))
        self.req_edit = QTextEdit()
        self.req_edit.setFont(QFont("JetBrains Mono", 10))
        self.req_edit.setStyleSheet("background-color: #0d0e12; color: #00f2ff; border: 1px solid #333;")
        req_box.addWidget(self.req_edit)
        e_layout.addLayout(req_box)

        # Right: Response Inspector / Media Replacement
        resp_box = QVBoxLayout()
        resp_box.addWidget(QLabel("Response Headers & Body (Editable):"))
        self.resp_edit = QTextEdit()
        self.resp_edit.setFont(QFont("JetBrains Mono", 10))
        self.resp_edit.setStyleSheet("background-color: #0d0e12; color: #2ed573; border: 1px solid #333;")
        resp_box.addWidget(self.resp_edit)

        # Action Buttons
        act_layout = QHBoxLayout()
        self.forward_btn = QPushButton("FORWARD REQUEST ⏩")
        self.forward_btn.setStyleSheet("background-color: #7000ff; color: white; font-weight: bold; padding: 6px;")
        act_layout.addWidget(self.forward_btn)

        self.drop_btn = QPushButton("DROP ❌")
        self.drop_btn.setStyleSheet("background-color: #ff4757; color: white; font-weight: bold; padding: 6px;")
        act_layout.addWidget(self.drop_btn)
        resp_box.addLayout(act_layout)

        e_layout.addLayout(resp_box)
        splitter.addWidget(editor_group)

        layout.addWidget(splitter)

    def _toggle_proxy(self):
        if "STOPPED" in self.status_label.text():
            self.status_label.setText("Proxy Status: 🟢 ACTIVE (Port 8080)")
            self.status_label.setStyleSheet("font-weight: bold; color: #2ed573;")
            self.toggle_proxy_btn.setText("⏹️ Stop Proxy")
            self.toggle_proxy_btn.setStyleSheet("background-color: #ff4757; color: white; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        else:
            self.status_label.setText("Proxy Status: ⏹️ STOPPED (Port 8080)")
            self.status_label.setStyleSheet("font-weight: bold; color: #ff4757;")
            self.toggle_proxy_btn.setText("▶️ Start Proxy")
            self.toggle_proxy_btn.setStyleSheet("background-color: #2ed573; color: black; font-weight: bold; padding: 6px 12px; border-radius: 4px;")

    def _on_session_selected(self, row: int, col: int):
        pass
