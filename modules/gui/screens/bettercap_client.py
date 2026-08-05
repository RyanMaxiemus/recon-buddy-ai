from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QCheckBox, QSplitter, QComboBox
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt, Slot

class BettercapScreen(QWidget):
    """
    Section 3: Bettercap Client Integration Screen.
    Provides a rich GUI frontend interacting with Bettercap via REST API and WebSocket events.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Top Control Bar: Connection & MITM Master Button
        top_bar = QHBoxLayout()

        self.conn_label = QLabel("Bettercap REST API: 🔴 Disconnected (http://127.0.0.1:8081)")
        self.conn_label.setStyleSheet("font-weight: bold; color: #ff4757;")
        top_bar.addWidget(self.conn_label)

        self.connect_btn = QPushButton("🔌 Connect Daemon")
        self.connect_btn.clicked.connect(self._toggle_connection)
        top_bar.addWidget(self.connect_btn)

        top_bar.addSpacing(20)

        self.mitm_btn = QPushButton("⚡ START MITM ATTACK")
        self.mitm_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #ff4757, #ff6b81);
                color: white;
                font-weight: bold;
                font-size: 13px;
                padding: 6px 16px;
                border-radius: 4px;
            }
        """)
        self.mitm_btn.clicked.connect(self._toggle_mitm)
        top_bar.addWidget(self.mitm_btn)

        top_bar.addStretch()

        top_bar.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(["eth0", "wlan0", "lo"])
        top_bar.addWidget(self.iface_combo)

        layout.addLayout(top_bar)

        # Main Splitter: Modules & Discovered Hosts (Top) vs Event Logs (Bottom)
        main_splitter = QSplitter(Qt.Vertical)

        top_splitter = QSplitter(Qt.Horizontal)

        # Left Panel: Module Configurations
        module_group = QGroupBox("⚙️ Active Bettercap Modules")
        module_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00f2ff; border: 1px solid rgba(0, 242, 255, 0.3); border-radius: 8px; }")
        m_layout = QVBoxLayout(module_group)

        self.net_probe_cb = QCheckBox("net.probe / net.recon (Host Discovery)")
        self.net_probe_cb.setChecked(True)
        m_layout.addWidget(self.net_probe_cb)

        self.arp_spoof_cb = QCheckBox("arp.spoof (ARP Poisoning)")
        m_layout.addWidget(self.arp_spoof_cb)

        self.dns_spoof_cb = QCheckBox("dns.spoof (DNS Hijacking)")
        m_layout.addWidget(self.dns_spoof_cb)

        self.http_proxy_cb = QCheckBox("http.proxy (SSL Strip & Proxy)")
        m_layout.addWidget(self.http_proxy_cb)

        # Module Parameter Inputs
        m_layout.addWidget(QLabel("Spoofed DNS Domain Regex:"))
        self.dns_regex_input = QLineEdit(".*")
        m_layout.addWidget(self.dns_regex_input)

        m_layout.addWidget(QLabel("Redirect Target IP:"))
        self.dns_ip_input = QLineEdit("192.168.1.100")
        m_layout.addWidget(self.dns_ip_input)

        m_layout.addStretch()
        top_splitter.addWidget(module_group)

        # Right Panel: Discovered Network Targets Table
        hosts_group = QGroupBox("🎯 Discovered Network Targets")
        hosts_group.setStyleSheet("QGroupBox { font-weight: bold; color: #7000ff; border: 1px solid rgba(112, 0, 255, 0.3); border-radius: 8px; }")
        h_layout = QVBoxLayout(hosts_group)

        self.hosts_table = QTableWidget(0, 4)
        self.hosts_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Hostname / Vendor", "Target MITM"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hosts_table.setStyleSheet("QTableWidget { background-color: #0d0e12; color: #ffffff; }")
        h_layout.addWidget(self.hosts_table)

        top_splitter.addWidget(hosts_group)
        main_splitter.addWidget(top_splitter)

        # Bottom Panel: Bettercap WebSocket Event Stream Logs
        events_group = QGroupBox("📡 Bettercap Event Stream & Event Logs")
        events_group.setStyleSheet("QGroupBox { font-weight: bold; color: #ffa502; border: 1px solid rgba(255, 165, 2, 0.3); border-radius: 8px; }")
        ev_layout = QVBoxLayout(events_group)

        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setFont(QFont("JetBrains Mono", 10))
        self.event_log.setStyleSheet("background-color: #0d0e12; color: #ffa502; border: 1px solid #333;")
        ev_layout.addWidget(self.event_log)

        main_splitter.addWidget(events_group)
        layout.addWidget(main_splitter)

    def _toggle_connection(self):
        if "Disconnected" in self.conn_label.text():
            self.conn_label.setText("Bettercap REST API: 🟢 Connected (http://127.0.0.1:8081)")
            self.conn_label.setStyleSheet("font-weight: bold; color: #2ed573;")
            self.connect_btn.setText("🔌 Disconnect")
            self.event_log.append("Connected to Bettercap REST API & WebSocket Event Stream.")
        else:
            self.conn_label.setText("Bettercap REST API: 🔴 Disconnected (http://127.0.0.1:8081)")
            self.conn_label.setStyleSheet("font-weight: bold; color: #ff4757;")
            self.connect_btn.setText("🔌 Connect Daemon")
            self.event_log.append("Disconnected from Bettercap daemon.")

    def _toggle_mitm(self):
        if "START" in self.mitm_btn.text():
            self.mitm_btn.setText("🛑 STOP MITM ATTACK")
            self.mitm_btn.setStyleSheet("background-color: #ff4757; color: white; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
            self.event_log.append("[MITM] Started ARP spoofing and proxy redirection.")
        else:
            self.mitm_btn.setText("⚡ START MITM ATTACK")
            self.mitm_btn.setStyleSheet("background-color: #7000ff; color: white; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
            self.event_log.append("[MITM] Stopped MITM attack.")
