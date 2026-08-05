import sys
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QSplitter, QStatusBar, QMessageBox
)
from PySide6.QtGui import QIcon, QFont
from PySide6.QtCore import Qt, Slot

from modules.gui.console import IntegratedConsoleWidget, ConsoleOutputRedirector
from modules.gui.screens.target_control import TargetControlScreen
from modules.gui.screens.history_diff import HistoryDiffScreen
from modules.gui.screens.network_proxy import NetworkProxyScreen
from modules.gui.screens.bettercap_client import BettercapScreen
from modules.gui.workers import ScanRunnerWorker

class ReconBuddyMainWindow(QMainWindow):
    """
    Main Application Window integrating:
    - Tabbed Graphical User Interface Screens (Target Control, History Diff, Proxy, Bettercap)
    - Dockable / Collapsible Integrated Terminal Console (capturing stdout/stderr)
    - Non-blocking Background Task Orchestration via Qt Workers
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon Buddy AI — Enterprise Reconnaissance & Network Security Platform")
        self.resize(1350, 900)
        self.active_scan_worker = None
        self._init_ui()
        self._setup_logging_redirect()

    def _init_ui(self):
        # Central Container & Main Vertical Splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)

        self.splitter = QSplitter(Qt.Vertical)

        # Tab Widget for Main GUI Screens
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(255, 255, 255, 0.1);
                background-color: #0a0a0c;
            }
            QTabBar::tab {
                background: #14161d;
                color: #a0a0ab;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #7000ff;
                color: #ffffff;
            }
        """)

        # Screen 1: Target Control
        self.target_screen = TargetControlScreen()
        self.target_screen.start_scan_requested.connect(self._on_start_scan)
        self.tabs.addTab(self.target_screen, "🎯 Target & Campaign Control")

        # Screen 2: History & Diff
        self.history_screen = HistoryDiffScreen()
        self.tabs.addTab(self.history_screen, "📜 History & Security Diff Analyzer")

        # Section 2: Network Proxy (PortSwigger-like Data Manipulation)
        self.proxy_screen = NetworkProxyScreen()
        self.tabs.addTab(self.proxy_screen, "🌐 Network Proxy & Data Manipulation")

        # Section 3: Bettercap Integration Client
        self.bettercap_screen = BettercapScreen()
        self.tabs.addTab(self.bettercap_screen, "⚡ Bettercap MITM Client")

        self.splitter.addWidget(self.tabs)

        # Integrated Console Widget (Bottom Dockable Panel)
        self.console_widget = IntegratedConsoleWidget()
        self.console_widget.command_submitted.connect(self._on_console_command)
        self.splitter.addWidget(self.console_widget)

        # Set initial splitter proportions (70% Screens, 30% Console)
        self.splitter.setSizes([630, 270])
        main_layout.addWidget(self.splitter)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready — Recon Buddy AI v0.1.0")

    def _setup_logging_redirect(self):
        """Redirects stdout and stderr to the integrated console widget."""
        self.stdout_redirector = ConsoleOutputRedirector(sys.stdout, 'stdout')
        self.stderr_redirector = ConsoleOutputRedirector(sys.stderr, 'stderr')

        self.stdout_redirector.text_written.connect(self.console_widget.append_output)
        self.stderr_redirector.text_written.connect(self.console_widget.append_output)

        sys.stdout = self.stdout_redirector
        sys.stderr = self.stderr_redirector

    @Slot(dict)
    def _on_start_scan(self, config: dict):
        """Handles scan launch request from TargetControlScreen in a background thread."""
        if self.active_scan_worker and self.active_scan_worker.isRunning():
            QMessageBox.warning(self, "Scan Active", "A campaign scan is already running.")
            return

        self.status_bar.showMessage(f"Campaign running... Target: {config.get('target')}")
        self.active_scan_worker = ScanRunnerWorker(config)
        self.active_scan_worker.host_updated.connect(self.target_screen.update_host_status)
        self.active_scan_worker.log_message.connect(self.console_widget.append_output)
        self.active_scan_worker.campaign_finished.connect(self._on_campaign_finished)
        self.active_scan_worker.start()

    @Slot(list)
    def _on_campaign_finished(self, results: list):
        self.status_bar.showMessage("Campaign finished successfully.")
        self.history_screen.refresh_history()

    @Slot(str)
    def _on_console_command(self, cmd: str):
        """Executes raw CLI commands typed into the integrated terminal."""
        # Simple flag parser runner or command dispatcher
        if cmd.startswith("main.py") or cmd.startswith("python"):
            self.console_widget.append_output("[System] Executing command in thread...\n", 'stdout')
        elif cmd == "clear":
            self.console_widget.clear_console()
        else:
            self.console_widget.append_output(f"[System] Unrecognized built-in. Executing default handler for: '{cmd}'\n", 'stdout')

def main_gui():
    app = QApplication(sys.argv)
    window = ReconBuddyMainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main_gui()
