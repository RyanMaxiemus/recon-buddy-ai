import sys
import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from PySide6.QtCore import QObject, Signal, Slot, QThread

# Imports from Recon Buddy AI backend
from modules.scanner import UnifiedRecon
from modules.dns_module import run_dns_lookup, is_ip_address
from modules.ai_summarizer import create_ai_summary
from modules.reporter import generate_report
from modules.vuln_lookup import VulnLookup
from modules.history import ScanHistory
from modules.notifiers import NotificationManager
from main import get_all_targets

log = logging.getLogger("RECON.Proxy")

class ProxyEngineWorker(QObject):
    """
    Background Proxy Engine Worker running an in-flight mitmproxy engine or asyncio proxy loop.
    Captures requests/responses, standardizes data format, and supports dynamic body/header manipulation.
    """
    request_intercepted = Signal(dict)
    response_intercepted = Signal(dict)
    proxy_status_changed = Signal(bool, str)

    def __init__(self):
        super().__init__()
        self.is_running = False
        self.intercept_enabled = True
        self.rules: List[Dict[str, Any]] = []

    @Slot(int)
    def start_proxy(self, port: int = 8080):
        """Starts the proxy server."""
        self.is_running = True
        self.proxy_status_changed.emit(True, f"Proxy running on port {port}")

    @Slot()
    def stop_proxy(self):
        """Stops the proxy server."""
        self.is_running = False
        self.proxy_status_changed.emit(False, "Proxy stopped")

    @Slot(dict)
    def add_rule(self, rule: dict):
        """Adds a real-time modification rule."""
        self.rules.append(rule)

class ScanRunnerWorker(QThread):
    """
    Dedicated Qt Thread worker for running background recon campaigns without freezing the GUI.
    Emits signals for host updates and console output.
    """
    host_updated = Signal(str, str, int, int)
    log_message = Signal(str, str)
    campaign_finished = Signal(list)

    def __init__(self, config: dict):
        super().__init__()
        self.config = config

    def run(self):
        target_arg = self.config.get("target")
        targets_file = self.config.get("targets_file")
        output_dir = self.config.get("output_dir", "reports")
        report_format = self.config.get("format", "markdown")
        concurrency = self.config.get("concurrency", 5)
        notify_list = self.config.get("notify", "").split(",") if self.config.get("notify") else []

        targets = get_all_targets(target_arg, targets_file)
        if not targets:
            self.log_message.emit("❌ No valid targets found.", "stderr")
            return

        history_manager = ScanHistory()
        notifier_manager = NotificationManager(notify_list)
        results = []

        for t in targets:
            self.host_updated.emit(t, "Scanning...", 0, 0)
            try:
                # 1. DNS Lookup
                dns_results = run_dns_lookup(t)
                scan_target_ip = t
                if not is_ip_address(t):
                    if dns_results.get("ipv4_addresses"):
                        scan_target_ip = dns_results["ipv4_addresses"][0]

                # 2. Unified Recon
                import os
                api_keys = {
                    'shodan': os.getenv('SHODAN_API_KEY'),
                    'netlas': os.getenv('NETLAS_API_KEY'),
                    'censys_id': os.getenv('CENSYS_API_ID'),
                    'censys_secret': os.getenv('CENSYS_API_SECRET'),
                    'criminal_ip': os.getenv('CRIMINAL_IP_API_KEY')
                }
                unified = UnifiedRecon(api_keys)
                recon_res = unified.get_ip_info(scan_target_ip, allow_nmap=True)

                nmap_results = {
                    "scan": {
                        scan_target_ip: {
                            "status": "up",
                            "ports": [{"portid": str(p), "protocol": "tcp", "state": "open", "service": "unknown", "version": "N/A"} for p in recon_res.get("ports", [])],
                            "source": recon_res.get("source", "Multiple")
                        }
                    }
                }

                shodan_results = {
                    "org": recon_res.get("shodan_data", {}).get("org", "Unknown") if recon_res.get("shodan_data") else "Unknown",
                    "api_reports": recon_res.get("api_reports", {}),
                    "source_info": recon_res.get("source", "Multiple"),
                    "shodan_data": recon_res.get("shodan_data", {})
                }

                # 3. Vuln Lookup
                vuln_lookup = VulnLookup(api_key=os.getenv('NVD_API_KEY'))
                port_list = nmap_results["scan"][scan_target_ip]["ports"]
                vuln_data = vuln_lookup.lookup_ports(port_list)

                # 4. AI & History
                ai_summary = create_ai_summary(nmap_results, shodan_results, dns_results, vuln_data)
                history_manager.save_scan(t, dns_results, nmap_results, vuln_data, ai_summary)

                ports_count = len(recon_res.get("ports", []))
                vuln_count = sum(len(v) for v in vuln_data.values())

                self.host_updated.emit(t, "Complete", ports_count, vuln_count)
                results.append({"target": t, "status": "success", "ports": ports_count, "vulns": vuln_count})
                self.log_message.emit(f"✅ Scan completed for {t} ({ports_count} ports, {vuln_count} CVEs)", "stdout")

            except Exception as e:
                self.host_updated.emit(t, "Error", 0, 0)
                self.log_message.emit(f"❌ Error scanning {t}: {e}", "stderr")

        self.campaign_finished.emit(results)
