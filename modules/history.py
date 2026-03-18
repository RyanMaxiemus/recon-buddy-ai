import sqlite3
import json
import os
import logging
from datetime import datetime

log = logging.getLogger("RECON.History")

HISTORY_DIR = os.path.expanduser("~/.recon-buddy")
HISTORY_DB = os.path.join(HISTORY_DIR, "history.db")

class ScanHistory:
    def __init__(self):
        self.init_db()

    def init_db(self):
        """Initializes the scan history database."""
        try:
            os.makedirs(HISTORY_DIR, exist_ok=True)
            conn = sqlite3.connect(HISTORY_DB)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    timestamp DATETIME,
                    dns_json TEXT,
                    recon_json TEXT,
                    vuln_json TEXT,
                    ai_summary TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Failed to initialize history DB: {e}")

    def save_scan(self, target, dns_data, recon_data, vuln_data, ai_summary):
        """Saves a complete scan result to history."""
        try:
            conn = sqlite3.connect(HISTORY_DB)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (target, timestamp, dns_json, recon_json, vuln_json, ai_summary)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                target,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps(dns_data),
                json.dumps(recon_data),
                json.dumps(vuln_data),
                ai_summary
            ))
            conn.commit()
            conn.close()
            log.info(f"Scan for {target} saved to history.")
        except Exception as e:
            log.error(f"Failed to save scan to history: {e}")

    def get_last_scan(self, target):
        """Retrieves the most recent scan for a target."""
        try:
            conn = sqlite3.connect(HISTORY_DB)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT dns_json, recon_json, vuln_json, ai_summary, timestamp 
                FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 1
            ''', (target,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'dns_data': json.loads(row[0]),
                    'recon_data': json.loads(row[1]),
                    'vuln_data': json.loads(row[2]),
                    'ai_summary': row[3],
                    'timestamp': row[4]
                }
            return None
        except Exception as e:
            log.error(f"Failed to retrieve last scan: {e}")
            return None

    def list_history(self, target=None):
        """Lists all past scans, optionally filtered by target."""
        try:
            conn = sqlite3.connect(HISTORY_DB)
            cursor = conn.cursor()
            if target:
                cursor.execute("SELECT id, target, timestamp FROM scans WHERE target = ? ORDER BY timestamp DESC", (target,))
            else:
                cursor.execute("SELECT id, target, timestamp FROM scans ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            log.error(f"Failed to list history: {e}")
            return []

    def diff_scans(self, old_scan, new_scan):
        """
        Compares two scans and returns a structured diff.
        Identifies new/removed ports and changed versions.
        """
        diff = {
            'added_ports': [],
            'removed_ports': [],
            'changed_services': [],
            'new_vulns': [],
            'has_changes': False
        }
        
        if not old_scan:
            return None

        # 1. Compare Ports
        old_recon = old_scan.get('recon_data', {})
        new_recon = new_scan.get('recon_data', {})
        
        # Extract ports into dict for easy lookup: {portid: {info}}
        def get_ports_map(recon):
            p_map = {}
            for host, data in recon.get('scan', {}).items():
                for p in data.get('ports', []):
                    p_map[p.get('portid')] = p
            return p_map

        old_ports = get_ports_map(old_recon)
        new_ports = get_ports_map(new_recon)
        
        for pid in new_ports:
            if pid not in old_ports:
                diff['added_ports'].append(new_ports[pid])
                diff['has_changes'] = True
            else:
                # Check for version change
                if new_ports[pid].get('version') != old_ports[pid].get('version'):
                    diff['changed_services'].append({
                        'port': pid,
                        'old_version': old_ports[pid].get('version'),
                        'new_version': new_ports[pid].get('version'),
                        'service': new_ports[pid].get('service')
                    })
                    diff['has_changes'] = True
        
        for pid in old_ports:
            if pid not in new_ports:
                diff['removed_ports'].append(old_ports[pid])
                diff['has_changes'] = True

        # 2. Compare Vulns
        old_vulns = old_scan.get('vuln_data', {})
        new_vulns = new_scan.get('vuln_data', {})
        
        for key, vulns in new_vulns.items():
            old_vuln_ids = [v['id'] for v in old_vulns.get(key, [])]
            for v in vulns:
                if v['id'] not in old_vuln_ids:
                    diff['new_vulns'].append({'port_service': key, 'id': v['id'], 'severity': v.get('severity')})
                    diff['has_changes'] = True

        return diff
