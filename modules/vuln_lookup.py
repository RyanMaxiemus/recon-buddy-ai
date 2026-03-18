import json
import logging
import os
import sqlite3
import time
import requests
from datetime import datetime, timedelta

log = logging.getLogger("RECON.VulnLookup")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.expanduser("~/.recon-buddy")
CACHE_DB = os.path.join(CACHE_DIR, "vuln_cache.db")

class VulnLookup:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.last_query_time = 0
        self.init_cache()

    def init_cache(self):
        """Initializes the local SQLite cache."""
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            conn = sqlite3.connect(CACHE_DB)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vuln_cache (
                    cpe TEXT PRIMARY KEY,
                    vuln_data TEXT,
                    timestamp DATETIME
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Failed to initialize cache: {e}")

    def get_cached_vulns(self, cpe):
        """Retrieves cached vulnerabilities for a CPE."""
        try:
            conn = sqlite3.connect(CACHE_DB)
            cursor = conn.cursor()
            # Only use cache if it's less than 7 days old
            cursor.execute("SELECT vuln_data, timestamp FROM vuln_cache WHERE cpe = ?", (cpe,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                vuln_data, timestamp = row
                cached_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                if datetime.now() - cached_time < timedelta(days=7):
                    return json.loads(vuln_data)
            return None
        except Exception as e:
            log.error(f"Cache lookup failed: {e}")
            return None

    def cache_vulns(self, cpe, vuln_data):
        """Stores vulnerabilities in the local cache."""
        try:
            conn = sqlite3.connect(CACHE_DB)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO vuln_cache (cpe, vuln_data, timestamp) VALUES (?, ?, ?)",
                (cpe, json.dumps(vuln_data), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Cache storage failed: {e}")

    def construct_cpe(self, service_name, version):
        """
        Constructs a best-guess CPE 2.3 string from service name and version.
        This is a heuristic and may not be 100% accurate.
        """
        if not service_name or not version or version == "N/A":
            return None
        
        # Simple mapping for common services
        vendor_map = {
            'nginx': 'nginx',
            'apache': 'apache',
            'httpd': 'apache',
            'openssh': 'openbsd',
            'ssh': 'openbsd',
            'iis': 'microsoft',
            'mysql': 'oracle',
            'postgresql': 'postgresql',
            'redis': 'redislabs'
        }
        
        name = service_name.lower().replace(' ', '_')
        vendor = vendor_map.get(name, name)
        
        # Format: cpe:2.3:a:VENDOR:PRODUCT:VERSION
        return f"cpe:2.3:a:{vendor}:{name}:{version}"

    def query_nvd(self, cpe):
        """Queries the NVD API for a specific CPE."""
        if not cpe:
            return []

        # Check Cache first
        cached = self.get_cached_vulns(cpe)
        if cached is not None:
            log.debug(f"Cache hit for CPE: {cpe}")
            return cached

        # Rate limiting (NVD suggests no more than 5 requests per 30 seconds WITHOUT key,
        # but with key we can go faster. We'll still wait 1s to be safe).
        elapsed = time.time() - self.last_query_time
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)

        params = {'virtualMatchString': cpe}
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            log.info(f"Querying NVD for: {cpe}")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
            self.last_query_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                vulns = []
                for vuln_item in data.get('vulnerabilities', []):
                    cve = vuln_item.get('cve', {})
                    vulns.append({
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value'),
                        'baseScore': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')
                    })
                
                self.cache_vulns(cpe, vulns)
                return vulns
            elif response.status_code == 403:
                log.error("NVD API Key rejected or rate limit exceeded.")
                return []
            else:
                log.error(f"NVD API Error: {response.status_code}")
                return []
        except Exception as e:
            log.error(f"Failed to query NVD: {e}")
            return []

    def lookup_ports(self, ports_list):
        """Helper to lookup multiple ports' vulns."""
        all_vulns = {}
        for port_info in ports_list:
            service = port_info.get('service')
            version = port_info.get('version')
            if service and version and version != "N/A":
                cpe = self.construct_cpe(service, version)
                if cpe:
                    vulns = self.query_nvd(cpe)
                    if vulns:
                        all_vulns[f"{port_info.get('portid')}/{service}"] = vulns
        return all_vulns
