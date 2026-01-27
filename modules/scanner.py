import nmap
import json
import logging
import requests
import os

try:
    import netlas
    HAS_NETLAS = True
except ImportError:
    HAS_NETLAS = False

try:
    from censys.search import CensysHosts
    HAS_CENSYS = True
except ImportError:
    HAS_CENSYS = False

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

# Get a module-specific logger instance
log = logging.getLogger("RECON.Scanner")

class UnifiedRecon:
    """
    Unified reconnaissance class that queries multiple data sources in priority order.
    Sources: Shodan -> Netlas -> Criminal IP -> Censys -> Nmap (fallback)
    """

    def __init__(self, keys):
        """
        Initialize the UnifiedRecon scanner with API keys.

        Args:
            keys: Dictionary with optional API keys:
                - 'shodan': Shodan API key
                - 'netlas': Netlas API key
                - 'censys_id': Censys API ID
                - 'censys_secret': Censys API Secret
                - 'criminal_ip': Criminal IP API key
        """
        self.keys = keys
        self.api_status = {}  # Track API availability

        # Initialize Shodan connection
        if HAS_SHODAN and keys.get('shodan'):
            try:
                self.shodan_conn = shodan.Shodan(keys.get('shodan'))
                log.info("✅ Shodan connection initialized")
            except Exception as e:
                log.warning(f"❌ Shodan initialization failed: {e}")
                self.shodan_conn = None
        else:
            self.shodan_conn = None

        # Initialize Netlas connection
        if HAS_NETLAS and keys.get('netlas'):
            try:
                self.netlas_conn = netlas.Netlas(api_key=keys.get('netlas'))
                log.info("✅ Netlas connection initialized")
            except Exception as e:
                log.warning(f"❌ Netlas initialization failed: {e}")
                self.netlas_conn = None
        else:
            self.netlas_conn = None

        # Initialize Censys connection
        if HAS_CENSYS and keys.get('censys_id') and keys.get('censys_secret'):
            try:
                self.censys_conn = CensysHosts(
                    api_id=keys.get('censys_id'),
                    api_secret=keys.get('censys_secret')
                )
                log.info("✅ Censys connection initialized")
            except Exception as e:
                log.warning(f"❌ Censys initialization failed: {e}")
                self.censys_conn = None
        else:
            self.censys_conn = None

        self.nm = nmap.PortScanner()

    def get_shodan_info(self, ip):
        """Query Shodan for host information."""
        if not self.shodan_conn:
            return None

        try:
            log.info(f"📡 [Shodan] Querying {ip}...")
            host_info = self.shodan_conn.host(ip)

            # Extract ports from Shodan data
            ports = [service.get('port') for service in host_info.get('data', []) if service.get('port')]

            return {
                'ports': ports,
                'org': host_info.get('org', 'Unknown'),
                'hostnames': host_info.get('hostnames', []),
                'country': host_info.get('country_name', 'Unknown'),
                'city': host_info.get('city', 'Unknown'),
                'isp': host_info.get('isp', 'Unknown'),
                'tags': host_info.get('tags', []),
                'vulns': list(host_info.get('vulns', [])),
                'last_update': host_info.get('last_update', 'Unknown'),
                'raw_data': host_info
            }
        except shodan.APIError as e:
            log.warning(f"⚠️ [Shodan] API Error: {e}")
            return None
        except Exception as e:
            log.warning(f"⚠️ [Shodan] Error: {e}")
            return None

    def get_ip_info(self, ip, allow_nmap=False):
        """
        Fetches IP data from multiple sources in priority order.

        Args:
            ip: The IP address to scan
            allow_nmap: Set to True to enable local Nmap scanning if APIs fail

        Returns:
            Dictionary with keys: ip, ports, source, api_reports, shodan_data, error (if applicable)
        """
        results = {
            "ip": ip,
            "ports": [],
            "source": None,
            "api_reports": {},
            "shodan_data": None
        }

        # 1. Try Shodan first (most comprehensive data)
        if self.shodan_conn:
            shodan_data = self.get_shodan_info(ip)
            if shodan_data:
                results["ports"] = shodan_data['ports']
                results["source"] = "Shodan"
                results["api_reports"]["Shodan"] = "Success"
                results["shodan_data"] = shodan_data
                log.info(f"✅ [Shodan] Found {len(results['ports'])} open ports")
                return results
            else:
                results["api_reports"]["Shodan"] = "Failed/No data"

        # 2. Try Netlas
        if self.netlas_conn:
            try:
                log.info(f"📡 [Netlas] Querying {ip}...")
                data = self.netlas_conn.host(ip=ip)
                results["ports"] = [obj['port'] for obj in data.get('data', [])]
                results["source"] = "Netlas"
                results["api_reports"]["Netlas"] = "Success"
                log.info(f"✅ [Netlas] Found {len(results['ports'])} open ports")
                return results
            except Exception as e:
                error_msg = f"Failed/Limited: {str(e)}"
                results["api_reports"]["Netlas"] = error_msg
                log.warning(f"⚠️ [Netlas] {error_msg}")

        # 3. Try Criminal IP
        if self.keys.get('criminal_ip'):
            try:
                log.info(f"📡 [CriminalIP] Querying {ip}...")
                headers = {"x-api-key": self.keys["criminal_ip"]}
                resp = requests.get(
                    f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}",
                    headers=headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results["ports"] = [p["port"] for p in data.get('port_stats', [])]
                    results["source"] = "CriminalIP"
                    results["api_reports"]["CriminalIP"] = "Success"
                    log.info(f"✅ [CriminalIP] Found {len(results['ports'])} open ports")
                    return results
                else:
                    error_msg = f"HTTP {resp.status_code} (Likely Rate Limited)"
                    results["api_reports"]["CriminalIP"] = error_msg
                    log.warning(f"⚠️ [CriminalIP] {error_msg}")
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                results["api_reports"]["CriminalIP"] = error_msg
                log.warning(f"⚠️ [CriminalIP] {error_msg}")

        # 4. Try Censys
        if self.censys_conn:
            try:
                log.info(f"📡 [Censys] Querying {ip}...")
                host = self.censys_conn.view(ip)
                results["ports"] = [p["port"] for p in host.get("services", [])]
                results["source"] = "Censys"
                results["api_reports"]["Censys"] = "Success"
                log.info(f"✅ [Censys] Found {len(results['ports'])} open ports")
                return results
            except Exception as e:
                error_msg = f"Failed/Limited: {str(e)}"
                results["api_reports"]["Censys"] = error_msg
                log.warning(f"⚠️ [Censys] {error_msg}")

        # 5. Final Fallback: The "Manual" Nmap Trigger
        if allow_nmap:
            log.info(f"📡 All APIs failed. Executing manual Nmap scan for {ip}...")
            return self._run_nmap(ip, results)

        results["error"] = "No API data found and Nmap scan was not authorized."
        log.error(results["error"])
        return results

    def _run_nmap(self, ip, results):
        """
        Fallback method to run a local Nmap scan if all APIs fail.

        Args:
            ip: The IP address to scan
            results: Dictionary to populate with results

        Returns:
            Updated results dictionary
        """
        try:
            log.info(f"🔍 [Nmap] Running fast scan (-F) on {ip}...")
            self.nm.scan(ip, arguments='-F -T4')
            if ip in self.nm.all_hosts():
                results["ports"] = list(self.nm[ip]['tcp'].keys()) if 'tcp' in self.nm[ip] else []
                results["source"] = "Local Nmap"
                results["api_reports"]["Nmap"] = "Success (Fallback)"
                log.info(f"✅ [Nmap] Found {len(results['ports'])} open ports")
                return results
            results["error"] = "Nmap couldn't find the host."
            log.error(results["error"])
        except Exception as e:
            results["error"] = f"Nmap Error: {str(e)}"
            log.exception("Nmap scan failed")
        return results

def run_basic_scan(target_ip: str, ports: str = '22,80,443,8080') -> str:
    """
    Runs a basic Nmap scan on the target IP for specified ports and returns the result as a JSON string.
    Args:
        target_ip: The IP address or hostname to scan.
        ports: A comma-separated string of ports to scan.

    Returns:
        A JSON string representation of the scan results.
    """
    try:
        # 1. Initialize the Nmap PortScanner object.
        nm = nmap.PortScanner()

        # 2. Define the Nmap scan arguments.
        # -sT: TCP Connect Scan (no root required, works without sudo)
        # -T4: Faster execution (aggressive timing)
        # -p: Specify ports to scan
        scan_args = f'-sT -T4 -p {ports}'

        # 3. Execute the Nmap scan on the target IP with the defined arguments.
        log.info(f"✅ [Nmap] Scanning {target_ip} on ports {ports} with args: {scan_args}")
        nm.scan(hosts=target_ip, arguments=scan_args)

        # 4. Convert the PortScanner object to a dictionary format.
        raw_result_dict = {
            'scan': {},
            'nmap': {'command_line': nm.command_line(), 'scanstats': nm.scanstats()}
        }

        # Include detailed port information
        for host in nm.all_hosts():
            raw_result_dict['scan'][host] = {
                'status': nm[host].state(),
                'ports': []
            }
            for proto in nm[host].all_protocols():
                ports_info = nm[host][proto]
                for port in ports_info:
                    port_info = {
                        'portid': str(port),
                        'protocol': proto,
                        'state': ports_info[port]['state'],
                        'service': ports_info[port].get('name', 'unknown'),
                        'version': ports_info[port].get('version', 'unknown')
                    }
                    raw_result_dict['scan'][host]['ports'].append(port_info)

        # 5. Convert the Python dictionary to a clean JSON string for easier consumption.
        json_output = json.dumps(raw_result_dict, indent=4, default=str)
        return json_output

    except nmap.PortScannerError as e:
        log.exception("Nmap Scan Failed!")
        return json.dumps({"error": "Nmap Scan Error", "details": str(e)})
    except Exception as e:
        log.exception("General scan error")
        return json.dumps({"error": "General Error", "details": str(e)})

if __name__ == "__main__":
    # Example usage when running the script directly.
    test_target = 'scanme.nmap.org'  # Always use scanme.nmap.org for testing.

    log.info(f"--- STARTING SCAN on {test_target} ---")

    # Run the scan and get the JSON output.
    scan_json = run_basic_scan(test_target)

    log.info("\n--- RAW JSON RESULT ---\n")
    log.info(scan_json)
    log.info("\n-----------------------\n")
