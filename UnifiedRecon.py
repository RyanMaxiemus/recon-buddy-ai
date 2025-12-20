import nmap
import json
import requests
import netlas
from censys.search import CensysHosts

class UnifiedRecon:
    def __init__(self, keys):
        self.keys = keys
        self.api_status = {} # Track who is ghosting us

        # Initialize connections
        self.netlas_conn = netlas.Netlas(api_key=keys.get('netlas')) if keys.get('netlas') else None
        self.censys_conn = CensysHosts(api_id=keys.get('censys_id'), api_secret=keys.get('censys_secret')) if keys.get('censys_id') else None
        self.nm = nmap.PortScanner()

    def get_ip_info(self, ip, allow_nmap=False):
        """
        Fetches IP data.
        
        :param allow_nmap: Set to True to enable local scanning if APIs fail.
        """
        results = {"ip": ip, "ports": [], "source": None, "api_reports": {}}

        # 1. Try Netlas
        if self.netlas_conn:
            try:
                data = self.netlas_conn.host(ip=ip)
                results["ports"] = [obj['port'] for obj in data.get('data', [])]
                results["source"] = "Netlas"
                results["api_reports"]["Netlas"] = "Success"
                return results
            except Exception as e:
                results["api_reports"]["Netlas"] = f"Failed/Limited: {str(e)}"

        # 2. Try Criminal IP
        if self.keys.get('criminal_ip'):
            try:
                headers = {"x-api-key": self.keys["criminal_ip"]}
                resp = requests.get(f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}", headers=headers, timeout=5)
                if resp.status_code == 200:
                    results["ports"] = [p["port"] for p in resp.json().get('port_stats', [])]
                    results["source"] = "CriminalIP"
                    results["api_reports"]["CriminalIP"] = "Success"
                    return results
                else:
                    results["api_reports"]["CriminalIP"] = f"HTTP {resp.status_code} (Likely Rate Limited)"
            except Exception as e:
                results["api_reports"]["CriminalIP"] = f"Error: {str(e)}"

        # 3.Try Censys
        if self.censys_conn:
            try:
                host = self.censys_conn.view(ip)
                results["ports"] = [p["port"] for p in host.get("services", [])]
                results["source"] = "Censys"
                results["api_reports"]["Censys"] = "Success"
                return results
            except Exception as e:
                results["api_reports"]["Censys"] = f"Failed/Limited: {str(e)}"

        # 4. Final Fallback: The "Manual" Nmap Trigger
        if allow_nmap:
            print(f"📡 All APIs failed. Executing manual Nmap scan for {ip}...")
            return self._run_nmap(ip, results)
        
        results["error"] = "No API data found and Nmap scan was not authorized."
        return results
    
    def _run_nmap(self, ip, results):
        try:
            self.nm.scan(ip, arguments='-F') 
            if ip in self.nm.all_hosts():
                results["ports"] = list(self.nm[ip]['tcp'].keys()) if 'tcp' in self.nm[ip] else []
                results["source"] = "Local Nmap"
                return results
            results["error"] = "Nmap couldn't find the host."
        except Exception as e:
            results["error"] = f"Nmap Error: {str(e)}"
        return results

# Example Usage:
MY_KEYS = {'netlas': 'NETLAS_API_KEY', 'criminal_ip': 'CRIMINAL_IP_API_KEY', 'censys': 'CENSYS_API_KEY'}
scanner = UnifiedRecon(MY_KEYS)

# This will fail gracefully if APIs are down because allow_nmap defaults to False
print(json.dumps(scanner.get_ip_info("8.8.8.8"), indent=2))

# This will actually fire up Nmap if the APIs tell you to go away
# print(json.dumps(scanner.get_ip_info("8.8.8.8", allow_nmap=True), indent=2))