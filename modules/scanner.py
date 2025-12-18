import nmap
import json
import logging

# Get a module-specific logger instance
log = logging.getLogger("RECON.Scanner") # <-- Use a hierarchical name (e.g., RECON.Scanner)
# This will inherit the setup from the root logger configured in main.py

def run_basic_scan(target_ip: str,ports: str = '22,80,443,8080') -> str:
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
        # The output of scan is a structured dictionary.
        log.info(f" [Nmap] Scanning {target_ip} on ports {ports} with args: {scan_args}")
        nm.scan(hosts=target_ip,arguments=scan_args)

        # 4. Get the result in the 'nmap_report' format, which is a big dictionary.
        # This is the 'raw' structured output we want from Nmap.
        raw_result_dict = nm.nmap_report()

        # 5. Convert the Python dictionary to a clean JSON string for easier consumption.
        # The 'indent=4' makes the JSON output human-readable in the console.
        json_output = json.dumps(raw_result_dict, indent=4)

        return json_output
    
    except nmap.PortScannerError as e:
        log.exception("Nmap Scan Failed!")
        return json.dumps({"error": "Nmap Scan Error", "details": str(e)})
    except Exception as e:
        return json.dumps({"error": "General Error", "details": str(e)})
    
if __name__ == "__main__":
    # Example usage when running the script directly.
    test_target = 'scanme.nmap.org' # Always use scanme.nmap.org for testing.

    log.info(f"--- STARTING SCAN on {test_target} ---")

    # Run the scan and get the JSON output.
    scan_json = run_basic_scan(test_target)

    log.info("\n--- RAW JSON RESULT ---\n")
    log.info(scan_json)
    log.info("\n-----------------------\n")