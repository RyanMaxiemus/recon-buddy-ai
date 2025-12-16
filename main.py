import argparse
import json
import os
from dotenv import load_dotenv

# Import the logging setup
from log_config import setup_logging

# Initialize logging immediately
log = setup_logging() # Initialize and get the logger instance

# Make sure your project structure has 'modules' directory
from modules.scanner import run_basic_scan
from modules.dns_module import run_dns_lookup
from modules.shodan_module import get_shodan_host_info
from modules.ai_summarizer import create_ai_summary

# Load environment variables from a .env file (for API keys, etc.)
load_dotenv()

def orchestrate_recon(target: str) -> None:
    """
    Main function to execute the full recon and analysis pipeline:
    1. Performs DNS lookups.
    2. Determines the primary IP address.
    3. Runs a basic Nmap scan.
    4. Queries Shodan for additional host information.
    5. Generates an AI-driven security summary.
    6. Outputs the final report.

    Args:
        target: The IP address or domain name to scan.
    """
    log.info("=========================================")
    log.info(f"🕵️ Starting AI-Powered Recon on: {target}")
    log.info("=========================================")

    # 1. DNS Lookup (Get context and primary IP if we started with a domain)
    log.debug("🔍 Attempting DNS lookup for target: {target}") # <-- Use log.debug for detailed steps
    dns_results = run_dns_lookup(target)
    
    # 2. Determine the primary IP for scanning/Shodan. If the target was a domain, use the first resolved IP.
    scan_target_ip = target
    # Example for error handling with logging:
    if not is_ip_address(target):
        if dns_results.get('ipv4_addresses'):
            scan_target_ip = dns_results['ipv4_addresses'][0]
            log.info(f"✅ Resolved domain '{target}' to primary IP: {scan_target_ip}")
        else:
            log.error("❌ ERROR: Could not resolve domain to an IP. Aborting scan.")
            return

    # 3. Run Basic Nmap Scan
    nmap_json = run_basic_scan(scan_target_ip)
    nmap_results = json.loads(nmap_json)
    print(f"✅ Nmap scan complete for {scan_target_ip}.")

    # 4. Query Shodan for Host Information
    # We use the same IP for Shodan lookup.
    shodan_results = get_shodan_host_info(scan_target_ip)
    print(f"✅ Shodan lookup complete for {scan_target_ip}.")

    print("\n-----------------------------------------")
    print("🧠 Starting AI Analysis...")

    # 5. Generate AI-Driven Security Summary
    # Pass all structured data to the LLM for summarization.
    final_summary_report = create_ai_summary(nmap_results, shodan_results, dns_results)
    
    print("✅ Analysis complete. Final Report:")
    print("-----------------------------------------\n")
    
    # 6. Output the result
    print(final_summary_report)

def main():
    # Set up argument parsing for command-line execution
    parser = argparse.ArgumentParser(
        description="AI-Powered Network Reconnaissance and Analysis Tool.")
    parser.add_argument(
        '--target',
        required=True,
        help='The IP address or hostname to scan (e.g., 192.168.1.1 or scanme.nmap.org).'
    )

    # For future arguments (e.g., --output, --llm-model, --ports)
    # parser.add_argument(...)

    args = parser.parse_args()

    # Check for root/admin privileges needed for SYN scan (Nmap -sS)
    if os.geteuid() != 0:
        print("⚠️ WARNING: Nmap SYN scan (-sS) requires root/administrator privileges.")
        print("   Falling back to a less stealthy connect scan (-sT) if needed, or run with 'sudo'.")
        # In a real tool, you would dynamically change the scan argument here.

    # Start the recon process
    orchestrate_recon(args.target)

if __name__ == "__main__":
    main()