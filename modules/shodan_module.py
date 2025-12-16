import shodan
import os
import json
import logging
from dotenv import load_dotenv

# Get a module-specific logger instance
log = logging.getLogger("RECON.Scanner") # <-- Use a hierarchical name (e.g., RECON.Scanner)
# This will inherit the setup from the root logger configured in main.py

# Load environment variables from a .env file
load_dotenv()

# Get the Shodan API key from environment variables
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

def get_shodan_host_info(ip_address: str) -> dict:
    """
    Queries the Shodan API for host information based on IP address.
    
    Args:
        ip_address: The target IPv4 or IPv6 address.
    
    Returns:
        A dictionary containing the host information from Shodan, or an error dictionary.
    """
    if not SHODAN_API_KEY:
        log.error("❌ ERROR: SHODAN_API_KEY not found in environment variables.")
        return {"error": "Shodan API key missing."}
    
    try:
        # 1. Initialize the Shodan API object with the API key.
        api = shodan.Shodan(SHODAN_API_KEY)

        # 2. Lookup the host information.
        # The .host() method is the standard way to get all known data for an IP.
        print(f"    [Shodan] Querying Shodan for host information on {ip_address}...")
        host_info = api.host(ip_address)

        # We can return the raw dictionary directly. Shodan's output is already rich.
        # It includes ports, organization, CVEs, and the raw banners.
        return host_info
    
    except shodan.exception.APIError as e:
        # This handles errors like "No information available for that IP" or
        # API key issues, or if you run out of query credits.
        return {"error": "Shodan API Error", "ip": ip_address, "details": str(e)}
    except Exception as e:
        # General unexpected error handling
        return {"error": "Unexpected Error", "ip": ip_address, "details": str(e)}
    
if __name__ == "__main__":
    # Reminder: Replace '8.8.8.8' with an IP you want to test!
    # A test IP like '207.241.147.219' (Shodan's own IP) often works well for demos.
    test_ip = "8.8.8.8"

    shodan_data = get_shodan_host_info(test_ip)

    log.info("\n--- RAW SHODAN RESULT ---\n")
    # Pretty print the resulting dictionary as JSON
    log.info(json.dumps(shodan_data, indent=4))
    log.info("\n-------------------------\n")