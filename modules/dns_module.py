import dns.resolver
import dns.reversename
import logging
from ipaddress import IPv4Address, IPv6Address, AddressValueError

# Get a module-specific logger instance
log = logging.getLogger("RECON.Scanner") # <-- Use a hierarchical name (e.g., RECON.Scanner)
# This will inherit the setup from the root logger configured in main.py

def is_ip_address(target: str) -> bool:
    """Checks if the target string is a valid IPv4 or IPv6 address."""
    try:
        IPv4Address(target)
        return True
    except AddressValueError:
        try:
            IPv6Address(target)
            return True
        except AddressValueError:
            return False
        
def run_dns_lookup(target: str) -> dict:
    """
    Performs reverse and forward DNS lookup based on the target type (IP or Domain).

    Args:
        target: The IP adress or domain name to query.

    Returns:
        A dictionary containing the results of the DNS lookups.
    """
    results = {}

    if is_ip_address(target):
        # --- Revers Lookup (IP -> Domain) ---
        log.info(f"✅ [DNS] Performing reverse lookup for IP: {target}")
        try:
            # 1. Convert IP to the special reverse format (e.g., 8.8.8.8 -> 8.8.8.8.in-addr.arpa)
            rev_name = dns.reversename.from_address(target)

            # 2. Query the PTR (Pointer) record
            answers  = dns.resolver.resolve(rev_name, 'PTR')

            # 3. Extract and clean the domain name
            results['reverse_hostnames'] = [str(r.target).rstrip('.') for r in answers]

        except dns.resolver.NoAnswer:
            results['reverse_hostnames'] = ["No PTR record found."]
        except Exception as e:
            results['error'] = f"Forward DNS Error (A): {e}"

        # CNAME Record (Alias)
        try:
            answers = dns.resolver.resolve(target, 'CNAME')
            # CNAME points to another domain, not an IP
            results['canonical_name'] = [str(r.target).rstrip('.') for r in answers]
        except dns.resolver.NoAnswer:
            results['canonical_name'] = ["No CNAME record found."]
        except Exception as e:
            # We don't want a CNAME error to crash the script if A is working.
            pass

    return results

if __name__ == "__main__":
    # Test 1: Domain Lookup (Forward)
    domain_result = run_dns_lookup("google.com")
    log.info("\n --- GOOGLE.COM LOOKUP ---")
    log.info(domain_result)

    # Test 2: IP Lookup (Reverse)
    # Using one of Google's public DNS IPs
    ip_result = run_dns_lookup("8.8.8.8")
    log.info("\n --- 8.8.8.8 LOOKUP (PTR) ---")
    log.info(ip_result)