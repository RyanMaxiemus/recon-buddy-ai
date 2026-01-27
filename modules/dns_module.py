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
        target: The IP address or domain name to query.

    Returns:
        A dictionary containing the results of the DNS lookups.
    """
    results = {}

    if is_ip_address(target):
        # --- Reverse Lookup (IP -> Domain) ---
        log.info(f"✅ [DNS] Performing reverse lookup for IP: {target}")
        try:
            # 1. Convert IP to the special reverse format (e.g., 8.8.8.8 -> 8.8.8.8.in-addr.arpa)
            rev_name = dns.reversename.from_address(target)

            # 2. Query the PTR (Pointer) record
            answers = dns.resolver.resolve(rev_name, 'PTR')

            # 3. Extract and clean the domain name
            results['reverse_hostnames'] = [str(r.target).rstrip('.') for r in answers]

        except dns.resolver.NoAnswer:
            results['reverse_hostnames'] = ["No PTR record found."]
        except Exception as e:
            results['reverse_hostnames'] = [f"Reverse DNS Error: {e}"]

    else:
        # --- Forward Lookup (Domain -> IP) ---
        log.info(f"✅ [DNS] Performing forward lookup for domain: {target}")

        # A Record (IPv4)
        try:
            answers = dns.resolver.resolve(target, 'A')
            results['ipv4_addresses'] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results['ipv4_addresses'] = ["No A record found."]
        except Exception as e:
            results['ipv4_addresses'] = [f"Forward DNS Error (A): {e}"]

        # AAAA Record (IPv6)
        try:
            answers = dns.resolver.resolve(target, 'AAAA')
            results['ipv6_addresses'] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results['ipv6_addresses'] = ["No AAAA record found."]
        except Exception as e:
            results['ipv6_addresses'] = [f"Forward DNS Error (AAAA): {e}"]

        # CNAME Record (Alias)
        try:
            answers = dns.resolver.resolve(target, 'CNAME')
            # CNAME points to another domain, not an IP
            results['canonical_name'] = [str(r.target).rstrip('.') for r in answers]
        except dns.resolver.NoAnswer:
            results['canonical_name'] = ["No CNAME record found."]
        except Exception as e:
            results['canonical_name'] = [f"CNAME Error: {e}"]

        # MX Record (Mail Exchange)
        try:
            answers = dns.resolver.resolve(target, 'MX')
            results['mx_records'] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
        except dns.resolver.NoAnswer:
            results['mx_records'] = ["No MX record found."]
        except Exception as e:
            results['mx_records'] = [f"MX Error: {e}"]

        # TXT Record
        try:
            answers = dns.resolver.resolve(target, 'TXT')
            results['txt_records'] = [str(r).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            results['txt_records'] = ["No TXT record found."]
        except Exception as e:
            results['txt_records'] = [f"TXT Error: {e}"]

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
