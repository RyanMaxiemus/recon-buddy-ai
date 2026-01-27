import json
import logging
from datetime import datetime

# Get the logger instance from the root logging setup
log = logging.getLogger("RECON.Reporter")

def format_nmap_ports(nmap_dict: dict) -> str:
    """
    Extracts open ports and services from the Nmap JSON and formats them into a clean Markdown table.
    """
    # Initialize the table header
    table_content = "| Port | Protocol | State | Service | Version |\n"
    table_content += "|------|----------|-------|---------|---------|\n"

    try:
        # Nmap results are often nested under the IP key
        for host, data in nmap_dict.get('scan', {}).items():
            if data.get('ports'):
                for port_entry in data['ports']:
                    # Handle both dict and string port entries
                    if isinstance(port_entry, dict):
                        port = port_entry.get('portid', 'N/A')
                        protocol = port_entry.get('protocol', 'tcp')
                        state = port_entry.get('state', 'unknown')
                        service = port_entry.get('service', 'N/A')
                        version = port_entry.get('version', 'N/A')
                    else:
                        # Handle simple port numbers
                        port = str(port_entry)
                        protocol = 'tcp'
                        state = 'open'
                        service = 'N/A'
                        version = 'N/A'

                    # Append the formatted row to the table content
                    table_content += f"| {port} | {protocol} | **{state.upper()}** | {service} | {version} |\n"
                break  # Process only the first host for simplicity
            elif data.get('protocols'):
                # Handle the old format with protocols
                for proto, ports in data.get('protocols', {}).items():
                    for port, port_info in ports.items():
                        service = port_info.get('name', 'N/A')
                        version = port_info.get('version', 'N/A')
                        state = port_info.get('state', 'unknown')

                        table_content += f"| {port} | {proto} | **{state.upper()}** | {service} | {version} |\n"
                break
    except Exception as e:
        log.error(f"Error formatting Nmap ports: {e}")
        table_content += f"\n*Nmap data formatting failed due to an internal error: {e}*\n"

    return table_content

def generate_markdown_report(target: str, nmap_data: dict, shodan_data: dict, dns_data: dict, ai_summary: str, output_path: str) -> bool:
    """
    Creates the final structured Markdown report file.
    Now supports unified recon data with full Shodan integration.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract primary IP from nmap_data (unified recon format)
    primary_ip = "N/A"
    for host in nmap_data.get('scan', {}).keys():
        primary_ip = host
        break

    # Extract data source information
    data_source = shodan_data.get('source_info', 'Multiple Sources')
    api_reports = shodan_data.get('api_reports', {})
    api_status_str = ", ".join([f"{api}: {status}" for api, status in api_reports.items()])

    # Extract Shodan-specific data if available
    shodan_info = shodan_data.get('shodan_data', {})

    # --- 1. Assemble the Report Sections ---

    # 1.1 Header and Metadata
    report_content = f"""# Reconnaissance and Analysis Report: {target}

* **Target:** `{target}`
* **Primary IP:** `{primary_ip}`
* **Data Source:** {data_source}
* **Report Generated:** {timestamp}

## 🧠 AI-Generated Security Summary

{ai_summary}

---

## 🔎 Technical Findings

### A. Network Footprint (Unified Recon)

The following open ports were detected on the target IP:

{format_nmap_ports(nmap_data)}

### B. Reconnaissance Data Sources

| Data Source | Status |
| :---| :---|
{chr(10).join([f"| {api} | {status} |" for api, status in api_reports.items()]) if api_reports else "| No API Reports | N/A |"}

**Primary Source Used:** {data_source}

### C. Host Intelligence (Shodan Data)

{format_shodan_data(shodan_info) if shodan_info else "No Shodan data available."}

### D. DNS Records

| Record Type | Data |
| :---| :---|
| IPv4 Addresses | `{', '.join(dns_data.get('ipv4_addresses', ['N/A']))}` |
| IPv6 Addresses | `{', '.join(dns_data.get('ipv6_addresses', ['N/A']))}` |
| Hostnames (PTR) | `{', '.join(dns_data.get('reverse_hostnames', ['N/A']))}` |
| Canonical Name (CNAME) | `{', '.join(dns_data.get('canonical_name', ['N/A']))}` |
| Mail Exchange (MX) | `{', '.join(dns_data.get('mx_records', ['N/A']))}` |
| TXT Records | `{', '.join(dns_data.get('txt_records', ['N/A'])[:3])}{'...' if len(dns_data.get('txt_records', [])) > 3 else ''}` |

---

## 💾 Raw Data Dump (For Auditing)

This section contains the full, raw JSON output from the tools used for detailed auditing.

### Raw Unified Recon Output

```json
{json.dumps(nmap_data, indent=2)}
```

### Raw API Reports & Source Info

```json
{json.dumps(shodan_data, indent=2)}
```

### Raw DNS Output

```json
{json.dumps(dns_data, indent=2)}
```
"""

    # --- 2. Write to File ---
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        log.info(f"✅ Markdown Report successfully saved to: {output_path}")
        return True
    except Exception as e:
        log.critical(f"❌ Failed to write Markdown report file to {output_path}. Error: {e}")
        return False

def format_shodan_data(shodan_info: dict) -> str:
    """
    Formats Shodan data into a readable markdown section.
    """
    if not shodan_info:
        return "No Shodan data available."

    content = "| Attribute | Value |\n| :--- | :--- |\n"

    # Organization
    if shodan_info.get('org'):
        content += f"| Organization | {shodan_info['org']} |\n"

    # Location
    if shodan_info.get('country') or shodan_info.get('city'):
        location = f"{shodan_info.get('city', 'Unknown')}, {shodan_info.get('country', 'Unknown')}"
        content += f"| Location | {location} |\n"

    # ISP
    if shodan_info.get('isp'):
        content += f"| ISP | {shodan_info['isp']} |\n"

    # Hostnames
    if shodan_info.get('hostnames'):
        hostnames = ', '.join(shodan_info['hostnames'][:3])
        if len(shodan_info['hostnames']) > 3:
            hostnames += '...'
        content += f"| Hostnames | {hostnames} |\n"

    # Tags
    if shodan_info.get('tags'):
        tags = ', '.join(shodan_info['tags'][:5])
        if len(shodan_info['tags']) > 5:
            tags += '...'
        content += f"| Tags | {tags} |\n"

    # Vulnerabilities
    if shodan_info.get('vulns'):
        vulns = ', '.join(list(shodan_info['vulns'])[:5])
        if len(shodan_info['vulns']) > 5:
            vulns += '...'
        content += f"| Vulnerabilities | {vulns} |\n"

    # Last Update
    if shodan_info.get('last_update'):
        content += f"| Last Update | {shodan_info['last_update']} |\n"

    return content
