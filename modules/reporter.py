import json
import logging
from datetime import datetime

# Get the logger instance from the root logging setup
logger = logging.getLogger("RECON.Reporter")

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
                    port = port_entry['portid']
                    protocol = port_entry['protocol']
                    state = port_entry['state']
                    service = port_entry.get('service', {}).get('name', 'N/A')
                    version = port_entry.get('service', {}).get('version', 'N/A')

                    # Append the formatted row to the table content
                    table_content += f"| {port} | {protocol} | **{state.upper()}** | {service} | {version} |\n"
                    break # Process only the first host for simplicity
    except Exception as e:
        log.error(f"Error formatting Nmap ports: {e}")
        table_content += f"\n*Nmap data formatting failed due to an internal error.*\n"

    return table_content

def generate_markdown_report(target: str, nmap_data: dict, shodan_data: dict, dns_data: dict, ai_summary: str, output_path: str) -> bool:
    """
    Creates the final structured Markdown report file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # --- 1. Assemble the Report Sections ---

    # 1.1 Header and Metadata
    report_content = f"""# Reconnaissance and Analysis Report: {target}\n\n

* **Target:** `{target}`
* **Primary IP:** `{nmap_data.get('scan', {}).get(target, {}).get('addresses', {}).get('ipv4', 'N/A')}`
* **Report Generated:** {timestamp}

## 🧠 AI-Generated Security Summary

{ai_summary}

---

## 🔎 Technical Findings

### A. Network Footprint (Nmap)

The following open ports were detected on the target IP:

{format_nmap_ports(nmap_data)}

### B. External Intelligence (Shodan)

| Metric | Detail |
| :---| :---|
| Organization | `{shodan_data.get('org', 'N/A')}` |
| Hostnames | `{', '.join(shodan_data.get('hostnames', ['N/A']))}` |
| Tags | `{', '.join(shodan_data.get('tags', ['N/A']))}` |
| Last Update | `{shodan_data.get('last_update', 'N/A')}` |
| Reported CVEs | `{len(shodan_data.get('vulns', []))}` |

### C. DNS Records

| Record Type | Data |
| :---| :---|
| IPv4 Addresses | `{', '.join(dns_data.get('ipv4_addresses', ['N/A']))}` |
| Hostnames (PTR) | `{', '.join(dns_data.get('reverse_hostnames', ['N/A']))}` |
| Canonical Name (CNAME) | `{', '.join(dns_data.get('canonical_name', ['N/A']))}` |

---

## 💾 Raw Data Dump (For Auditing)

This section contains the full, raw JSON output from the tools used for detailed auditing.

### Raw Nmap Output

```json
{json.dumps(nmap_data, indent=2)}
{json.dumps(shodan_data, indent=2)}
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