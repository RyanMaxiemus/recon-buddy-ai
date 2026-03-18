import json
import logging
import os
import re
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# Get the logger instance from the root logging setup
log = logging.getLogger("RECON.Reporter")


def format_nmap_ports(nmap_dict: dict, vuln_data: dict = None) -> str:
    """
    Extracts open ports and services from the Nmap JSON and formats them into a clean Markdown table.
    """
    table_content = "| Port | Protocol | State | Service | Version | CVEs |\n"
    table_content += "|------|----------|-------|---------|---------|------|\n"

    try:
        for host, data in nmap_dict.get('scan', {}).items():
            if data.get('ports'):
                for port_entry in data['ports']:
                    if isinstance(port_entry, dict):
                        port = port_entry.get('portid', 'N/A')
                        protocol = port_entry.get('protocol', 'tcp')
                        state = port_entry.get('state', 'unknown')
                        service = port_entry.get('service', 'N/A')
                        version = port_entry.get('version', 'N/A')
                    else:
                        port = str(port_entry)
                        protocol = 'tcp'
                        state = 'open'
                        service = 'N/A'
                        version = 'N/A'

                    cve_str = "None"
                    if vuln_data:
                        key = f"{port}/{service}"
                        if key in vuln_data:
                            cve_str = ", ".join([v['id'] for v in vuln_data[key][:3]])
                            if len(vuln_data[key]) > 3: cve_str += "..."

                    table_content += f"| {port} | {protocol} | **{state.upper()}** | {service} | {version} | {cve_str} |\n"
                break
    except Exception as e:
        log.error(f"Error formatting Nmap ports: {e}")
        table_content += f"\n*Nmap data formatting failed: {e}*\n"

    return table_content


def format_diff_markdown(diff: dict) -> str:
    """Formats the scan diff into a clean Markdown section."""
    if not diff or not diff.get('has_changes'):
        return "No changes detected since the last scan."

    content = "### 🔄 Changes Since Last Scan\n\n"
    
    if diff.get('added_ports'):
        content += "**New Ports Detected:**\n"
        for p in diff['added_ports']:
            content += f"- `{p.get('portid')}/{p.get('protocol')}` ({p.get('service')} {p.get('version')})\n"
        content += "\n"

    if diff.get('removed_ports'):
        content += "**Ports No Longer Visible:**\n"
        for p in diff['removed_ports']:
            content += f"- `{p.get('portid')}/{p.get('protocol')}`\n"
        content += "\n"

    if diff.get('changed_services'):
        content += "**Version/Service Changes:**\n"
        for c in diff['changed_services']:
            content += f"- Port `{c['port']}`: `{c['old_version']}` ➔ `{c['new_version']}`\n"
        content += "\n"

    if diff.get('new_vulns'):
        content += "**New Vulnerabilities Found:**\n"
        for v in diff['new_vulns']:
            content += f"- `{v['id']}` on `{v['port_service']}` (Severity: {v.get('severity')})\n"
        content += "\n"

    return content


def generate_markdown_report(target: str, nmap_data: dict, shodan_data: dict, dns_data: dict, ai_summary: str, output_filename: str, output_dir: str = "reports", vuln_data: dict = None, diff: dict = None) -> bool:
    """
    Creates the final structured Markdown report file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    primary_ip = next(iter(nmap_data.get('scan', {}).keys()), "N/A")
    data_source = shodan_data.get('source_info', 'Multiple Sources')
    api_reports = shodan_data.get('api_reports', {})
    shodan_info = shodan_data.get('shodan_data', {})

    report_content = f"""# Reconnaissance and Analysis Report: {target}

* **Target:** `{target}`
* **Primary IP:** `{primary_ip}`
* **Data Source:** {data_source}
* **Report Generated:** {timestamp}

## 🧠 AI-Generated Security Summary

{ai_summary}

---

{format_diff_markdown(diff) if diff else ""}

---

## 🔎 Technical Findings

### A. Network Footprint (Unified Recon)

{format_nmap_ports(nmap_data, vuln_data)}

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
| IPv4 Addresses | `{', '.join(dns_data.get('ipv4_addresses', ['N/A'])) or 'N/A'}` |
| IPv6 Addresses | `{', '.join(dns_data.get('ipv6_addresses', ['N/A'])) or 'N/A'}` |
| Hostnames (PTR) | `{', '.join(dns_data.get('reverse_hostnames', ['N/A'])) or 'N/A'}` |
| Canonical Name (CNAME) | `{', '.join(dns_data.get('canonical_name', ['N/A'])) or 'N/A'}` |
| Mail Exchange (MX) | `{', '.join(dns_data.get('mx_records', ['N/A'])) or 'N/A'}` |
| TXT Records | `{', '.join(dns_data.get('txt_records', ['N/A'])[:3]) or 'N/A'}{'...' if len(dns_data.get('txt_records', [])) > 3 else ''}` |

---

## 💾 Raw Data Dump (For Auditing)

### Raw Unified Recon Output
```json
{json.dumps(nmap_data, indent=2)}
```

### Raw Vulnerability Data
```json
{json.dumps(vuln_data, indent=2)}
```

### Raw DNS Output
```json
{json.dumps(dns_data, indent=2)}
```
"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, output_filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        log.info(f"✅ Markdown Report saved to: {output_path}")
        return True
    except Exception as e:
        log.error(f"❌ Failed to write Markdown report: {e}")
        return False


def generate_html_report(target: str, nmap_data: dict, shodan_data: dict, dns_data: dict, ai_summary: str, output_filename: str, output_dir: str = "reports", vuln_data: dict = None, diff: dict = None) -> bool:
    """
    Creates the final interactive HTML report using Jinja2 templates.
    """
    try:
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report_template.html')

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        primary_ip = next(iter(nmap_data.get('scan', {}).keys()), "N/A")
        
        ports = []
        host_data = nmap_data.get('scan', {}).get(primary_ip, {})
        if host_data.get('ports'):
            for p in host_data['ports']:
                p_copy = p.copy()
                key = f"{p.get('portid')}/{p.get('service')}"
                p_copy['cves'] = vuln_data.get(key, []) if vuln_data else []
                ports.append(p_copy)
        
        ai_html = ai_summary.replace('\n', '<br>')
        ai_html = re.sub(r'### (.*?)<br>', r'<h3>\1</h3>', ai_html)
        ai_html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', ai_html)

        render_vars = {
            'target': target,
            'primary_ip': primary_ip,
            'data_source': shodan_data.get('source_info', 'Multiple Sources'),
            'timestamp': timestamp,
            'ai_summary_html': ai_html,
            'ports': ports,
            'dns_data': dns_data,
            'shodan_info': shodan_data.get('shodan_data', {}),
            'api_reports_json': json.dumps(shodan_data.get('api_reports', {})),
            'nmap_raw': json.dumps(nmap_data, indent=2),
            'vuln_raw': json.dumps(vuln_data, indent=2),
            'dns_raw': json.dumps(dns_data, indent=2),
            'diff': diff
        }

        html_content = template.render(**render_vars)

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, output_filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log.info(f"✅ HTML Report saved to: {output_path}")
        return True
    except Exception as e:
        log.error(f"❌ Failed to write HTML report: {e}")
        return False


def generate_report(target: str, nmap_data: dict, shodan_data: dict, dns_data: dict, ai_summary: str, output_filename_base: str, output_dir: str = "reports", format: str = "markdown", vuln_data: dict = None, diff: dict = None) -> dict:
    """
    Central function to generate reports in specified formats.
    """
    results = {}
    if format in ("markdown", "both"):
        md_filename = f"{output_filename_base}.md"
        results['markdown'] = generate_markdown_report(target, nmap_data, shodan_data, dns_data, ai_summary, md_filename, output_dir, vuln_data, diff)
    if format in ("html", "both"):
        html_filename = f"{output_filename_base}.html"
        results['html'] = generate_html_report(target, nmap_data, shodan_data, dns_data, ai_summary, html_filename, output_dir, vuln_data, diff)
    return results

def format_shodan_data(shodan_info: dict) -> str:
    """Formats Shodan data into a readable markdown section."""
    if not shodan_info: return "No Shodan data available."
    content = "| Attribute | Value |\n| :--- | :--- |\n"
    if shodan_info.get('org'): content += f"| Organization | {shodan_info['org']} |\n"
    if shodan_info.get('country') or shodan_info.get('city'):
        content += f"| Location | {shodan_info.get('city', 'Unknown')}, {shodan_info.get('country', 'Unknown')} |\n"
    if shodan_info.get('isp'): content += f"| ISP | {shodan_info['isp']} |\n"
    if shodan_info.get('hostnames'): content += f"| Hostnames | {', '.join(shodan_info['hostnames'][:3])}... |\n"
    return content
