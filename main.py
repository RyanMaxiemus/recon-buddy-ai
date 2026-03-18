import argparse
import json
import os
import re
import sys
from datetime import datetime
from ipaddress import ip_address, ip_network, AddressValueError
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# UI & Logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from log_config import setup_logging

# Custom Modules
from modules.scanner import UnifiedRecon
from modules.dns_module import run_dns_lookup, is_ip_address
from modules.ai_summarizer import create_ai_summary
from modules.reporter import generate_report
from modules.vuln_lookup import VulnLookup
from modules.history import ScanHistory
from modules.notifiers import NotificationManager

# --- Initialization ---
load_dotenv()
console = Console()
log = setup_logging()

# Valid domain regex
_DOMAIN_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
)


def validate_target(target: str) -> bool:
    """Validates that the target is a legitimate IPv4/IPv6 address, CIDR, or domain name."""
    target = target.strip()
    if not target: return False
    if '/' in target:
        try:
            ip_network(target, strict=False)
            return True
        except (ValueError, AddressValueError): pass
    try:
        ip_address(target)
        return True
    except (AddressValueError, ValueError): pass
    if _DOMAIN_RE.match(target): return True
    return False


def get_all_targets(target_arg=None, targets_file=None):
    """Parses CLI arguments and files to returns a flat list of unique targets."""
    targets = []
    if target_arg:
        if '/' in target_arg:
            try:
                network = ip_network(target_arg.strip(), strict=False)
                targets.extend([str(ip) for ip in list(network)[:256]])
            except ValueError: targets.append(target_arg.strip())
        else: targets.append(target_arg.strip())

    if targets_file and os.path.exists(targets_file):
        try:
            with open(targets_file, 'r') as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith('#'):
                        if validate_target(t):
                            if '/' in t:
                                network = ip_network(t, strict=False)
                                targets.extend([str(ip) for ip in list(network)[:256]])
                            else: targets.append(t)
        except Exception as e: log.error(f"Error reading targets file: {e}")

    return list(dict.fromkeys(targets))


def scan_single_target(target, output_dir, report_format, history_manager, notifier_manager, json_mode=False):
    """Performs the full recon flow for a single target string."""
    if not json_mode: log.info(f"Scanning target: {target}")
    
    try:
        # 1. DNS Phase
        dns_results = run_dns_lookup(target)
        scan_target_ip = target
        if not is_ip_address(target):
            if dns_results.get('ipv4_addresses'):
                scan_target_ip = dns_results['ipv4_addresses'][0]
            else: return f"❌ {target}: DNS Failure"

        # 2. Unified Recon
        api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY'),
            'netlas': os.getenv('NETLAS_API_KEY'),
            'censys_id': os.getenv('CENSYS_API_ID'),
            'censys_secret': os.getenv('CENSYS_API_SECRET'),
            'criminal_ip': os.getenv('CRIMINAL_IP_API_KEY')
        }
        unified_recon = UnifiedRecon(api_keys)
        unified_results = unified_recon.get_ip_info(scan_target_ip, allow_nmap=True)

        nmap_results = {
            "scan": {
                scan_target_ip: {
                    "status": "up",
                    "ports": [{"portid": str(p), "protocol": "tcp", "state": "open", "service": "unknown", "version": "N/A"} for p in unified_results.get("ports", [])],
                    "source": unified_results.get("source", "Multiple")
                }
            }
        }

        shodan_results = {
            "org": unified_results.get("shodan_data", {}).get("org", "Unknown") if unified_results.get("shodan_data") else "Unknown",
            "api_reports": unified_results.get("api_reports", {}),
            "source_info": unified_results.get("source", "Multiple"),
            "shodan_data": unified_results.get("shodan_data", {})
        }

        # 3. Vulnerability Lookup Phase (NVD)
        vuln_lookup = VulnLookup(api_key=os.getenv('NVD_API_KEY'))
        port_list = nmap_results["scan"][scan_target_ip]["ports"]
        vuln_data = vuln_lookup.lookup_ports(port_list)
        
        # 4. History & Diff Phase
        last_scan = history_manager.get_last_scan(target)
        diff = None
        if last_scan:
            current_scan = {'recon_data': nmap_results, 'vuln_data': vuln_data}
            diff = history_manager.diff_scans(last_scan, current_scan)
        
        # 5. AI Phase
        ai_summary = create_ai_summary(nmap_results, shodan_results, dns_results, vuln_data)

        # 6. Reporting Phase
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_base = f"report_{target.replace('.', '_').replace('/', '_')}_{timestamp_str}"
        generate_report(target, nmap_results, shodan_results, dns_results, ai_summary, report_base, output_dir, report_format, vuln_data, diff)
        
        # 7. Save to History
        history_manager.save_scan(target, dns_results, nmap_results, vuln_data, ai_summary)
        
        # 8. Notifications
        ports_count = len(unified_results.get("ports", []))
        vuln_count = sum(len(v) for v in vuln_data.values())
        has_changes = diff['has_changes'] if diff else False
        notifier_manager.notify_scan_complete(target, ports_count, vuln_count, has_changes)
        
        # 9. Terminal Output (AI Insight)
        if not json_mode:
            console.print("") # Separation from progress bar
            console.print(Panel.fit(ai_summary, title="[bold yellow]AI Security Insight[/bold yellow]", subtitle=f"[dim]{target}[/dim]", border_style="yellow", padding=(1, 2)))
        
        if json_mode:
            return {
                "target": target,
                "status": "success",
                "ports_count": ports_count,
                "vuln_count": vuln_count,
                "has_changes": has_changes,
                "report_base": report_base
            }
        
        diff_status = " (Changes detected!)" if has_changes else ""
        return f"✅ {target}: Success ({ports_count} ports, {vuln_count} CVEs){diff_status}"

    except Exception as e:
        log.error(f"Error scanning {target}: {e}")
        error_msg = f"❌ {target}: Error: {str(e)}"
        return {"target": target, "status": "error", "error": str(e)} if json_mode else error_msg


def orchestrate_recon(target_arg, targets_file, output_dir, report_format, concurrency, notify_list, json_mode=False):
    """Orchestrates scans across multiple targets in parallel."""
    history_manager = ScanHistory()
    notifier_manager = NotificationManager(notify_list)
    targets = get_all_targets(target_arg, targets_file)
    if not targets:
        if json_mode:
            print(json.dumps({"status": "error", "message": "No valid targets found."}))
        else:
            console.print("[bold red]Error:[/bold red] No valid targets found.")
        return

    if not json_mode:
        console.print(Panel.fit(
            f"🕵️ [bold cyan]AI RECON CAMPAIGN[/bold cyan]\n[dim]Targets: {len(targets)} | Concurrency: {concurrency} | Notify: {','.join(notify_list) or 'None'}[/dim]", 
            border_style="magenta"
        ))

    results = []
    
    if json_mode:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_target = {executor.submit(scan_single_target, t, output_dir, report_format, history_manager, notifier_manager, True): t for t in targets}
            for future in as_completed(future_to_target):
                results.append(future.result())
        print(json.dumps(results, indent=2))
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        transient=False,
    ) as progress:
        main_task = progress.add_task("[bold white]Recon Progress", total=len(targets))
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_target = {executor.submit(scan_single_target, t, output_dir, report_format, history_manager, notifier_manager, False): t for t in targets}
            for future in as_completed(future_to_target):
                result = future.result()
                results.append(result)
                progress.update(main_task, advance=1, description=f"[cyan]Last: {str(result).split(':')[0]}")

    console.print("\n[bold]Campaign Results Summary:[/bold]")
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Status", width=4)
    table.add_column("Target")
    table.add_column("Outcome")
    for res in results:
        status = "[green]OK[/green]" if "✅" in str(res) else "[red]ERR[/red]"
        parts = str(res).split(': ', 1)
        table.add_row(status, parts[0].replace('✅ ', '').replace('❌ ', ''), parts[1] if len(parts) > 1 else "Unknown")
    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="AI-Powered Recon & Scan Tool")
    parser.add_argument('--target', help='The IP, CIDR, or Domain to investigate')
    parser.add_argument('--targets-file', help='File containing target IPs or Domains')
    parser.add_argument('--output-dir', default='reports', help='Directory to save reports')
    parser.add_argument('--format', choices=['markdown', 'html', 'both'], default='markdown', help='Output format')
    parser.add_argument('--concurrency', type=int, default=5, help='Number of parallel scans')
    parser.add_argument('--model', help='Ollama model to use')
    parser.add_argument('--history', nargs='?', const=True, help='Display scan history')
    parser.add_argument('--notify', help='Comma-separated notifiers (slack,discord,email)')
    parser.add_argument('--json', action='store_true', help='Output results as structured JSON to stdout')
    args = parser.parse_args()

    if args.history:
        display_history(args.history if isinstance(args.history, str) else None)
        return

    if not args.target and not args.targets_file:
        parser.error("At least one of --target or --targets-file is required.")

    if args.json:
        # Re-initialize logging to stay quiet
        global log
        from log_config import setup_logging
        os.environ['RECON_LOG_QUIET'] = '1'
        log = setup_logging()

    notify_list = args.notify.split(',') if args.notify else []
    if args.model:
        os.environ['OLLAMA_MODEL'] = args.model

    try:
        orchestrate_recon(args.target, args.targets_file, args.output_dir, args.format, args.concurrency, notify_list, args.json)
    except KeyboardInterrupt:
        if not args.json: console.print("\n[bold red]Aborted.[/bold red]")
    except Exception as e:
        log.exception("A fatal error occurred")
        if not args.json: console.print(f"[bold red]Fatal Error:[/bold red] {e}")

def display_history(target_filter=None):
    history_manager = ScanHistory()
    rows = history_manager.list_history(target_filter)
    if not rows: console.print("[yellow]No history found.[/yellow]"); return
    table = Table(title="📜 Scan History", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Date", style="green")
    for row in rows:
        table.add_row(str(row[0]), row[1], row[2])
    console.print(table)


if __name__ == "__main__":
    main()
