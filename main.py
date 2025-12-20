import argparse
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# UI & Logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from log_config import setup_logging

# Custom Modules (Ensure these are in your /modules folder)
from modules.scanner import run_basic_scan, UnifiedRecon
from modules.dns_module import run_dns_lookup, is_ip_address
from modules.ai_summarizer import create_ai_summary
from modules.reporter import generate_markdown_report

# --- Initialization ---
load_dotenv()
console = Console()
log = setup_logging()

def orchestrate_recon(target: str):
    """The central nervous system of the recon operation."""
    console.print(Panel.fit("🕵️ [bold cyan]AI RECON ORCHESTRATOR[/bold cyan]", border_style="magenta"))
    log.info(f"Session started for target: {target}")

    # Use 'with Progress' to handle the sleek status bars
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        
        # 1. DNS Phase: Checking the ID at the door
        progress.add_task(description="[yellow]Fetching DNS records...", total=None)
        dns_results = run_dns_lookup(target)
        
        # Resolve target to IP if user provided a domain
        scan_target_ip = target
        if not is_ip_address(target):
            if dns_results.get('ipv4_addresses'):
                scan_target_ip = dns_results['ipv4_addresses'][0]
                log.info(f"Resolved {target} to {scan_target_ip}")
            else:
                log.error(f"DNS failure for {target}")
                console.print(f"[bold red]Error:[/bold red] Could not resolve {target}")
                return

        # 2. Initialize UnifiedRecon with API keys
        progress.add_task(description="[cyan]Initializing multi-source recon...", total=None)
        api_keys = {
            'netlas': os.getenv('NETLAS_API_KEY'),
            'censys_id': os.getenv('CENSYS_API_ID'),
            'censys_secret': os.getenv('CENSYS_API_SECRET'),
            'criminal_ip': os.getenv('CRIMINAL_IP_API_KEY')
        }
        unified_recon = UnifiedRecon(api_keys)
        
        # 3. Unified Recon Phase: Query all sources in priority order
        progress.add_task(description="[green]Querying multiple reconnaissance sources...", total=None)
        unified_results = unified_recon.get_ip_info(scan_target_ip, allow_nmap=True)
        
        # Convert ports to nmap-like format for compatibility
        nmap_results = {
            "scan": {
                scan_target_ip: {
                    "status": "up",
                    "ports": [{"portid": str(p), "protocol": "tcp", "state": "open"} for p in unified_results.get("ports", [])],
                    "source": unified_results.get("source", "Multiple")
                }
            }
        }
        
        # Format api_reports as shodan-like data for compatibility
        shodan_results = {
            "org": "Unknown",
            "api_reports": unified_results.get("api_reports", {}),
            "source_info": unified_results.get("source", "Multiple")
        }
        
        # 4. AI Phase: The 'Brain' work
        progress.add_task(description="[magenta]AI is analyzing data (Ollama)...", total=None)
        ai_summary = create_ai_summary(nmap_results, shodan_results, dns_results)

    # --- CLI RESULTS SUMMARY ---
    # Give the user some instant gratification before they open the report
    table = Table(title=f"Intel Summary: {target}", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Result")
    
    table.add_row("Primary IP", scan_target_ip)
    table.add_row("Data Source", unified_results.get('source', 'Unknown'))
    
    # Extract port list for the table
    ports = unified_results.get("ports", [])
    table.add_row("Open Ports", ", ".join(map(str, ports)) if ports else "[red]None Detected[/red]")
    
    console.print(table)
    console.print(Panel(ai_summary, title="[bold gold1]AI Security Insight[/bold gold1]", border_style="gold1"))

    # 5. Reporting Phase: Writing it down for posterity
    report_name = f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    success = generate_markdown_report(
        target, nmap_results, shodan_results, dns_results, ai_summary, report_name
    )
    
    if success:
        console.print(f"\n[bold green]Success![/bold green] Report saved to: [underline]{report_name}[/underline]")
        log.info(f"Report generated: {report_name}")
    else:
        console.print("\n[bold red]Error:[/bold red] Failed to generate report file.")

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Recon & Scan Tool")
    parser.add_argument('--target', required=True, help='The IP or Domain to investigate')
    args = parser.parse_args()

    # Quick privilege check for Nmap (Linux/macOS)
    if os.name != 'nt' and os.geteuid() != 0:
        console.print("[yellow]Note:[/yellow] Running without sudo. Nmap may use slower TCP connect scans.")

    try:
        orchestrate_recon(args.target)
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted.[/bold red] Getting out of here!")
    except Exception as e:
        log.exception("A fatal error occurred")
        console.print(f"[bold red]Fatal Error:[/bold red] {e}")

if __name__ == "__main__":
    main()