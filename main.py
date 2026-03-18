import argparse
import json
import os
import re
from datetime import datetime
from ipaddress import ip_address, AddressValueError
from dotenv import load_dotenv

# UI & Logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from log_config import setup_logging

# Custom Modules
from modules.scanner import UnifiedRecon
from modules.dns_module import run_dns_lookup, is_ip_address
from modules.ai_summarizer import create_ai_summary
from modules.reporter import generate_markdown_report

# --- Initialization ---
load_dotenv()
console = Console()
log = setup_logging()

# Valid domain regex (RFC 1035 compliant, reasonably strict)
_DOMAIN_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
)


def validate_target(target: str) -> bool:
    """
    Validates that the target is a legitimate IPv4/IPv6 address or domain name.
    Rejects anything that could be used for injection or is nonsensical.

    Args:
        target: The user-provided target string.

    Returns:
        True if valid, False otherwise.
    """
    # Strip whitespace
    target = target.strip()

    if not target:
        return False

    # Check if it's a valid IP address
    try:
        ip_address(target)
        return True
    except (AddressValueError, ValueError):
        pass

    # Check if it's a valid domain name
    if _DOMAIN_RE.match(target):
        return True

    return False


def orchestrate_recon(target: str, output_dir: str = "reports"):
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
                dns_errors = dns_results.get('errors', [])
                error_detail = f" ({'; '.join(dns_errors)})" if dns_errors else ""
                console.print(f"[bold red]Error:[/bold red] Could not resolve {target}{error_detail}")
                return

        # 2. Initialize UnifiedRecon with API keys
        progress.add_task(description="[cyan]Initializing multi-source recon...", total=None)
        api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY'),
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
            "org": unified_results.get("shodan_data", {}).get("org", "Unknown") if unified_results.get("shodan_data") else "Unknown",
            "api_reports": unified_results.get("api_reports", {}),
            "source_info": unified_results.get("source", "Multiple"),
            "shodan_data": unified_results.get("shodan_data", {})
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
        target, nmap_results, shodan_results, dns_results, ai_summary, report_name, output_dir
    )

    if success:
        report_path = os.path.join(output_dir, report_name)
        console.print(f"\n[bold green]Success![/bold green] Report saved to: [underline]{report_path}[/underline]")
        log.info(f"Report generated: {report_path}")
    else:
        console.print("\n[bold red]Error:[/bold red] Failed to generate report file.")

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Recon & Scan Tool")
    parser.add_argument('--target', required=True, help='The IP or Domain to investigate')
    parser.add_argument('--output-dir', default='reports', help='Directory to save reports (default: reports/)')
    parser.add_argument('--model', default=None, help='Ollama model to use (overrides OLLAMA_MODEL env var)')
    args = parser.parse_args()

    # Validate target before doing anything else
    if not validate_target(args.target):
        console.print(f"[bold red]Error:[/bold red] Invalid target: '{args.target}'. Must be a valid IP address or domain name.")
        return

    # Override OLLAMA_MODEL if --model flag is provided
    if args.model:
        os.environ['OLLAMA_MODEL'] = args.model

    # Quick privilege check for Nmap (Linux/macOS)
    if os.name != 'nt' and os.geteuid() != 0:
        console.print("[yellow]Note:[/yellow] Running without sudo. Nmap may use slower TCP connect scans.")

    try:
        orchestrate_recon(args.target, args.output_dir)
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted.[/bold red] Getting out of here!")
    except Exception as e:
        log.exception("A fatal error occurred")
        console.print(f"[bold red]Fatal Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
