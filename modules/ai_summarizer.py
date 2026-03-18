import os
import logging
import json
import ollama
from rich.console import Console

# Get the logger instance from the root logging setup
log = logging.getLogger("RECON.AI")

# Default Ollama configuration
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# Payload truncation safety
MAX_LLM_PAYLOAD_CHARS = 12000 # Safety limit for context window

def _prepare_data_for_llm(nmap_data: dict, shodan_data: dict, dns_data: dict, vuln_data: dict = None) -> str:
    """
    Cleans and truncates the data before sending to the LLM.
    Strips bulky 'raw_data' from Shodan results and truncates if necessary.
    Includes CVE data if provided.
    """
    
    # 1. Strip raw_data from Shodan to save context space
    shodan_clean = shodan_data.copy()
    if 'shodan_data' in shodan_clean:
        # Keep basic org/location but strip the massive 'data' list
        sd = shodan_clean['shodan_data']
        shodan_clean['shodan_data'] = {
            'org': sd.get('org'),
            'isp': sd.get('isp'),
            'city': sd.get('city'),
            'country': sd.get('country'),
            'tags': sd.get('tags', []),
            'vulns': sd.get('vulns', []),
            'hostnames': sd.get('hostnames', [])
        }

    # 2. Extract ports summary from nmap
    ports_summary = []
    for host, data in nmap_data.get('scan', {}).items():
        if data.get('ports'):
            for p in data['ports']:
                ports_summary.append(f"{p.get('portid')}/{p.get('protocol')} ({p.get('service')} {p.get('version')})")

    # 3. Assemble the prompt context
    payload = {
        "targets": list(nmap_data.get('scan', {}).keys()),
        "open_ports": ports_summary,
        "dns_records": dns_data,
        "host_intelligence": shodan_clean,
        "known_vulnerabilities": vuln_data or {}
    }
    
    json_payload = json.dumps(payload, indent=2)
    
    # Final safeguard truncation
    if len(json_payload) > MAX_LLM_PAYLOAD_CHARS:
        log.warning(f"Payload too large ({len(json_payload)} chars). Truncating for LLM context safety.")
        return json_payload[:MAX_LLM_PAYLOAD_CHARS] + "\n[... PAYLOAD TRUNCATED]"
    
    return json_payload

def create_ai_summary(nmap_data: dict, shodan_data: dict, dns_data: dict, vuln_data: dict = None) -> str:
    """
    Sends the gathered recon data to the Ollama LLM for a structured security summary.
    Includes CVE information from NVD if available.
    """
    
    prepared_data = _prepare_data_for_llm(nmap_data, shodan_data, dns_data, vuln_data)
    
    prompt = f"""
    You are a professional security consultant at Recon Buddy AI. 
    Analyze the following technical reconnaissance data for a target and provide a concise, high-level security summary.
    
    RECON DATA:
    {prepared_data}
    
    YOUR TASK:
    1. Identify the most critical risks (e.g., exposed databases, known vulnerabilities with high CVSS scores).
    2. Summarize the exposed network surface.
    3. Provide 3-5 concrete remediation steps.
    4. Comment on any interesting DNS or host intelligence (Shodan) findings.
    
    Format your response using Markdown (use bold and tables where appropriate).
    Keep it professional, direct, and actionable.
    """

    try:
        log.info(f"Sending request to Ollama ({OLLAMA_MODEL}) at {OLLAMA_HOST}...")
        client = ollama.Client(host=OLLAMA_HOST)
        response = client.generate(model=OLLAMA_MODEL, prompt=prompt)
        
        summary = response.get('response', "AI failed to generate a summary.")
        return summary
        
    except (ollama.ResponseError, ConnectionError, Exception) as e:
        log.error(f"Ollama Interaction Failed: {e}")
        return f"⚠️ [bold red]AI Analysis Error:[/bold red] Could not connect to Ollama ({OLLAMA_MODEL}). Ensure Ollama is running.\n\nRaw Error: {e}"
