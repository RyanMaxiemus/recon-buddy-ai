import ollama
import json
import logging

# Get a module-specific logger instance
log = logging.getLogger("RECON.Scanner")# <-- Use a hierarchical name (e.g., RECON.Scanner)
# This will inherit the setup from the root logger configured in main.py

# IMPORTANT PREREQUISITE:
# You must have Ollama installed and running (ollama serve)
# AND you must have a model pulled, e.g., "ollama pull llama3"
OLLAMA_MODEL = "llama3" # Or 'mistral', 'gemma', etc. Choose one you have pulled.
OLLAMA_HOST = "http://localhost:11434" # Default host for Ollama server

def create_ai_summary(nmap_data: dict, shodan_data: dict, dns_data: dict) -> str:
    """
    Combines all recon data, generates a prompt, and requests a security summary from the Ollama AI model.

    Args:
        nmap_data: A raw dictionary containing Nmap/unified scan results.
        shodan_data: A dictionary containing source information and API reports (can be unified recon data).
        dns_data: A dictionary containing DNS lookup results.

    Returns:
        A concise, actionable security summary as a string.
    """
    # 1. Combine and format the data into a single string for the prompt
    combined_data = {
        "nmap": nmap_data,
        "shodan": shodan_data,
        "dns": dns_data
    }

    # Use JSON.dumps to make sure the data is safely formatted for the LLM.
    data_string = json.dumps(combined_data, indent=2)

    # 2. Craft the System Prompt (This is the most critical part!)
    # This instructs the AI to adopt a persona and output a structured response.
    system_prompt = (
        "You are an expert Cybersecurity Analyst specializing in threat analysis and vulnerability assessment. "
        "Your task is to analyze the following JSON data containing network reconnaissance results from multiple sources "
        "(unified recon may include data from Shodan, Netlas, Criminal IP, Censys, and/or Nmap). "
        "Do not output the raw JSON data. Instead, provide a concise and actionable security summary "
        "in Markdown format. Your report must include the following sections:\n\n"
        "### 1. Host Identity & DNS\n"
        "State the primary IP and discovered hostnames/CNAMES.\n"
        "### 2. High-Priority Findings\n"
        "List all open ports and critical information about the target (focus on HTTP/S, SSH, RDP, and other dangerous services). "
        "If Shodan data is available, highlight organization, location, ISP, and any security tags or vulnerabilities.\n"
        "### 3. Data Sources & Confidence\n"
        "List which data sources were queried and their results (Shodan, Netlas, Criminal IP, Censys, Nmap). "
        "Any data source failures are noted in api_reports.\n"
        "### 4. Attack Surface Summary\n"
        "In one paragraph, summarize the most significant vulnerabilities or misconfigurations. "
        "Which services are most exposed? Include any CVEs or security tags from Shodan if available.\n"
        "### 5. Next Steps (Actionable)\n"
        "Provide 3-5 clear, prioritized steps the user should take next based on the findings.\n\n"
    )

    # 3. Craft the User Prompt
    user_prompt = (
        f"--- RAW RECON DATA ---\n"
        f"{data_string}\n\n"
        f"Please analyze this reconnaissance data and provide a structured security assessment following the format specified in the system prompt."
    )

    try:
        # 4. Call the Ollama API using the modern library interface
        log.info(f"✅ [AI] Sending {len(data_string)} bytes of recon data to '{OLLAMA_MODEL}' for summary...")

        # Use the modern ollama library API (no OllamaClient needed)
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )

        return response['message']['content']

    except Exception as e:
        # Log the full error later, but for now, return a helpful message.
        return f"❌ ERROR: Ollama summary failed. Is the Ollama server running and is the model '{OLLAMA_MODEL}' pulled? Details: {e}"

if __name__ == "__main__":
    # --- Example Usage (Requires Ollama server to be running) ---
    log.info("--- TESTING AI SUMMARIZER (Requires local Ollama server and model) ---")

    # Dummy data simulating outputs from your other modules
    dummy_nmap = {"scan": {"192.168.1.1": {"status": "up", "ports": [{"port": 80, "service": "http", "version": "Apache 2.4.7"}, {"port": 22, "service": "ssh", "version": "OpenSSH 7.2p2"}]}}}
    dummy_shodan = {"org": "Example Corp", "tags": ["insecure", "webcam"], "ports": [80, 22]}
    dummy_dns = {"ipv4_addresses": ["192.168.1.1"], "canonical_name": ["web.example.corp"]}

    summary = create_ai_summary(dummy_nmap, dummy_shodan, dummy_dns)

    log.info("\n--- FINAL AI REPORT ---\n")
    log.info(summary)
    log.info("\n-----------------------\n")
