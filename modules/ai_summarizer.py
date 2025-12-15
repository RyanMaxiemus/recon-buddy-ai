import ollama
import json

# IMPORTANT PREREQUISITE:
# You must have Ollama installed and running (ollama serve)
# AND you must have a model pulled, e.g., "ollama pull llama3"
OLLAMA_MODEL = "llama3" # Or 'mistral', 'gemma', etc. Choose one you have pulled.
OLLAMA_HOST = "http://localhost:11434" # Default host for Ollama server

def create_ai_summary(nmap_data: dict, shodan_data: dict, dns_data: dict) -> str:
    """
    Combines all recon data, generates a prompt, and requests a security summary from the Ollama AI model.

    Args:
        nmap_data: A raw dictionary containing Nmap scan results.
        shodan_data: A raw dictionary containing Shodan scan results.
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
        "You are an expert Cybersecurity Analyst specializing in threat analysis and vulnerability assessment."
        "Your task is to analyze the following JSON data containing Nmap, Shodan, and DNS "
        "reconaissance results for a single host. "
        "Do not output the raw JSON data. Instead, provide a concise and actionable security summary "
        "in Markdown format. Your report must include the following sections:\n\n"
    )
    
    # 3. Craft the User Prompt
    user_prompt = (
        f"{system_prompt}\n\n"
        "### 1. Host Identity & DNS\n"
        "State the primary IP and discovered hostnames/CNAMES.\n"
        "### 2. High-Priority Findings\n"
        "List all open ports (especially HTTP/S, SSH, RDP) and any critical information from Shodan "
        "(e.g., outdated software version, reported CVEs, 'vulnerable' tags).\n"
        "### 3. Attack Surface Summary\n"
        "In one paragraph, summarize the most significant vulnerabilities or misconfigurations. "
        "Which services are mostly exposed?\n"
        "### 4. Next Steps (Actionable)\n"
        "Provide 3-5 clear, prioritized steps the user should take next (e.g., 'Run an in-depth Nikto scan "
        "on port 80', 'Check the SSH banner version against Mitre CVEs').\n\n"
        "--- RAW RECON DATA ---\n"
        f"{data_string}"
    )

    try:
        # 4. Initialize Client and Call the API
        client = ollama.OllamaClient(host=OLLAMA_HOST)
        
        print(f"    [AI] Sending {len(data_string)} bytes of recon data to '{OLLAMA_MODEL}' for summary...")
        
        # We use the 'chat' endpoint which is generally more flexible than 'generate' 
        # for structured prompts using system messages.
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "user", "content": user_prompt}
            ],
            # Options can be added here, e.g., 'temperature': 0.1 for less creativity
            options={'temperature': 0.1}
        )

        return response['message']['content']
    
    except Exception as e:
        # Log the full error later, but for now, return a helpful message.
        return f"❌ ERROR: Ollama summary failed. Is the Ollama server running and is the model '{OLLAMA_MODEL}' pulled? Details: {e}"
    
if __name__ == "__main__":
    # --- Example Usage (Requires Ollama server to be running) ---
    print("--- TESTING AI SUMMARIZER (Requires local Ollama server and model) ---")

    # Dummy data simulating outputs from your other modules
    dummy_nmap = {"scan": {"192.168.1.1": {"status": "up", "ports": [{"port": 80, "service": "http", "version": "Apache 2.4.7"}, {"port": 22, "service": "ssh", "version": "OpenSSH 7.2p2"}]}}}
    dummy_shodan = {"org": "Example Corp", "tags": ["insecure", "webcam"], "ports": [80, 22]}
    dummy_dns = {"ipv4_addresses": ["192.168.1.1"], "canonical_name": ["web.example.corp"]}

    summary = create_ai_summary(dummy_nmap, dummy_shodan, dummy_dns)

    print("\n--- FINAL AI REPORT ---\n")
    print(summary)
    print("\n-----------------------\n")