# 🕵️ Recon Buddy AI

> Automated recon for the modern (lazy) security pro. Wraps Nmap, Shodan, and DNS utils into one Python tool, then uses AI to summarize the attack surface so you don't have to parse XML manually.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

## 🤔 Why?

Because staring at raw Nmap XML output is a violation of the Geneva Convention. I wanted a tool that scans the target, grabs the low-hanging fruit (Shodan/DNS), and then uses an LLM to tell me, *"Hey, look at port 8080, it looks vulnerable,"* instead of me `grep`-ing through 5,000 lines of logs.

## ✨ Features

-   **Nmap Integration:** Automated port scanning without the headache.
-   **DNS & Shodan:** Enriches IP data with hostnames and public vulnerability data.
-   **AI Analysis:** Uses Local LLMs (Ollama) or OpenAI to summarize findings.
-   **Reporting:** Generates clean Markdown/PDF reports. Manager-friendly.

## 🛠️ Installation

1.  **Clone the repo:**
    ```bash
    git clone [https://github.com/ryanmaxiemus/recon-buddy-ai.git](https://github.com/ryanmaxiemus/recon-buddy-ai.git)
    cd project-name
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Setup Keys (Optional but recommended):**
    Create a `.env` file and add your keys:
    ```env
    SHODAN_API_KEY=your_key_here
    OPENAI_API_KEY=your_key_here  # Only if not using Local LLM
    ```

## 🚀 Usage

Basic scan:
```bash
python main.py --target 192.168.1.1 --scan-type quick
````

Generate a full report with AI summary:

```bash
python main.py --target example.com --ai-summary --output report.md
```

## 🗺️ Roadmap

  - [ ] **Core:** Nmap & DNS Module
  - [ ] **Intel:** Shodan API Integration
  - [ ] **Brain:** AI Summarizer (Local + Cloud support)
  - [ ] **Paperwork:** PDF/MD Report Generator
  - [ ] **Polish:** Logging & Error Handling
  - [ ] **UI:** CLI Beautification (Rich/Typer)

## ⚠️ Disclaimer

**Do not scan targets you do not have permission to test.** The developer is not responsible if you use this tool to do something illegal and end up in a cell without Wi-Fi. Use responsibly.

## 🤝 Contributing

PRs are welcome. If you fix a bug, you're a legend. If you add a feature, please update the tests.
