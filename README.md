# 🚀 Recon Buddy AI

> Automated reconnaissance and port scanning, summarized by a local AI model, so you can stop parsing raw terminal output.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Tech: Python](https://img.shields.io/badge/Tech-Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AI: Ollama](https://img.shields.io/badge/AI-Ollama-000000?logo=ollama&logoColor=white)](https://ollama.com/)

---

## 🧐 What is this?

**Recon Buddy AI** is a command-line utility designed for modern security professionals and bug bounty hunters. It solves the problem of "recon fatigue" by consolidating data from multiple sources—including local Nmap scans and external APIs like Shodan, Netlas, Censys, and Criminal IP—into a single, unified report. The key differentiator is the integration of a local Large Language Model (LLM) via **Ollama** to analyze the raw findings and generate a concise, actionable security summary. Instead of sifting through pages of terminal output, you get a clear, prioritized attack surface analysis instantly.

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **Recon:** `python-nmap`, `dnspython`, Shodan API, Netlas API, Censys API, Criminal IP API
- **AI/LLM:** Ollama (default model: `llama3`)
- **UI/Reporting:** `rich` (for beautiful terminal output), `markdown` (for report generation)
- **Dependency Management:** Poetry

## 🚀 Quick Start (Optimized for Ubuntu)

This project requires **Nmap** and **Ollama** to be installed on your system.

### Prerequisites

1.  **Install Nmap:**

    ```bash
    sudo apt update
    sudo apt install nmap -y
    ```

2.  **Install Ollama and Pull Model:**
    Follow the official instructions to install Ollama. Once installed, pull the default model (`llama3`):
    ```bash
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull llama3
    ```
    > **Note:** Ollama must be running in the background (`ollama serve`) for the AI summary feature to work.

### Installation

The project uses **Poetry** for dependency management.

```bash
# Clone it
git clone https://github.com/RyanMaxiemus/recon-buddy-ai.git
cd recon-buddy-ai

# Install Poetry (if you don't have it)
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install
```

### Configuration

Create a `.env` file in the project root to store your API keys. The tool will function without them, but the multi-source recon will be limited. Copy the example file and add your keys:

```bash
cp .env.example .env
# Edit .env with your actual API keys
```

Example `.env` file:

```ini
# Primary source (most comprehensive)
SHODAN_API_KEY="your_shodan_key"

# Alternative sources (optional)
NETLAS_API_KEY="your_netlas_key"
CENSYS_API_ID="your_censys_id"
CENSYS_API_SECRET="your_censys_secret"
CRIMINAL_IP_API_KEY="your_criminal_ip_key"
```

**Note:** You don't need all API keys. The tool prioritizes sources in this order: Shodan → Netlas → Criminal IP → Censys → Nmap (fallback).

### Run it

Execute the main script, providing a target domain or IP address:

```bash
# Run it
poetry run python main.py --target scanme.nmap.org
```

## 📸 Preview

_(Placeholder for a screenshot or GIF of the terminal output)_

## 🤝 Contributing

Found a bug? Open an issue. Want to fix it? Send a PR. Let's make this better together.

We welcome contributions of all kinds! Whether it's a new feature, a bug fix, or just improving the documentation, your help is appreciated.

1.  **Fork** the repository.
2.  **Clone** your fork: `git clone https://github.com/your-username/recon-buddy-ai.git`
3.  **Create** a new branch: `git checkout -b feature/your-feature-name`
4.  **Commit** your changes: `git commit -m 'feat: Add amazing new feature'`
5.  **Push** to the branch: `git push origin feature/your-feature-name`
6.  **Open a Pull Request** and describe your changes.

We use **Poetry** for dependency management, so please ensure your environment is set up with `poetry install` before making changes. Thank you for making Recon Buddy AI better!
