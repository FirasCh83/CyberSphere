# 🛡️ CyberSphere

**A multi-agent AI penetration-testing platform.** Point it at a target and two
LLM-driven agents run a full **recon → vulnerability analysis → report** pipeline
on their own — reasoning about what they see, driving real security tooling, and
*actively validating* every finding before it's called confirmed.

Built on one principle: **never trust, always verify.** An LLM will happily
invent a critical CVE that doesn't exist; CyberSphere only reports what a real
tool observed and what it can prove.

> ⚖️ **For authorized testing only.** Use CyberSphere exclusively against systems
> you own or have explicit written permission to test (e.g. a local
> [Metasploitable](https://docs.rapid7.com/metasploit/metasploitable-2/) lab VM).

---

## How it works

```
target ──▶ Recon Agent ──handoff──▶ Vuln Agent ──▶ live report
           (ReAct loop)              (RAG + active validation)
```

- **🔍 Recon Agent** — a ReAct reasoning loop that drives `nmap`, `nuclei`,
  `httpx`, `katana`, `whatweb`, and `whois`, deciding its own next move. A
  **completion gate** stops it from handing off until it has actually covered the
  attack surface (e.g. it won't skip un-fingerprinted / un-crawled web ports).
- **🎯 Vuln Agent** — two layers:
  1. **RAG** over a CVE knowledge base (ChromaDB + `all-MiniLM-L6-v2` embeddings)
     shortlists real candidates from the recon evidence.
  2. **Active validation** — connects, grabs the service banner, and checks for a
     working Metasploit path before labelling anything `confirmed`.
- **Two-lane routing** — candidates with an exploit module are actively validated;
  those without are logged as **advisory / potential exposure** (manual review),
  cleanly separated from confirmed findings. A guard strips any CVE the model
  cites that no tool actually reported — **no hallucinated findings**.
- **🐳 Docker isolation** — every tool runs in its own disposable container, so
  the toolchain is sandboxed, reproducible, and never installed on the host.

## Architecture

| Layer | Tech |
|-------|------|
| Desktop app | Electron + React 19 + Vite + Tailwind |
| Backend | Python + FastAPI, live Server-Sent Events (SSE) streaming |
| Orchestration | `orchestrator.py` — recon → vuln → report pipeline |
| Agents | `agents/recon.py`, `agents/vuln.py` (LLM reasoning via OpenRouter) |
| Knowledge base | ChromaDB (`knowledge/`), populated from curated + NVD CVE data |
| Tooling | Dockerized `nmap`, `nuclei`, `httpx`, `katana`, `whatweb`, `whois`, Metasploit |

The Electron main process spawns the FastAPI backend automatically; the React UI
streams each agent's reasoning, tool runs, and the final report in real time.

## Prerequisites

- **Python 3.11**
- **Node.js** (18+)
- **Docker** — must be running; the agents execute all tools in containers
- An **OpenRouter API key**

## Setup

```bash
# 1. Clone
git clone https://github.com/FirasCh83/CyberSphere.git
cd CyberSphere

# 2. Python backend
python -m venv venv
venv\Scripts\activate        # Windows  (source venv/bin/activate on macOS/Linux)
pip install -r requirements.txt

# 3. Frontend
npm install

# 4. Secrets
copy .env.example .env       # then edit .env and add your OPENROUTER_API_KEY

# 5. Build / pull the tool images
docker build -t cybersphere-httpx:latest   tools/httpx
docker build -t cybersphere-whatweb:latest tools/whatweb
docker build -t cybersphere-whois:latest   tools/whois
docker build -t cybersphere/nuclei:latest  tools/nuclei
docker pull instrumentisto/nmap:latest
docker pull projectdiscovery/katana:v1.6.1
# Metasploit image: see the image name defined in tools/validation/msf_check.py

# 6. Build the CVE knowledge base
python -m knowledge.populate.seed        # curated, module-backed CVEs
# (optional) enrich with NVD advisory data via knowledge/populate/nvd_loader.py
```

## Run

```bash
npm run dev
```

This starts Vite + Electron; Electron launches the Python backend (`server.py`)
on `127.0.0.1:8000`. Enter a target (IP / domain / host) in the app and launch a
scan. To run the pipeline headless instead:

```bash
python orchestrator.py <target>
```

## Project layout

```
agents/       recon & vuln agents (ReAct loops)
tools/        Dockerized scanner wrappers + Metasploit validation
knowledge/    ChromaDB CVE knowledge base + populate scripts
utilities/    shared state, models, SSE event emitters, parsers
electron/     Electron main process
src/          React UI
server.py     FastAPI backend (SSE stream + findings/report API)
orchestrator.py  recon → vuln → report pipeline
```

## Roadmap

- End-to-end test suite
- Broader target coverage beyond lab VMs
- Hosted / paid edition

---

*Portfolio project by [Firas](https://github.com/FirasCh83). Built to explore
agent orchestration, RAG, container isolation, and keeping LLMs honest.*

