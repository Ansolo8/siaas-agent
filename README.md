# siaas-agent

_Intelligent System for Automation of Security Audits (SIAAS) - Agent_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD), 2022-2024

__

**Instructions (tested on Ubuntu 20.04 "Focal", Ubuntu 22.04 "Jammy", Debian 11 "Bullseye", and Raspberry Pi OS 11 "Bullseye")**

 - Install and configure: `sudo ./siaas_agent_install_and_configure.sh`

 - Start: `sudo systemctl start siaas-agent` or `sudo ./siaas_agent_run.sh`

 - Stop: `sudo systemctl stop siaas-agent` or `sudo ./siaas_agent_kill.sh`

 - Logs: `tail -100f /var/log/siaas-agent/siaas-agent.log` or `tail -100f ./log/siaas-agent.log`

 - Generate a project archive (it is recommended to stop all processes before): `sudo ./siaas_agent_archive.sh`

 - Remove: `sudo ./siaas_agent_remove.sh`

## Added modules

This agent can now run three optional extension modules that keep the same local JSON database and data-transfer architecture as the original SIAAS modules:

- `aiaavsraw_webscanner.py` writes OWASP ZAP web scan output to `var/webscanner.db`.
- `siaas_metasploit.py` writes defensive Metasploit correlation output to `var/metasploit.db`. It correlates CVEs, services, and products from scanner evidence with local Metasploit module candidates when `metasploit_enable_msfconsole_search=true`; it does **not** execute exploits or payloads. If it runs before scanner DBs exist, it retries with `metasploit_no_data_retry_interval_sec` instead of waiting a full long scan interval.
- `siaas_remediation.py` writes a remediation report to `var/remediation.db` by consuming the port scanner, web scanner, and Metasploit assistant outputs. By default it uses deterministic local rules; set `remediation_ai_provider=ollama` with a local free Ollama model (for example `llama3.1:8b`) to generate vulnerability-specific AI remediation text from the scanner evidence.

The data-transfer and internal API module list includes `platform`, `neighborhood`, `portscanner`, `webscanner`, `metasploit`, `remediation`, and `config`, so server-side consumers can ingest the new module outputs without changing the agent upload endpoint.

### Metasploit and AI remediation notes

`metasploit_enable_msfconsole_search` is disabled by default for safety and performance. With the default setting, `var/metasploit.db` can show scanner targets, CVEs, and generated search terms, but `metasploit_modules` will stay empty. To search local Metasploit modules, install Metasploit, ensure `msfconsole` is in `PATH` or set `metasploit_msfconsole_path`, then set `metasploit_enable_msfconsole_search=true`.

For free/local AI remediation, install Ollama on the agent host, pull a model such as `ollama pull llama3.1:8b`, and configure:

```ini
remediation_ai_provider = ollama
remediation_ai_model = llama3.1:8b
remediation_ollama_api_url = http://127.0.0.1:11434
```

The remediation module keeps a local-rule fallback. If Ollama is unavailable or a model response cannot be parsed, the finding is still saved with the rule-based recommendation and an `ai_error` field for troubleshooting.
