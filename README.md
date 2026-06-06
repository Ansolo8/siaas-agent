# siaas-agent

_Intelligent System for Automation of Security Audits (SIAAS) - Agent_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD), 2022-2024

__

## System requirements

The table below shows which extra components are needed beyond the base Python environment. The install script (`siaas_agent_install_and_configure.sh`) handles everything marked **auto** automatically. Items marked **manual** require a one-time step after installation.

| Component | Required by | How to install | Notes |
|---|---|---|---|
| **Python 3.8+** | All modules | auto (apt) | |
| **Nmap 7.80+** | PortScanner | auto (apt) | |
| **Docker** | WebScanner | auto (Docker CE via apt) | The ZAP image (`ghcr.io/zaproxy/zaproxy:stable`) is pulled automatically on the first web scan |
| **Metasploit Framework** | Metasploit module | auto (snap) | After install, run `msfconsole` once as the agent user to generate the module metadata cache (`~/.msf4/store/modules_metadata_base.json`). If installed via snap, the metadata file is already present at `/snap/metasploit-framework/current/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json` and no extra step is needed |
| **Groq API key** *(optional)* | Remediation / Audit (AI) | [console.groq.com](https://console.groq.com) — free tier | Set `export SIAAS_AI_API_KEY="your-key"` in the agent's environment (e.g. the systemd unit drop-in). Configure `remediation_ai_provider = groq` and `audit_ai_provider = groq` in `conf/siaas_agent.cnf` |
| **Ollama** *(optional)* | Remediation / Audit (AI, local/offline) | [ollama.com](https://ollama.com) — `curl -fsSL https://ollama.com/install.sh \| sh` | After install: `ollama pull llama3.1:8b`. Configure `remediation_ai_provider = ollama` in `conf/siaas_agent.cnf`. No API key needed, fully offline |
| **OpenAI / Gemini key** *(optional)* | Remediation / Audit (AI) | platform.openai.com / aistudio.google.com | Same env-var as Groq (`SIAAS_AI_API_KEY`). Set `remediation_ai_provider = openai` or `gemini` |

> **Minimum setup (no AI, no web scanning):** only Nmap and Python are required. Docker and Metasploit can be disabled individually in `conf/siaas_agent.cnf` (`disable_webscanner = true`, `disable_metasploit = true`).

---

**Instructions (tested on Ubuntu 20.04 "Focal", Ubuntu 22.04 "Jammy", Debian 11 "Bullseye", and Raspberry Pi OS 11 "Bullseye")**

 - Install and configure: `sudo ./siaas_agent_install_and_configure.sh`

 - Start: `sudo systemctl start siaas-agent` or `sudo ./siaas_agent_run.sh`

 - Stop: `sudo systemctl stop siaas-agent` or `sudo ./siaas_agent_kill.sh`

 - Logs: `tail -100f /var/log/siaas-agent/siaas-agent.log` or `tail -100f ./log/siaas-agent.log`

 - Generate a project archive (it is recommended to stop all processes before): `sudo ./siaas_agent_archive.sh`

 - Remove: `sudo ./siaas_agent_remove.sh`

## Added modules

This agent can now run four optional extension modules that keep the same local JSON database and data-transfer architecture as the original SIAAS modules:

- `siaas_webscanner.py` writes OWASP ZAP web scan output to `var/webscanner.db`.
- `siaas_metasploit.py` writes defensive Metasploit correlation output to `var/metasploit.db`. It correlates the CVEs found in scanner evidence with Metasploit exploit modules; it does **not** execute exploits or payloads. By default it uses precise CVE→module correlation read directly from Metasploit's local module metadata cache (`metasploit_use_metadata_cache=true`), filtered by the target's detected OS/platform (`metasploit_filter_by_platform=true`), and ranks candidates by module rank. A live `msfconsole search` fallback is available via `metasploit_enable_msfconsole_search=true`. If it runs before scanner DBs exist, it retries with `metasploit_no_data_retry_interval_sec` instead of waiting a full long scan interval.
- `siaas_remediation.py` writes a remediation report to `var/remediation.db` by consuming the port scanner, web scanner, and Metasploit assistant outputs. By default it uses deterministic local rules; set `remediation_ai_provider` to a free AI backend to generate vulnerability-specific remediation text grounded in the scanner evidence. Supported providers: `ollama` (local/offline), `groq` (free hosted), `openai`/any OpenAI-compatible endpoint, and `gemini`. AI answers are cached per finding (`remediation_ai_cache=true`) so unchanged findings are not re-queried every loop.
- `siaas_audit.py` writes an organization-level security posture report to `var/audit.db`. It aggregates the outputs of all other modules, computes deterministic metrics (per-host risk scores, CVE counts, exploitability flags, web finding counts), and then generates a narrative summary — either via the same AI providers as the remediation module (`audit_ai_provider`) or via deterministic local rules. The AI is given only facts already computed by the scanner, not raw packet data, so it synthesizes and prioritizes rather than invents findings.

The data-transfer and internal API module list includes `platform`, `neighborhood`, `portscanner`, `webscanner`, `metasploit`, `remediation`, `audit`, and `config`, so server-side consumers can ingest the new module outputs without changing the agent upload endpoint.

### Metasploit and AI remediation notes

**Metasploit correlation.** The preferred correlation method reads Metasploit's local module metadata cache (`~/.msf4/store/modules_metadata_base.json`) and matches the CVEs found by the scanners to exploit modules whose references include those CVEs. This is precise and fast (no `msfconsole` process is spawned). To enable it, install Metasploit and run `msfconsole` once so the cache is generated (or point `metasploit_metadata_path` at the file). Candidates are filtered by the target's detected OS so, for example, Windows exploits are not attached to a Linux host. If the metadata cache is unavailable, set `metasploit_enable_msfconsole_search=true` to fall back to a live `msfconsole search` (CVE-first; enable `metasploit_product_fallback_search=true` only if you accept noisier product/service keyword matches). Each candidate carries its `rank`, `platform`, the `matched_cve`, and the `correlation_method` used.

**AI remediation.** The remediation module always keeps the deterministic local-rule recommendation as a baseline and fallback. If an AI provider is unavailable or a response cannot be parsed, the finding is still saved with the rule-based recommendation and an `ai_error` field for troubleshooting.

- Free/local (recommended for sensitive data, fully offline): install Ollama, `ollama pull llama3.1:8b`, then:

  ```ini
  remediation_ai_provider = ollama
  remediation_ai_model = llama3.1:8b
  remediation_ollama_api_url = http://127.0.0.1:11434
  ```

- Free hosted (e.g. Groq). The API key is read from an environment variable (named by `remediation_ai_api_key_env`, default `SIAAS_AI_API_KEY`) so it is never written into synced configs:

  ```ini
  remediation_ai_provider = groq
  remediation_ai_model = llama-3.1-8b-instant
  # remediation_ai_api_base is auto-set per provider; override only if needed
  ```

  ```bash
  # export the key in the agent's environment (e.g. the systemd unit or your shell)
  export SIAAS_AI_API_KEY="your-key"
  ```

  `openai` (or any OpenAI-compatible endpoint via `remediation_ai_api_base`) and `gemini` are configured the same way, only changing `remediation_ai_provider` and `remediation_ai_model`.

### Security audit / posture summary

`siaas_audit.py` is the top-level aggregation module. It reads every other module's DB and produces a two-layer report:

1. **Deterministic metrics** (always present, no AI needed): per-host risk scores, total unique CVEs, exploitable hosts (those with Metasploit candidates), open-port counts, web finding counts, and an organization-level composite risk score and level (`info` → `low` → `medium` → `high` → `critical`).
2. **AI narrative** (optional): an executive posture summary, key risks, priority actions, positive observations, and a three-phase remediation roadmap — written from the metrics above, not invented. Uses the same provider options as the remediation module (`audit_ai_provider`).

Configure it the same way as the remediation AI:

```ini
audit_ai_provider = groq
audit_ai_model = llama-3.1-8b-instant
# SIAAS_AI_API_KEY env var is reused automatically
```

The AI narrative is cached by a signature of the current metrics, so unchanged scan results do not trigger a new API call. If the AI call fails, the deterministic narrative is saved instead with an `ai_error` field.

### Manual "Run now" module triggers

The `portscanner`, `webscanner`, `metasploit`, `remediation`, and `audit` modules normally run on their own timed loops. To run one on demand (e.g. from a GUI button), the internal agent API exposes:

```
POST /siaas-agent/trigger/<module>
```

This drops a `var/trigger_<module>` file; the module's loop detects it (within a couple of seconds), consumes it, and runs once immediately instead of waiting for its next interval. The internal API must be enabled for this to work:

```ini
enable_internal_api = true   # exposes the agent API on port 5001
```

Example:

```bash
curl -X POST http://<agent-host>:5001/siaas-agent/trigger/audit
# {"output": {"module": "audit", "message": "Manual run triggered..."}, "status": "success", ...}
```

Each module's loop uses an interruptible sleep, so the trigger takes effect almost immediately even when a long loop interval is configured. Stale trigger files are cleared on agent startup.

### Web scanner scan modes and resource usage

The OWASP ZAP web scanner is by far the heaviest component (a Java daemon plus crawling/attacking), so its weight is controlled by `zap_scan_mode`:

- `passive` (default): spider the site (bounded by `zap_spider_max_children`) and run passive analysis only — it does **not** attack the target. Much lighter; suitable for a Raspberry Pi. Finds missing headers, info leaks, cookie issues, outdated components, etc.
- `spider`: spider only.
- `active`: spider + full active scan — attacks every discovered endpoint/parameter. This is the heavy mode and can generate thousands of requests against deliberately-vulnerable apps.

Each phase has a time budget (`zap_spider_timeout_sec`, `zap_passive_timeout_sec`, `zap_ascan_timeout_sec`) after which it is stopped, so a single target cannot monopolize the host.

ZAP reports one alert *instance* per URL/parameter. The scanner deduplicates these into unique findings (what the detail table shows) while recording `instances` and a few `example_urls` per finding. Stats expose both `total_num_vulnerabilities` (unique) and `total_num_instances` (raw), so a count like "19 findings across 1138 instances" is no longer contradictory.

### Running light (Raspberry Pi)

`conf/siaas_agent.cnf.orig` ships a commented **low-resource preset**. In short: keep the portscanner (the lightweight core), run the web scanner in `passive` mode with a shallow spider (or disable it), lengthen the loop intervals, and on very small devices set `metasploit_use_metadata_cache = false` so the large Metasploit metadata JSON is not parsed into RAM.
