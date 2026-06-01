# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Security Audit / Posture Summary module
# Aggregates all scanner outputs and generates an organization-level security posture report, 2026

import hashlib
import json
import logging
import os
import re
import sys
import time

import requests

import siaas_aux

logger = logging.getLogger(__name__)

BASE_DIR = sys.path[0]
VAR_DIR = os.path.join(BASE_DIR, "var")
AUDIT_DB = os.path.join(VAR_DIR, "audit.db")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")
METASPLOIT_DB = os.path.join(VAR_DIR, "metasploit.db")
REMEDIATION_DB = os.path.join(VAR_DIR, "remediation.db")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 25, "info": 5, "unknown": 10}

RISK_LEVELS = [
    (80, "critical"),
    (60, "high"),
    (35, "medium"),
    (10, "low"),
    (0,  "info"),
]

AI_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst writing an executive security posture report for an organization. "
    "You are given structured metrics already computed by a deterministic scanner — do not invent findings, "
    "CVE identifiers, host names, or statistics that are not in the provided data. "
    "Your job is to synthesize the data into clear, actionable narrative for both technical and management audiences. "
    "Do NOT include exploit steps, payloads, or offensive instructions. "
    "Return ONLY valid JSON with exactly these keys:\n"
    "  overall_posture: one sentence rating (e.g. 'Poor — critical unpatched services exposed').\n"
    "  executive_summary: 2-4 sentences for management — business risk, not technical jargon.\n"
    "  key_risks: array of 3-5 strings, each a concise risk statement grounded in the data.\n"
    "  priority_actions: array of 3-5 strings, ordered by risk-reduction impact.\n"
    "  positive_observations: array of 1-3 strings noting what is already well-configured (if any).\n"
    "  remediation_roadmap: array of objects with keys 'phase' (string, e.g. 'Immediate / 0-7 days'), "
    "'actions' (array of strings). Use 3 phases: Immediate, Short-term, Long-term."
)

PROVIDER_DEFAULTS = {
    "ollama": {"model": "llama3.1:8b"},
    "groq":   {"api_base": "https://api.groq.com/openai/v1", "model": "llama-3.1-8b-instant", "key_env": "SIAAS_AI_API_KEY"},
    "openai": {"api_base": "https://api.openai.com/v1",      "model": "gpt-4o-mini",           "key_env": "SIAAS_AI_API_KEY"},
    "gemini": {"api_base": "https://generativelanguage.googleapis.com/v1beta", "model": "gemini-1.5-flash", "key_env": "SIAAS_AI_API_KEY"},
}


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _config_bool(name, default=False):
    value = siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True)
    if value is None:
        return default
    return siaas_aux.validate_bool_string(value, default_output=default)


def _config_int(name, default):
    try:
        return int(siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True))
    except Exception:
        return default


def _config_string(name, default=""):
    value = siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True)
    if value is None or value == "":
        return default
    return value


# ---------------------------------------------------------------------------
# Data collection — read each scanner DB
# ---------------------------------------------------------------------------

def _collect_portscanner():
    """Returns list of host dicts from portscanner.db."""
    data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    hosts = []
    for host_key, host_data in data.items():
        if not isinstance(host_data, dict):
            continue
        hosts.append({"host": host_key, "data": host_data})
    return hosts


def _collect_webscanner():
    """Returns list of target dicts from webscanner.db."""
    data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    targets = []
    for target_key, target_data in data.items():
        if not isinstance(target_data, dict):
            continue
        targets.append({"target": target_key, "data": target_data})
    return targets


def _collect_metasploit():
    """Returns the metasploit.db dict (keyed by host)."""
    return siaas_aux.read_from_local_file(METASPLOIT_DB) or {}


def _collect_remediation():
    """Returns the remediation_plan list from remediation.db."""
    data = siaas_aux.read_from_local_file(REMEDIATION_DB) or {}
    return data.get("remediation_plan", [])


# ---------------------------------------------------------------------------
# Deterministic metric computation
# ---------------------------------------------------------------------------

def _extract_cves(obj):
    cves = set()
    text = json.dumps(obj)
    for m in CVE_RE.findall(text):
        cves.add(m.upper())
    return sorted(cves)


def _risk_score(severity):
    return SEVERITY_SCORE.get((severity or "unknown").lower(), 10)


def _risk_label(score):
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "info"


def compute_host_metrics(portscanner_hosts, metasploit_db, remediation_plan):
    """
    Returns a list of per-host metric dicts, sorted by risk score descending.

    Portscanner DB layout (per host):
        data["system_info"] (os_family etc.)
        data["scanned_ports"][port]["scan_results"] (nmap script output, scanned for CVEs)
    Severity counts are derived from the remediation findings overlay (which already
    classify each finding), since nmap raw output has no structured severity field.
    """
    host_metrics = {}

    # --- portscanner data ---
    for entry in portscanner_hosts:
        host = entry["host"]
        data = entry["data"]
        ports = []
        cves = set()
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}

        for port_key, port_data in (data.get("scanned_ports", {}) or {}).items():
            if not isinstance(port_data, dict):
                continue
            ports.append(port_key)
            for cve in _extract_cves(port_data.get("scan_results", {})):
                cves.add(cve)

        os_family = data.get("system_info", {}).get("os_family", "") or data.get("os_family", "")
        host_metrics[host] = {
            "host": host,
            "open_ports": ports,
            "num_open_ports": len(ports),
            "os_family": os_family,
            "cves": sorted(cves),
            "num_cves": len(cves),
            "severity_counts": severity_counts,
            "exploitable": False,
            "metasploit_modules": [],
            "remediation_findings": [],
            "risk_score": 0,
            "risk_level": "info",
        }

    # --- metasploit overlay ---
    # Metasploit DB layout: metasploit_db["targets"][host]["services"][port]["metasploit_modules"]
    for host, host_entry in (metasploit_db.get("targets", {}) or {}).items():
        if host not in host_metrics:
            host_metrics[host] = {
                "host": host,
                "open_ports": [],
                "num_open_ports": 0,
                "os_family": "",
                "cves": [],
                "num_cves": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
                "exploitable": False,
                "metasploit_modules": [],
                "remediation_findings": [],
                "risk_score": 0,
                "risk_level": "info",
            }
        modules = []
        if isinstance(host_entry, dict):
            for port_key, svc in (host_entry.get("services", {}) or {}).items():
                if isinstance(svc, dict):
                    for m in svc.get("metasploit_modules", []):
                        # Each module descriptor uses the "module" key (see siaas_metasploit).
                        modules.append(m.get("module", m.get("name", str(m))) if isinstance(m, dict) else str(m))
        if modules:
            host_metrics[host]["exploitable"] = True
            host_metrics[host]["metasploit_modules"] = modules

    # --- remediation overlay ---
    # Remediation findings already carry a classified severity, so use them as the
    # authoritative source for each host's severity_counts.
    for finding in remediation_plan:
        target = finding.get("target", "")
        if target in host_metrics:
            sev = (finding.get("severity") or "unknown").lower()
            if sev not in host_metrics[target]["severity_counts"]:
                sev = "unknown"
            host_metrics[target]["severity_counts"][sev] += 1
            host_metrics[target]["remediation_findings"].append({
                "id": finding.get("id", ""),
                "severity": finding.get("severity", "unknown"),
                "description": finding.get("description", ""),
            })

    # --- compute composite risk score per host ---
    for host, m in host_metrics.items():
        sc = m["severity_counts"]
        score = (
            sc.get("critical", 0) * 100 +
            sc.get("high",     0) *  80 +
            sc.get("medium",   0) *  50 +
            sc.get("low",      0) *  25 +
            sc.get("unknown",  0) *  10
        )
        score += m["num_cves"] * 15
        if m["exploitable"]:
            score += 200
        score += m["num_open_ports"] * 2
        m["risk_score"] = score
        m["risk_level"] = _risk_label(min(score, 100))

    return sorted(host_metrics.values(), key=lambda h: -h["risk_score"])


def compute_web_metrics(webscanner_targets):
    """
    Returns a list of per-target web metric dicts, sorted by risk score.

    Webscanner DB layout (per target):
        data["stats"]["total_num_vulnerabilities"|"total_num_instances"|"total_num_exploits"]
        data["scanned_ports"][port]["scan_results"]["zap_scan"]["vuln"][vuln_id]["severity"]
    """
    results = []
    for entry in webscanner_targets:
        target = entry["target"]
        data = entry["data"]
        stats = data.get("stats", {}) or {}
        unique = stats.get("total_num_vulnerabilities", 0)
        instances = stats.get("total_num_instances", 0)
        # The webscanner counts high-severity findings under "total_num_exploits".
        high = stats.get("total_num_exploits", 0)

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        scan_mode = "unknown"
        # Walk every scanned port -> scan_results. In scan_results the "zap_scan" key
        # maps directly to the ZAP content (scan_mode, vuln dict), so no extra nesting.
        for port_proto, port_data in (data.get("scanned_ports", {}) or {}).items():
            if not isinstance(port_data, dict):
                continue
            for scan_name, zap_scan in (port_data.get("scan_results", {}) or {}).items():
                if not isinstance(zap_scan, dict):
                    continue
                scan_mode = zap_scan.get("scan_mode", scan_mode)
                for vuln_id, vuln in (zap_scan.get("vuln", {}) or {}).items():
                    sev = (vuln.get("severity") or "unknown").lower()
                    if sev not in sev_counts:
                        sev = "unknown"
                    sev_counts[sev] += 1

        score = (
            sev_counts.get("critical", 0) * 100 +
            sev_counts.get("high",     0) *  80 +
            sev_counts.get("medium",   0) *  50 +
            sev_counts.get("low",      0) *  25
        )
        results.append({
            "target": target,
            "total_unique_findings": unique,
            "total_instances": instances,
            "high_findings": high,
            "severity_counts": sev_counts,
            "scan_mode": scan_mode,
            "risk_score": score,
            "risk_level": _risk_label(min(score, 100)),
        })

    return sorted(results, key=lambda t: -t["risk_score"])


def compute_org_metrics(host_metrics, web_metrics, remediation_plan):
    """Computes organization-level aggregate metrics."""
    total_hosts = len(host_metrics)
    total_web_targets = len(web_metrics)
    exploitable_hosts = sum(1 for h in host_metrics if h["exploitable"])
    total_cves = len({cve for h in host_metrics for cve in h["cves"]})
    total_open_ports = sum(h["num_open_ports"] for h in host_metrics)
    total_web_findings = sum(t["total_unique_findings"] for t in web_metrics)
    total_web_instances = sum(t["total_instances"] for t in web_metrics)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for finding in remediation_plan:
        sev = (finding.get("severity") or "unknown").lower()
        if sev not in sev_counts:
            sev = "unknown"
        sev_counts[sev] += 1

    most_exposed_hosts = [h["host"] for h in host_metrics[:5]]
    most_exposed_web = [t["target"] for t in web_metrics[:3]]

    # Overall org risk score: weighted average of top hosts + web
    all_scores = [h["risk_score"] for h in host_metrics] + [t["risk_score"] for t in web_metrics]
    avg_score = (sum(all_scores) / len(all_scores)) if all_scores else 0
    peak_score = max(all_scores) if all_scores else 0
    # Blend: 40% peak (a single critical host drags the org up), 60% average
    org_score = 0.4 * peak_score + 0.6 * avg_score

    return {
        "total_hosts_scanned": total_hosts,
        "total_web_targets_scanned": total_web_targets,
        "total_open_ports": total_open_ports,
        "total_unique_cves": total_cves,
        "exploitable_hosts": exploitable_hosts,
        "total_web_findings": total_web_findings,
        "total_web_instances": total_web_instances,
        "remediation_severity_counts": sev_counts,
        "most_exposed_hosts": most_exposed_hosts,
        "most_exposed_web_targets": most_exposed_web,
        "org_risk_score": round(org_score, 1),
        "org_risk_level": _risk_label(min(org_score, 100)),
    }


# ---------------------------------------------------------------------------
# AI narrative generation
# ---------------------------------------------------------------------------

def _ai_signature(provider, model, metrics_snapshot):
    raw = json.dumps({"provider": provider, "model": model, "metrics": metrics_snapshot}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _resolve_api_key():
    key_env = _config_string("audit_ai_api_key_env", "SIAAS_AI_API_KEY")
    key = os.environ.get(key_env, "")
    if not key:
        key = _config_string("audit_ai_api_key", "")
    return key


def _call_ollama(prompt, model, api_url, timeout):
    url = api_url.rstrip("/") + "/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    content = resp.json()["message"]["content"].strip()
    return json.loads(content)


def _call_openai_compatible(prompt, api_base, model, api_key, timeout):
    if not api_key:
        raise ValueError("missing API key (set the env var named by audit_ai_api_key_env)")
    url = api_base.rstrip("/") + "/chat/completions"
    headers = {"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.2,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"].strip()
    # Strip markdown fences if present
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\n?", "", content)
        content = re.sub(r"\n?```$", "", content)
    return json.loads(content)


def _call_gemini(prompt, api_base, model, api_key, timeout):
    if not api_key:
        raise ValueError("missing API key (set the env var named by audit_ai_api_key_env)")
    url = api_base.rstrip("/") + "/models/" + model + ":generateContent?key=" + api_key
    payload = {
        "system_instruction": {"parts": [{"text": AI_SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    content = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\n?", "", content)
        content = re.sub(r"\n?```$", "", content)
    return json.loads(content)


def _build_ai_prompt(org_metrics, host_metrics, web_metrics):
    """Build the structured prompt fed to the AI. Only facts — no instructions."""
    prompt_data = {
        "organization_metrics": org_metrics,
        "top_hosts_by_risk": [
            {
                "host": h["host"],
                "risk_level": h["risk_level"],
                "risk_score": h["risk_score"],
                "open_ports": h["open_ports"],
                "os_family": h["os_family"],
                "cves": h["cves"][:10],
                "exploitable": h["exploitable"],
                "metasploit_modules": h["metasploit_modules"][:5],
            }
            for h in host_metrics[:10]
        ],
        "web_targets": [
            {
                "target": t["target"],
                "risk_level": t["risk_level"],
                "total_unique_findings": t["total_unique_findings"],
                "high_findings": t["high_findings"],
                "scan_mode": t["scan_mode"],
            }
            for t in web_metrics[:5]
        ],
    }
    return (
        "Below is the structured security scan data for this organization. "
        "Generate the posture report as specified in your instructions.\n\n"
        + json.dumps(prompt_data, indent=2)
    )


def generate_ai_narrative(org_metrics, host_metrics, web_metrics, existing_report):
    """
    Call the configured AI provider and return the narrative dict.
    Uses a signature-based cache: if the metrics haven't changed since the last
    run, the prior AI answer is reused without a new API call.
    """
    provider = _config_string("audit_ai_provider", "local_rules").lower().strip()
    if provider == "local_rules" or provider == "":
        return None, None, False  # (narrative, sig, ai_enabled)

    defaults = PROVIDER_DEFAULTS.get(provider, {})
    model   = _config_string("audit_ai_model",   defaults.get("model",    ""))
    timeout = _config_int("audit_ai_timeout_sec", 60)

    metrics_snapshot = {
        "org": org_metrics,
        "hosts": [{"host": h["host"], "risk_score": h["risk_score"]} for h in host_metrics],
        "web": [{"target": t["target"], "risk_score": t["risk_score"]} for t in web_metrics],
    }
    sig = _ai_signature(provider, model, metrics_snapshot)

    # Cache hit: if sig matches prior run, reuse stored narrative
    prior = existing_report or {}
    if prior.get("ai_signature") == sig and prior.get("ai_narrative"):
        logger.debug("Audit AI narrative cache hit (sig=%s)", sig)
        return prior["ai_narrative"], sig, True

    prompt = _build_ai_prompt(org_metrics, host_metrics, web_metrics)

    try:
        if provider == "ollama":
            api_url = _config_string("audit_ollama_api_url", "http://127.0.0.1:11434")
            narrative = _call_ollama(prompt, model, api_url, timeout)
        elif provider == "gemini":
            api_base = _config_string("audit_ai_api_base", defaults.get("api_base", ""))
            narrative = _call_gemini(prompt, api_base, model, _resolve_api_key(), timeout)
        else:
            api_base = _config_string("audit_ai_api_base", defaults.get("api_base", ""))
            narrative = _call_openai_compatible(prompt, api_base, model, _resolve_api_key(), timeout)

        logger.info("Audit AI narrative generated (provider=%s model=%s)", provider, model)
        return narrative, sig, True

    except Exception as exc:
        logger.error("Audit AI narrative failed (provider=%s): %s", provider, exc)
        return None, sig, True  # ai_enabled=True but narrative=None → fallback


def _deterministic_narrative(org_metrics, host_metrics, web_metrics):
    """Fallback narrative built entirely from deterministic metrics."""
    risk = org_metrics.get("org_risk_level", "unknown")
    n_hosts = org_metrics.get("total_hosts_scanned", 0)
    n_cves = org_metrics.get("total_unique_cves", 0)
    exploitable = org_metrics.get("exploitable_hosts", 0)
    n_web = org_metrics.get("total_web_findings", 0)
    sev = org_metrics.get("remediation_severity_counts", {})

    posture = f"{risk.title()} — {n_hosts} host(s) scanned, {n_cves} unique CVE(s) found."
    if exploitable:
        posture += f" {exploitable} host(s) have known Metasploit exploit candidates."

    summary_parts = [
        f"The scan covered {n_hosts} host(s) and {org_metrics.get('total_web_targets_scanned', 0)} web target(s).",
    ]
    if sev.get("critical", 0) or sev.get("high", 0):
        summary_parts.append(
            f"{sev.get('critical', 0)} critical and {sev.get('high', 0)} high-severity findings require immediate attention."
        )
    if exploitable:
        summary_parts.append(
            f"{exploitable} host(s) have public exploit modules available — these pose the highest business risk."
        )
    if n_web:
        summary_parts.append(f"{n_web} unique web vulnerability type(s) were found across web targets.")

    key_risks = []
    if exploitable:
        key_risks.append(f"{exploitable} host(s) have Metasploit-exploitable findings.")
    if n_cves:
        key_risks.append(f"{n_cves} unique CVE(s) identified across scanned hosts.")
    if sev.get("critical", 0):
        key_risks.append(f"{sev['critical']} critical-severity finding(s) detected.")
    if n_web:
        key_risks.append(f"{n_web} web vulnerability type(s) across {org_metrics.get('total_web_instances', 0)} instance(s).")
    if org_metrics.get("total_open_ports", 0) > 20:
        key_risks.append(f"Large attack surface: {org_metrics['total_open_ports']} open ports across scanned hosts.")

    priority_actions = []
    if exploitable:
        priority_actions.append("Immediately patch services with known Metasploit exploit candidates.")
    if sev.get("critical", 0) or sev.get("high", 0):
        priority_actions.append("Remediate all critical and high-severity findings before lower priorities.")
    if n_cves:
        priority_actions.append("Review vendor advisories for all identified CVEs and apply patches.")
    if n_web:
        priority_actions.append("Address high-severity web findings (e.g. XSS, injection, missing headers).")
    priority_actions.append("Re-run all scans after remediation to verify fixes.")

    roadmap = [
        {
            "phase": "Immediate / 0-7 days",
            "actions": [a for a in priority_actions[:2]] or ["Triage and assign all critical/high findings."],
        },
        {
            "phase": "Short-term / 7-30 days",
            "actions": ["Patch remaining high/medium findings.", "Harden web application security headers.", "Review firewall rules and reduce exposed attack surface."],
        },
        {
            "phase": "Long-term / 30+ days",
            "actions": ["Implement a recurring vulnerability scanning schedule.", "Integrate scanner output into CI/CD pipelines where applicable.", "Train development and operations teams on secure configuration."],
        },
    ]

    positives = []
    if not exploitable:
        positives.append("No Metasploit-exploitable findings detected.")
    if sev.get("critical", 0) == 0:
        positives.append("No critical-severity findings detected.")
    if not positives:
        positives.append("Scanning and monitoring infrastructure is operational.")

    return {
        "overall_posture": posture,
        "executive_summary": " ".join(summary_parts),
        "key_risks": key_risks or ["No significant risks detected in this scan cycle."],
        "priority_actions": priority_actions or ["Maintain current patching cadence and re-scan regularly."],
        "positive_observations": positives,
        "remediation_roadmap": roadmap,
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report():
    start_time = time.time()
    logger.info("Security audit starting: aggregating all scanner module outputs ...")

    portscanner_hosts = _collect_portscanner()
    webscanner_targets = _collect_webscanner()
    metasploit_db = _collect_metasploit()
    remediation_plan = _collect_remediation()
    logger.info("Audit input — portscanner hosts: %s, webscanner targets: %s, metasploit hosts: %s, remediation findings: %s",
                len(portscanner_hosts), len(webscanner_targets), len(metasploit_db), len(remediation_plan))

    if not portscanner_hosts and not webscanner_targets:
        logger.warning("No host or web data available yet. The other scanner modules have likely "
                       "not produced var/portscanner.db or var/webscanner.db yet; the audit will "
                       "retry on the fast interval until data appears.")

    host_metrics = compute_host_metrics(portscanner_hosts, metasploit_db, remediation_plan)
    web_metrics  = compute_web_metrics(webscanner_targets)
    org_metrics  = compute_org_metrics(host_metrics, web_metrics, remediation_plan)
    logger.info("Computed metrics — org risk: %s (score %s); %s exploitable host(s), %s unique CVE(s)",
                org_metrics["org_risk_level"], org_metrics["org_risk_score"],
                org_metrics["exploitable_hosts"], org_metrics["total_unique_cves"])

    existing_report = siaas_aux.read_from_local_file(AUDIT_DB) or {}

    narrative, ai_sig, ai_enabled = generate_ai_narrative(org_metrics, host_metrics, web_metrics, existing_report)
    if narrative is None:
        if ai_enabled:
            logger.warning("AI narrative unavailable; using deterministic local-rules narrative instead.")
        else:
            logger.info("AI narrative disabled (audit_ai_provider=local_rules); using deterministic narrative.")
        narrative = _deterministic_narrative(org_metrics, host_metrics, web_metrics)
        narrative_source = "local_rules"
        ai_error = existing_report.get("ai_error") if ai_enabled else None
    else:
        narrative_source = _config_string("audit_ai_provider", "local_rules") + "/" + _config_string(
            "audit_ai_model", PROVIDER_DEFAULTS.get(_config_string("audit_ai_provider", ""), {}).get("model", ""))
        ai_error = None

    report = {
        "@generated": siaas_aux.get_now_utc_str(),
        "module_mode": "ai_assisted_audit" if ai_enabled else "local_rules_audit",
        "narrative_source": narrative_source,
        "org_metrics": org_metrics,
        "host_metrics": host_metrics,
        "web_metrics": web_metrics,
        "narrative": narrative,
        "ai_signature": ai_sig,
        "stats": {
            "time_taken_sec": int(time.time() - start_time),
            "sources": {
                "portscanner_hosts": len(portscanner_hosts),
                "webscanner_targets": len(webscanner_targets),
                "metasploit_hosts": len(metasploit_db),
                "remediation_findings": len(remediation_plan),
            },
        },
        "last_check": siaas_aux.get_now_utc_str(),
    }
    if ai_error:
        report["ai_error"] = ai_error

    return report


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------

def loop():
    os.makedirs(VAR_DIR, exist_ok=True)
    if not os.path.exists(AUDIT_DB):
        siaas_aux.write_to_local_file(AUDIT_DB, {})
    os.chmod(AUDIT_DB, os.stat(AUDIT_DB).st_mode & ~0o007)

    # This module does not run automatically on startup — it waits for a manual
    # trigger from the GUI ("Run now" button) before its first execution.
    # After the first run it continues on the normal loop interval automatically.
    first_run = True

    while True:
        disable = siaas_aux.get_config_from_configs_db(config_name="disable_audit", convert_to_string=True)
        if siaas_aux.validate_bool_string(disable):
            logger.warning("Security audit module is disabled as per configuration! Not running.")
            time.sleep(60)
            continue

        if first_run:
            logger.info("Security audit module waiting for a manual trigger from the GUI to start the first run ...")
            siaas_aux.interruptible_sleep("audit", 999999)
            first_run = False
            logger.info("Security audit first-run trigger received. Starting now ...")

        report = None
        try:
            report = build_report()
            siaas_aux.write_to_local_file(AUDIT_DB, report)
            logger.info(
                "Security audit saved — org risk: %s (score: %s), hosts: %d, web targets: %d",
                report["org_metrics"]["org_risk_level"],
                report["org_metrics"]["org_risk_score"],
                report["org_metrics"]["total_hosts_scanned"],
                report["org_metrics"]["total_web_targets_scanned"],
            )
        except Exception as exc:
            logger.error("Security audit cycle failed: %s", exc)

        # Quick retry while scanners haven't produced data yet
        if report is not None and report["org_metrics"]["total_hosts_scanned"] == 0 and report["org_metrics"]["total_web_targets_scanned"] == 0:
            sleep_time = _config_int("audit_initial_retry_interval_sec", 300)
        else:
            sleep_time = _config_int("audit_loop_interval_sec", 3600)

        logger.debug("Sleeping for %s seconds before next audit loop ...", sleep_time)
        if siaas_aux.interruptible_sleep("audit", sleep_time):
            logger.info("Audit module woke up early due to a manual run trigger.")


if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
    )
    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)
    siaas_aux.write_config_db_from_conf_file(output=os.path.join(VAR_DIR, "config.db"))
    print(json.dumps(build_report(), indent=2))
