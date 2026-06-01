# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - AI-style remediation advisor module
# Local-rules and optional free AI (Ollama/Groq/OpenAI-compatible/Gemini) remediation report generator, 2026

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
REMEDIATION_DB = os.path.join(VAR_DIR, "remediation.db")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")
METASPLOIT_DB = os.path.join(VAR_DIR, "metasploit.db")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SEVERITY_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 25, "info": 5, "unknown": 10}

# System prompt shared by every provider: defensive scope, no exploit content,
# and grounding rules to limit hallucination of fake fixes/versions.
AI_SYSTEM_PROMPT = (
    "You are a defensive cybersecurity remediation assistant for a vulnerability scanner. "
    "Analyze the scanner evidence and produce remediation guidance specific to this finding. "
    "Do not provide exploit steps, payloads, or instructions to compromise systems. "
    "Base your guidance on the provided evidence and well-established vendor hardening practices. "
    "Do NOT invent specific patch version numbers, CVE identifiers, or product names that are not "
    "present in the evidence; when a precise fixed version is unknown, instruct the operator to "
    "consult the official vendor advisory for the listed CVEs instead. "
    "Return ONLY valid JSON with these keys: risk_summary, likely_impact, remediation_steps, "
    "validation_steps, priority_reasoning. remediation_steps and validation_steps must be arrays "
    "of concise actionable strings."
)

# Sensible defaults so users only need to set provider + API key for hosted options.
PROVIDER_DEFAULTS = {
    "ollama": {"model": "llama3.1:8b"},
    "groq": {"api_base": "https://api.groq.com/openai/v1", "model": "llama-3.1-8b-instant", "key_env": "SIAAS_AI_API_KEY"},
    "openai": {"api_base": "https://api.openai.com/v1", "model": "gpt-4o-mini", "key_env": "SIAAS_AI_API_KEY"},
    "gemini": {"api_base": "https://generativelanguage.googleapis.com/v1beta", "model": "gemini-1.5-flash", "key_env": "SIAAS_AI_API_KEY"},
}

SERVICE_RECOMMENDATIONS = {
    "ssh": "Restrict SSH exposure to trusted networks, disable password login where possible, use key-based authentication, and keep the SSH daemon updated.",
    "http": "Patch the web server/application stack, enforce TLS, review security headers, validate inputs server-side, and retest with OWASP ZAP after changes.",
    "https": "Patch the web server/application stack, enforce modern TLS settings, review certificates/security headers, and retest with OWASP ZAP after changes.",
    "smb": "Apply vendor security updates, disable SMBv1, restrict file sharing to trusted networks, and audit share permissions.",
    "mysql": "Restrict database listener exposure, patch the database server, enforce strong authentication, and review least-privilege grants.",
    "postgresql": "Restrict database listener exposure, patch PostgreSQL, enforce strong authentication, and review pg_hba.conf and database roles.",
    "rdp": "Restrict RDP exposure, enforce Network Level Authentication and MFA/VPN access, and apply Windows security updates.",
    "ftp": "Replace FTP with SFTP/FTPS where possible, disable anonymous access, and restrict exposure to trusted networks.",
}


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


def stable_id(*parts):
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def walk_values(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from walk_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_values(nested)
    else:
        yield value


def extract_cves(value):
    cves = set()
    for item in walk_values(value):
        if item is not None:
            cves.update(match.upper() for match in CVE_RE.findall(str(item)))
    return sorted(cves)


def infer_severity(value):
    text = " ".join(str(item).lower() for item in walk_values(value) if item is not None)
    for sev in ["critical", "high", "medium", "low", "informational", "info"]:
        if sev in text:
            return "info" if sev == "informational" else sev
    if extract_cves(value):
        return "high"
    return "unknown"


def recommendation_for(service, source, description="", cves=None, metasploit_modules=None):
    service_lower = (service or "").lower()
    for key, recommendation in SERVICE_RECOMMENDATIONS.items():
        if key in service_lower:
            base = recommendation
            break
    else:
        base = "Patch or upgrade the affected service/application, remove unnecessary exposure, and retest to confirm the finding is resolved."

    additions = []
    if cves:
        additions.append("Prioritize vendor advisories for " + ", ".join(cves[:5]) + ".")
    if metasploit_modules:
        additions.append("Because Metasploit modules exist for this evidence, validate business impact in an authorized test window and remediate before broad exposure.")
    if source == "webscanner":
        additions.append("Use the ZAP alert solution/reference fields as implementation guidance for the web application team.")
    return " ".join([base] + additions)


def _trim_text(value, limit=1200):
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit - 3] + "..."


def finding_ai_context(finding):
    return {
        "source": finding.get("source", ""),
        "target": finding.get("target", ""),
        "port": finding.get("port", ""),
        "service": finding.get("service", ""),
        "product": finding.get("product", ""),
        "severity": finding.get("severity", ""),
        "title": finding.get("title", ""),
        "description": _trim_text(finding.get("description", "")),
        "cves": finding.get("cves", []),
        "cwe": finding.get("cwe", ""),
        "reference": _trim_text(finding.get("reference", "")),
        "metasploit_modules": [m.get("module", m) if isinstance(m, dict) else m for m in finding.get("metasploit_modules", [])],
        "scanner_recommendation": _trim_text(finding.get("recommendation", "")),
    }


def build_user_content(finding):
    context = json.dumps(finding_ai_context(finding), sort_keys=False)
    return (
        "Use the scanner_recommendation field as a trusted baseline and refine it for this specific "
        "finding. Scanner evidence (JSON): " + context
    )


def build_ollama_prompt(finding):
    # Ollama's /api/generate takes a single prompt, so the system prompt is prepended.
    return AI_SYSTEM_PROMPT + "\n\n" + build_user_content(finding)


def _extract_json_object(text):
    if not text:
        raise ValueError("empty model response")
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("model response did not contain a JSON object")
    return json.loads(text[start:end + 1])


def _validate_ai_result(ai_result):
    if not isinstance(ai_result.get("remediation_steps", []), list):
        raise ValueError("model remediation_steps was not a list")
    if not isinstance(ai_result.get("validation_steps", []), list):
        raise ValueError("model validation_steps was not a list")
    return ai_result


def ollama_remediation(finding, api_url, model, timeout):
    payload = {
        "model": model,
        "prompt": build_ollama_prompt(finding),
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2, "num_predict": 700},
    }
    response = requests.post(api_url.rstrip("/") + "/api/generate", json=payload, timeout=timeout)
    response.raise_for_status()
    model_text = response.json().get("response", "")
    return _validate_ai_result(_extract_json_object(model_text))


def openai_compatible_remediation(finding, api_base, model, api_key, timeout):
    """
    Works with any OpenAI-compatible chat completions endpoint: Groq, OpenAI,
    OpenRouter, Mistral, Together, etc. Most offer a free tier.
    """
    if not api_key:
        raise ValueError("missing API key (set the env var named by remediation_ai_api_key_env)")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": build_user_content(finding)},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    response = requests.post(api_base.rstrip("/") + "/chat/completions", json=payload, headers=headers, timeout=timeout)
    response.raise_for_status()
    model_text = response.json()["choices"][0]["message"]["content"]
    return _validate_ai_result(_extract_json_object(model_text))


def gemini_remediation(finding, api_base, model, api_key, timeout):
    if not api_key:
        raise ValueError("missing API key (set the env var named by remediation_ai_api_key_env)")
    url = api_base.rstrip("/") + "/models/" + model + ":generateContent?key=" + api_key
    payload = {
        "system_instruction": {"parts": [{"text": AI_SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": build_user_content(finding)}]}],
        "generationConfig": {"temperature": 0.2, "response_mime_type": "application/json"},
    }
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    model_text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
    return _validate_ai_result(_extract_json_object(model_text))


def _resolve_api_key():
    key_env = _config_string("remediation_ai_api_key_env", "SIAAS_AI_API_KEY")
    key = os.environ.get(key_env, "")
    if not key:
        # Convenience fallback; the env var is preferred so keys are not synced in configs.
        key = _config_string("remediation_ai_api_key", "")
    return key


def _call_provider(provider, finding, model, timeout):
    if provider == "ollama":
        api_url = _config_string("remediation_ollama_api_url", "http://127.0.0.1:11434")
        return ollama_remediation(finding, api_url, model, timeout)
    if provider in ("groq", "openai"):
        api_base = _config_string("remediation_ai_api_base", PROVIDER_DEFAULTS[provider]["api_base"])
        return openai_compatible_remediation(finding, api_base, model, _resolve_api_key(), timeout)
    if provider == "gemini":
        api_base = _config_string("remediation_ai_api_base", PROVIDER_DEFAULTS["gemini"]["api_base"])
        return gemini_remediation(finding, api_base, model, _resolve_api_key(), timeout)
    raise ValueError("unsupported remediation_ai_provider: " + provider)


def _ai_signature(provider, model, finding):
    """Signature over provider/model and the AI-relevant evidence, used for caching."""
    return stable_id(provider, model, json.dumps(finding_ai_context(finding), sort_keys=True))


def enrich_with_ai(remediation_plan):
    provider = _config_string("remediation_ai_provider", "local_rules").lower().strip()
    if provider in ["", "none", "local_rules", "rules"]:
        logger.info("AI remediation disabled (remediation_ai_provider=local_rules); using deterministic rules for %s finding(s)", len(remediation_plan))
        return remediation_plan, {"enabled": False, "provider": "local_rules"}
    if provider not in PROVIDER_DEFAULTS:
        logger.warning("Unsupported remediation_ai_provider '%s'; falling back to local rules. Supported: %s",
                       provider, ", ".join(PROVIDER_DEFAULTS.keys()))
        return remediation_plan, {"enabled": False, "provider": provider, "error": "unsupported remediation_ai_provider"}

    model = _config_string("remediation_ai_model", PROVIDER_DEFAULTS[provider]["model"])
    timeout = _config_int("remediation_ai_timeout_sec", 60)
    max_findings = _config_int("remediation_ai_max_findings", 20)
    cache_enabled = _config_bool("remediation_ai_cache", default=True)
    logger.info("AI remediation enabled (provider=%s, model=%s, timeout=%ss, max_new_calls=%s, cache=%s) for %s finding(s)",
                provider, model, timeout, max_findings, cache_enabled, len(remediation_plan))
    stats = {"enabled": True, "provider": provider, "model": model,
             "attempted": 0, "succeeded": 0, "failed": 0, "cached": 0}

    calls_made = 0
    for finding in remediation_plan:
        signature = _ai_signature(provider, model, finding)

        # Reuse a previous AI answer when nothing relevant changed (carried over by merge_state).
        if cache_enabled and finding.get("ai_remediation") and finding.get("ai_signature") == signature:
            stats["cached"] += 1
            if finding["ai_remediation"].get("remediation_steps"):
                finding["recommendation"] = " ".join(str(step) for step in finding["ai_remediation"]["remediation_steps"][:5])
            finding.pop("ai_error", None)
            continue

        if calls_made >= max_findings:
            continue  # leave the rule-based recommendation in place for the overflow

        calls_made += 1
        stats["attempted"] += 1
        logger.info("Querying %s/%s for finding %s (%s on %s %s)...",
                    provider, model, finding.get("id"), finding.get("service", "?"),
                    finding.get("target", "?"), finding.get("port", "?"))
        try:
            ai_result = _call_provider(provider, finding, model, timeout)
            finding["ai_remediation"] = ai_result
            finding["ai_model"] = model
            finding["ai_signature"] = signature
            finding.pop("ai_error", None)
            if ai_result.get("remediation_steps"):
                finding["recommendation"] = " ".join(str(step) for step in ai_result["remediation_steps"][:5])
            stats["succeeded"] += 1
            logger.info("AI remediation succeeded for finding %s", finding.get("id"))
        except Exception as exc:
            finding["ai_error"] = str(exc)
            finding.pop("ai_signature", None)
            stats["failed"] += 1
            logger.warning("AI remediation failed for finding %s: %s (kept rule-based recommendation)",
                           finding.get("id"), exc)

    logger.info("AI remediation finished: %s attempted, %s succeeded, %s failed, %s reused from cache",
                stats["attempted"], stats["succeeded"], stats["failed"], stats["cached"])
    return remediation_plan, stats


def merge_state(existing_report, finding):
    existing_findings = {}
    if isinstance(existing_report, dict):
        for old in existing_report.get("remediation_plan", []):
            if isinstance(old, dict) and old.get("id"):
                existing_findings[old["id"]] = old
    old = existing_findings.get(finding["id"], {})
    finding["first_seen"] = old.get("first_seen", finding["last_seen"])
    finding["status"] = old.get("status", "open")
    finding["notes"] = old.get("notes", "")
    # Carry over a previously generated AI answer so enrich_with_ai can reuse it (caching).
    for key in ("ai_remediation", "ai_model", "ai_signature"):
        if old.get(key) is not None:
            finding[key] = old[key]
    return finding


def collect_portscanner_findings():
    findings = []
    data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    if not isinstance(data, dict):
        return findings
    for target, target_info in data.items():
        for port_proto, port_info in target_info.get("scanned_ports", {}).items():
            scan_results = port_info.get("scan_results", {})
            if not scan_results:
                continue
            cves = extract_cves(scan_results)
            severity = infer_severity(scan_results)
            if severity == "unknown" and not cves:
                continue
            service = port_info.get("service", "unknown")
            product = port_info.get("product", "")
            findings.append({
                "id": stable_id("portscanner", target, port_proto, service, product, ",".join(cves)),
                "source": "portscanner",
                "target": target,
                "port": port_proto,
                "service": service,
                "product": product,
                "severity": severity,
                "score": SEVERITY_SCORE.get(severity, 10),
                "title": f"Portscanner finding on {service} {port_proto}",
                "description": "Nmap vulnerability scripts reported evidence requiring review.",
                "cves": cves,
                "recommendation": recommendation_for(service, "portscanner", cves=cves),
                "last_seen": siaas_aux.get_now_utc_str(),
            })
    return findings


def collect_webscanner_findings():
    findings = []
    data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    if not isinstance(data, dict):
        return findings
    for target, target_info in data.items():
        scanned_url = target_info.get("system_info", {}).get("scanned_url", target)
        for port_proto, port_info in target_info.get("scanned_ports", {}).items():
            for scan_name, scan_result in port_info.get("scan_results", {}).items():
                vuln_bucket = scan_result.get("zap_scan", {}).get("vuln", {}) if isinstance(scan_result, dict) else {}
                for vuln_id, vuln in vuln_bucket.items():
                    severity = vuln.get("severity", "unknown")
                    cves = extract_cves(vuln)
                    title = vuln.get("description", vuln_id)
                    if len(title) > 120:
                        title = title[:117] + "..."
                    service = port_info.get("service", "http")
                    findings.append({
                        "id": stable_id("webscanner", target, port_proto, vuln_id, scanned_url),
                        "source": "webscanner",
                        "target": target,
                        "port": port_proto,
                        "service": service,
                        "product": port_info.get("product", ""),
                        "severity": severity,
                        "score": SEVERITY_SCORE.get(severity, 10),
                        "title": title,
                        "description": vuln.get("description", "OWASP ZAP reported a web application finding."),
                        "cves": cves,
                        "cwe": vuln.get("cwe", ""),
                        "reference": vuln.get("reference", ""),
                        "instances": vuln.get("instances", 1),
                        "example_urls": vuln.get("example_urls", []),
                        "recommendation": vuln.get("solution") or recommendation_for(service, "webscanner", cves=cves),
                        "last_seen": siaas_aux.get_now_utc_str(),
                    })
    return findings


def collect_metasploit_findings():
    findings = []
    data = siaas_aux.read_from_local_file(METASPLOIT_DB) or {}
    if not isinstance(data, dict):
        return findings
    for target, target_info in data.get("targets", {}).items():
        for port_proto, service_info in target_info.get("services", {}).items():
            modules = service_info.get("metasploit_modules", [])
            cves = service_info.get("cves", [])
            if not modules and not cves:
                continue
            service = service_info.get("service", "unknown")
            severity = "critical" if modules and cves else "high" if cves else "medium"
            findings.append({
                "id": stable_id("metasploit", target, port_proto, service, ",".join(cves), ",".join(m.get("module", "") for m in modules)),
                "source": "metasploit",
                "target": target,
                "port": port_proto,
                "service": service,
                "product": service_info.get("product", ""),
                "severity": severity,
                "score": SEVERITY_SCORE.get(severity, 10),
                "title": f"Metasploit exploit candidates for {service} {port_proto}",
                "description": "Scanner evidence correlates with CVEs and/or Metasploit exploit module candidates.",
                "cves": cves,
                "metasploit_modules": modules,
                "recommendation": recommendation_for(service, "metasploit", cves=cves, metasploit_modules=modules),
                "last_seen": siaas_aux.get_now_utc_str(),
            })
    return findings


def build_report():
    start_time = time.time()
    logger.info("Remediation advisor starting: collecting findings from scanner DBs ...")
    existing = siaas_aux.read_from_local_file(REMEDIATION_DB) or {}
    ps_findings = collect_portscanner_findings()
    web_findings = collect_webscanner_findings()
    msf_findings = collect_metasploit_findings()
    logger.info("Collected findings — portscanner: %s, webscanner: %s, metasploit: %s",
                len(ps_findings), len(web_findings), len(msf_findings))
    findings = ps_findings + web_findings + msf_findings
    if not findings:
        logger.warning("No findings collected from any scanner. Either the scanners have not finished "
                       "their first run yet (var/portscanner.db / var/webscanner.db / var/metasploit.db "
                       "empty), or no vulnerabilities were detected.")
    deduped = {}
    for finding in findings:
        current = deduped.get(finding["id"])
        if current is None or finding.get("score", 0) > current.get("score", 0):
            deduped[finding["id"]] = finding
    logger.info("Deduplicated %s raw finding(s) into %s unique finding(s)", len(findings), len(deduped))

    remediation_plan = [merge_state(existing, finding) for finding in deduped.values()]
    remediation_plan.sort(key=lambda item: (-item.get("score", 0), item.get("target", ""), item.get("port", "")))

    max_items = _config_int("remediation_max_report_items", 200)
    remediation_plan = remediation_plan[:max_items]
    remediation_plan, ai_stats = enrich_with_ai(remediation_plan)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    target_counts = {}
    for finding in remediation_plan:
        counts[finding.get("severity", "unknown")] = counts.get(finding.get("severity", "unknown"), 0) + 1
        target_counts[finding.get("target", "unknown")] = target_counts.get(finding.get("target", "unknown"), 0) + 1

    report = {
        "@generated": siaas_aux.get_now_utc_str(),
        "module_mode": "ai_assisted_remediation" if ai_stats.get("enabled") else "local_rules_remediation",
        "executive_summary": {
            "total_open_findings": len(remediation_plan),
            "severity_counts": counts,
            "most_affected_targets": sorted(target_counts.items(), key=lambda item: item[1], reverse=True)[:10],
            "recommended_next_step": "Start with critical/high findings that have CVEs or Metasploit candidates, then retest affected services after remediation.",
        },
        "remediation_plan": remediation_plan,
        "stats": {
            "time_taken_sec": int(time.time() - start_time),
            "sources": ["portscanner", "webscanner", "metasploit"],
            "ai": ai_stats,
        },
        "last_check": siaas_aux.get_now_utc_str(),
    }
    logger.info("Remediation advisor ended: %s finding(s) in report (mode=%s, severity=%s). Elapsed time: %s seconds",
                len(remediation_plan), report["module_mode"], counts, report["stats"]["time_taken_sec"])
    return report


def loop():
    os.makedirs(VAR_DIR, exist_ok=True)
    if not os.path.exists(REMEDIATION_DB):
        siaas_aux.write_to_local_file(REMEDIATION_DB, {})
    os.chmod(REMEDIATION_DB, os.stat(REMEDIATION_DB).st_mode & ~0o007)

    # This module does not run automatically on startup — it waits for a manual
    # trigger from the GUI ("Run now" button) before its first execution.
    # After the first run it continues on the normal loop interval automatically.
    first_run = True

    while True:
        disable = siaas_aux.get_config_from_configs_db(config_name="disable_remediation", convert_to_string=True)
        if siaas_aux.validate_bool_string(disable):
            logger.warning("Remediation advisor is disabled as per configuration! Not running.")
            time.sleep(60)
            continue

        if first_run:
            logger.info("Remediation advisor waiting for a manual trigger from the GUI to start the first run ...")
            siaas_aux.interruptible_sleep("remediation", 999999)
            first_run = False
            logger.info("Remediation advisor first-run trigger received. Starting now ...")

        report = None
        try:
            report = build_report()
            siaas_aux.write_to_local_file(REMEDIATION_DB, report)
            logger.info("Remediation advisor saved %s findings", len(report.get("remediation_plan", [])))
        except Exception as exc:
            logger.error(f"Remediation advisor cycle failed: {exc}")

        # While there are no findings yet (scanners still running on their own loops),
        # retry quickly so results appear soon after a scan completes, instead of
        # waiting a full long interval. Once findings exist, use the normal interval.
        if report is not None and len(report.get("remediation_plan", [])) == 0:
            sleep_time = _config_int("remediation_initial_retry_interval_sec", 300)
        else:
            sleep_time = _config_int("remediation_loop_interval_sec", 3600)
        logger.debug("Sleeping for %s seconds before next remediation advisor loop ...", sleep_time)
        if siaas_aux.interruptible_sleep("remediation", sleep_time):
            logger.info("Remediation module woke up early due to a manual run trigger.")


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
    print(build_report())
