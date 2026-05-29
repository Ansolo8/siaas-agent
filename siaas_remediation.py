# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - AI-style remediation advisor module
# Deterministic remediation report generator, 2026

import hashlib
import logging
import os
import re
import sys
import time

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
    return siaas_aux.validate_bool_string(value)


def _config_int(name, default):
    try:
        return int(siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True))
    except Exception:
        return default


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
    existing = siaas_aux.read_from_local_file(REMEDIATION_DB) or {}
    findings = collect_portscanner_findings() + collect_webscanner_findings() + collect_metasploit_findings()
    deduped = {}
    for finding in findings:
        current = deduped.get(finding["id"])
        if current is None or finding.get("score", 0) > current.get("score", 0):
            deduped[finding["id"]] = finding

    remediation_plan = [merge_state(existing, finding) for finding in deduped.values()]
    remediation_plan.sort(key=lambda item: (-item.get("score", 0), item.get("target", ""), item.get("port", "")))

    max_items = _config_int("remediation_max_report_items", 200)
    remediation_plan = remediation_plan[:max_items]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    target_counts = {}
    for finding in remediation_plan:
        counts[finding.get("severity", "unknown")] = counts.get(finding.get("severity", "unknown"), 0) + 1
        target_counts[finding.get("target", "unknown")] = target_counts.get(finding.get("target", "unknown"), 0) + 1

    report = {
        "@generated": siaas_aux.get_now_utc_str(),
        "module_mode": "local_ai_style_rule_engine",
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
        },
        "last_check": siaas_aux.get_now_utc_str(),
    }
    return report


def loop():
    os.makedirs(VAR_DIR, exist_ok=True)
    if not os.path.exists(REMEDIATION_DB):
        siaas_aux.write_to_local_file(REMEDIATION_DB, {})
    os.chmod(REMEDIATION_DB, os.stat(REMEDIATION_DB).st_mode & ~0o007)

    while True:
        disable = siaas_aux.get_config_from_configs_db(config_name="disable_remediation", convert_to_string=True)
        if siaas_aux.validate_bool_string(disable):
            logger.warning("Remediation advisor is disabled as per configuration! Not running.")
            time.sleep(60)
            continue
        try:
            report = build_report()
            siaas_aux.write_to_local_file(REMEDIATION_DB, report)
            logger.info("Remediation advisor saved %s findings", len(report.get("remediation_plan", [])))
        except Exception as exc:
            logger.error(f"Remediation advisor cycle failed: {exc}")
        sleep_time = _config_int("remediation_loop_interval_sec", 3600)
        logger.debug("Sleeping for %s seconds before next remediation advisor loop ...", sleep_time)
        time.sleep(sleep_time)


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
