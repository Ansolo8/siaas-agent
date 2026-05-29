# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Metasploit assistant module
# Defensive Metasploit correlation/check planning module, 2026

import concurrent.futures
import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import time

import siaas_aux

logger = logging.getLogger(__name__)

BASE_DIR = sys.path[0]
VAR_DIR = os.path.join(BASE_DIR, "var")
METASPLOIT_DB = os.path.join(VAR_DIR, "metasploit.db")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MSF_MODULE_RE = re.compile(r"(?P<rank>\b(?:excellent|great|good|normal|average|low|manual)\b).*?(?P<module>exploit/[\w/\-]+)", re.IGNORECASE)


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


def _walk_values(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_values(nested)
    else:
        yield value


def extract_cves(value):
    cves = set()
    for item in _walk_values(value):
        if item is None:
            continue
        cves.update(match.upper() for match in CVE_RE.findall(str(item)))
    return sorted(cves)


def stable_id(*parts):
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def build_search_terms(service_name="", product="", cves=None):
    terms = []
    for cve in cves or []:
        terms.append(f"cve:{cve}")

    product_clean = re.sub(r"[^A-Za-z0-9_.+ -]", " ", product or "").strip()
    if product_clean:
        words = [word for word in product_clean.split() if len(word) > 2]
        if words:
            terms.append(" ".join(words[:3]))

    service_clean = re.sub(r"[^A-Za-z0-9_.+-]", " ", service_name or "").strip()
    if service_clean and service_clean.lower() not in ["unknown", "tcpwrapped"]:
        terms.append(f"type:exploit {service_clean}")

    # Keep order but remove duplicates.
    deduped = []
    for term in terms:
        if term and term not in deduped:
            deduped.append(term)
    return deduped


def get_msfconsole_path():
    configured = siaas_aux.get_config_from_configs_db(config_name="metasploit_msfconsole_path", convert_to_string=True)
    if configured:
        return configured
    return shutil.which("msfconsole")


def parse_msfconsole_search(output, limit=5):
    modules = []
    seen = set()
    for line in output.splitlines():
        if "exploit/" not in line:
            continue
        match = MSF_MODULE_RE.search(line)
        if not match:
            # Fallback for Metasploit versions whose table columns moved.
            module_match = re.search(r"exploit/[\w/\-]+", line)
            if not module_match:
                continue
            rank = "unknown"
            module_name = module_match.group(0)
        else:
            rank = match.group("rank").lower()
            module_name = match.group("module")
        if module_name in seen:
            continue
        seen.add(module_name)
        modules.append({"module": module_name, "rank": rank, "source": "msfconsole search"})
        if len(modules) >= limit:
            break
    return modules


def search_metasploit_modules(search_terms, timeout=90, limit=5):
    msfconsole = get_msfconsole_path()
    if not msfconsole:
        return [], "msfconsole not found in PATH; install Metasploit or configure metasploit_msfconsole_path"

    modules = []
    errors = []
    for term in search_terms:
        command = f"search {term}; exit -y"
        try:
            result = subprocess.run(
                [msfconsole, "-q", "-x", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"search timed out for '{term}' after {timeout}s")
            continue
        except Exception as exc:
            errors.append(f"search failed for '{term}': {exc}")
            continue

        if result.returncode != 0:
            errors.append(f"search returned {result.returncode} for '{term}': {result.stderr.strip()}")
            continue
        modules.extend(parse_msfconsole_search(result.stdout, limit=limit))
        if len(modules) >= limit:
            break

    deduped = []
    seen = set()
    for module in modules:
        if module["module"] in seen:
            continue
        seen.add(module["module"])
        deduped.append(module)
        if len(deduped) >= limit:
            break
    return deduped, "; ".join(errors)


def collect_target_services():
    targets = {}
    portscanner_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    if isinstance(portscanner_data, dict):
        for target, target_info in portscanner_data.items():
            target_record = targets.setdefault(target, {
                "system_info": target_info.get("system_info", {}),
                "services": {},
            })
            for port_proto, port_info in target_info.get("scanned_ports", {}).items():
                service_record = target_record["services"].setdefault(port_proto, {
                    "service": port_info.get("service", "unknown"),
                    "product": port_info.get("product", ""),
                    "state": port_info.get("state", "unknown"),
                    "source_modules": ["portscanner"],
                    "evidence": {},
                })
                service_record["evidence"]["portscanner_scan_results"] = port_info.get("scan_results", {})

    webscanner_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    if isinstance(webscanner_data, dict):
        for target, target_info in webscanner_data.items():
            target_record = targets.setdefault(target, {
                "system_info": target_info.get("system_info", {}),
                "services": {},
            })
            for port_proto, port_info in target_info.get("scanned_ports", {}).items():
                service_record = target_record["services"].setdefault(port_proto, {
                    "service": port_info.get("service", "web"),
                    "product": port_info.get("product", ""),
                    "state": port_info.get("state", "unknown"),
                    "source_modules": [],
                    "evidence": {},
                })
                if "webscanner" not in service_record["source_modules"]:
                    service_record["source_modules"].append("webscanner")
                service_record["evidence"]["webscanner_scan_results"] = port_info.get("scan_results", {})
                scanned_url = target_info.get("system_info", {}).get("scanned_url")
                if scanned_url:
                    service_record["scanned_url"] = scanned_url
    return targets


def assess_service(target, port_proto, service_record, enable_msf_search=False, timeout=90, limit=5):
    evidence = service_record.get("evidence", {})
    cves = extract_cves(evidence)
    search_terms = build_search_terms(service_record.get("service", ""), service_record.get("product", ""), cves)
    modules = []
    search_error = ""
    if enable_msf_search and search_terms:
        modules, search_error = search_metasploit_modules(search_terms, timeout=timeout, limit=limit)

    confidence = "high" if cves and modules else "medium" if cves or modules else "low"
    action = "review"
    if modules:
        action = "manual_validation_required"
    elif cves:
        action = "metasploit_module_not_found"

    return {
        "id": stable_id(target, port_proto, service_record.get("service", ""), service_record.get("product", ""), ",".join(cves)),
        "target": target,
        "port": port_proto,
        "service": service_record.get("service", "unknown"),
        "product": service_record.get("product", ""),
        "state": service_record.get("state", "unknown"),
        "source_modules": service_record.get("source_modules", []),
        "cves": cves,
        "search_terms": search_terms,
        "metasploit_modules": modules,
        "confidence": confidence,
        "recommended_action": action,
        "safety_note": "This module only correlates evidence with Metasploit module candidates; it does not run exploits or payloads.",
        "errors": search_error,
    }


def main():
    start_time = time.time()
    enable_msf_search = _config_bool("metasploit_enable_msfconsole_search", default=False)
    timeout = _config_int("metasploit_msfconsole_timeout_sec", 90)
    limit = _config_int("metasploit_search_result_limit", 5)
    max_workers = _config_int("metasploit_max_parallel_workers", 2)
    if max_workers < 1:
        max_workers = 1

    targets = collect_target_services()
    output = {
        "@generated": siaas_aux.get_now_utc_str(),
        "module_mode": "defensive_correlation",
        "msfconsole_search_enabled": enable_msf_search,
        "targets": {},
        "stats": {
            "num_targets": len(targets),
            "num_services": 0,
            "num_candidate_modules": 0,
            "time_taken_sec": 0,
        },
    }

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for target, target_record in targets.items():
            output["targets"][target] = {
                "system_info": target_record.get("system_info", {}),
                "services": {},
            }
            for port_proto, service_record in target_record.get("services", {}).items():
                futures.append((target, port_proto, executor.submit(
                    assess_service, target, port_proto, service_record, enable_msf_search, timeout, limit
                )))

        for target, port_proto, future in futures:
            try:
                assessed = future.result()
            except Exception as exc:
                logger.error(f"Metasploit assessment failed for {target} {port_proto}: {exc}")
                continue
            output["targets"][target]["services"][port_proto] = assessed
            output["stats"]["num_services"] += 1
            output["stats"]["num_candidate_modules"] += len(assessed.get("metasploit_modules", []))

    output["stats"]["time_taken_sec"] = int(time.time() - start_time)
    output["last_check"] = siaas_aux.get_now_utc_str()
    return output


def loop():
    os.makedirs(VAR_DIR, exist_ok=True)
    siaas_aux.write_to_local_file(METASPLOIT_DB, {})
    os.chmod(METASPLOIT_DB, os.stat(METASPLOIT_DB).st_mode & ~0o007)

    while True:
        disable = siaas_aux.get_config_from_configs_db(config_name="disable_metasploit", convert_to_string=True)
        if siaas_aux.validate_bool_string(disable):
            logger.warning("Metasploit assistant is disabled as per configuration! Not running.")
            time.sleep(60)
            continue

        try:
            results = main()
            siaas_aux.write_to_local_file(METASPLOIT_DB, results)
            logger.info("Metasploit assistant saved results for %s targets", len(results.get("targets", {})))
        except Exception as exc:
            logger.error(f"Metasploit assistant cycle failed: {exc}")

        sleep_time = _config_int("metasploit_loop_interval_sec", 86400)
        logger.debug("Sleeping for %s seconds before next Metasploit assistant loop ...", sleep_time)
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
    print(main())
