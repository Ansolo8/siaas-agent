# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Metasploit assistant module
# Defensive Metasploit correlation/check planning module, 2026

import concurrent.futures
import hashlib
import json
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

# Metasploit ranks the local metadata cache stores as integers; map them to the
# canonical names so the output is consistent regardless of correlation source.
RANK_SCORE_TO_NAME = {600: "excellent", 500: "great", 400: "good", 300: "normal", 200: "average", 100: "low", 0: "manual"}
RANK_NAME_TO_SCORE = {name: score for score, name in RANK_SCORE_TO_NAME.items()}

# Candidate locations for Metasploit's pre-built module metadata cache. Reading
# this JSON lets us correlate CVEs to modules in-process, without spawning a
# msfconsole per search term (which is slow and produces noisy keyword matches).
DEFAULT_METADATA_PATHS = [
    os.path.expanduser("~/.msf4/store/modules_metadata_base.json"),
    "/root/.msf4/store/modules_metadata_base.json",
    "/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json",
    "/usr/share/metasploit-framework/db/modules_metadata_base.json",
]

# Module-level cache so the (large) metadata file is parsed once and only
# re-read when the file changes on disk.
_METADATA_INDEX = None
_METADATA_MTIME = None
_METADATA_SOURCE = None


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


def normalize_platform(value):
    """
    Maps OS/platform free text (from scanner system_info or module metadata) to a
    small set of canonical platform tokens used for relevance filtering.
    """
    text = str(value or "").lower()
    tokens = set()
    if any(k in text for k in ["windows", "win32", "win64", "microsoft"]):
        tokens.add("windows")
    if any(k in text for k in ["linux", "ubuntu", "debian", "centos", "red hat", "redhat", "fedora"]):
        tokens.add("linux")
    if any(k in text for k in ["unix", "bsd", "solaris", "aix", "macos", "mac os", "osx", "darwin", "android"]):
        tokens.add("unix")
    return tokens


def target_platform_tokens(system_info):
    """
    Builds the set of platform tokens for a target from its scanner system_info.
    """
    if not isinstance(system_info, dict):
        return set()
    tokens = set()
    for key in ("os_family", "os_name", "os_vendor", "os_type"):
        tokens |= normalize_platform(system_info.get(key, ""))
    return tokens


def _rank_name(raw_rank):
    if isinstance(raw_rank, (int, float)):
        return RANK_SCORE_TO_NAME.get(int(raw_rank), "unknown")
    name = str(raw_rank or "").strip().lower()
    return name if name in RANK_NAME_TO_SCORE else "unknown"


def _rank_score(rank_name):
    return RANK_NAME_TO_SCORE.get(rank_name, -1)


def get_metadata_path():
    configured = _config_string("metasploit_metadata_path")
    candidates = [configured] if configured else []
    candidates += DEFAULT_METADATA_PATHS
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def load_metadata_index():
    """
    Loads and indexes Metasploit's module metadata by CVE. The index maps each
    CVE -> list of exploit module descriptors. Cached in-process and refreshed
    only when the backing file's mtime changes. Returns (index, source_path) or
    (None, error_string).
    """
    global _METADATA_INDEX, _METADATA_MTIME, _METADATA_SOURCE

    path = get_metadata_path()
    if not path:
        return None, "metadata cache not found (run msfconsole once to generate ~/.msf4/store/modules_metadata_base.json, or set metasploit_metadata_path)"

    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        return None, f"could not stat metadata file: {exc}"

    if _METADATA_INDEX is not None and _METADATA_SOURCE == path and _METADATA_MTIME == mtime:
        return _METADATA_INDEX, path

    try:
        with open(path, "r") as handle:
            raw = json.load(handle)
    except Exception as exc:
        return None, f"could not parse metadata file {path}: {exc}"

    index = {}
    for fullname, meta in raw.items():
        if not isinstance(meta, dict):
            continue
        if str(meta.get("type", "")).lower() != "exploit":
            continue
        references = meta.get("references", []) or []
        cves = {str(ref).upper() for ref in references if str(ref).upper().startswith("CVE-")}
        if not cves:
            continue
        descriptor = {
            "module": meta.get("fullname", fullname),
            "rank": _rank_name(meta.get("rank")),
            "platform": meta.get("platform", ""),
            "name": meta.get("name", ""),
            "disclosure_date": meta.get("disclosure_date", ""),
            "source": "metadata_cache",
        }
        for cve in cves:
            index.setdefault(cve, []).append(descriptor)

    _METADATA_INDEX = index
    _METADATA_MTIME = mtime
    _METADATA_SOURCE = path
    logger.info("Loaded Metasploit metadata index from %s (%s CVEs mapped to exploit modules)", path, len(index))
    return index, path


def correlate_via_metadata(cves, platform_tokens, filter_platform=True, limit=5):
    """
    Correlates a list of CVEs to Metasploit exploit modules using the local
    metadata index. This is precise (CVE reference match), unlike a keyword
    search. Optionally drops modules whose platform contradicts the target OS.
    Returns (modules, matched_cves, error_string).
    """
    index, source = load_metadata_index()
    if index is None:
        return [], [], source  # source carries the error message here

    modules = []
    matched_cves = set()
    seen = set()
    for cve in cves:
        for descriptor in index.get(cve.upper(), []):
            if filter_platform and platform_tokens:
                module_tokens = normalize_platform(descriptor.get("platform", ""))
                # Keep platform-agnostic modules (no tokens) and matches only.
                if module_tokens and not (module_tokens & platform_tokens):
                    continue
            matched_cves.add(cve.upper())
            module_name = descriptor["module"]
            if module_name in seen:
                continue
            seen.add(module_name)
            enriched = dict(descriptor)
            enriched["matched_cve"] = cve.upper()
            modules.append(enriched)

    # Highest rank first, then by module name for determinism.
    modules.sort(key=lambda m: (-_rank_score(m.get("rank", "unknown")), m.get("module", "")))
    return modules[:limit], sorted(matched_cves), ""


def build_search_terms(service_name="", product="", cves=None, product_fallback=False):
    """
    Builds msfconsole search terms. CVE searches are precise and always preferred.
    Product/service keyword searches are noisy (they match unrelated modules) and
    are only emitted when explicitly enabled via product_fallback.
    """
    terms = []
    for cve in cves or []:
        terms.append(f"cve:{cve}")

    if product_fallback:
        product_clean = re.sub(r"[^A-Za-z0-9_.+ -]", " ", product or "").strip()
        if product_clean:
            words = [word for word in product_clean.split() if len(word) > 2]
            if words:
                terms.append("type:exploit " + " ".join(words[:3]))

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
        modules.append({"module": module_name, "rank": rank, "source": "msfconsole_search"})
        if len(modules) >= limit:
            break
    return modules


def search_metasploit_modules(search_terms, platform_tokens=None, filter_platform=True, timeout=90, limit=5):
    """
    Fallback correlation using msfconsole's search command. Only used when the
    metadata cache is unavailable. Platform filtering is best-effort here because
    the search table does not always carry platform data.
    """
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
    deduped.sort(key=lambda m: (-_rank_score(m.get("rank", "unknown")), m.get("module", "")))
    return deduped[:limit], "; ".join(errors)


def collect_target_services():
    targets = {}
    portscanner_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    if isinstance(portscanner_data, dict):
        logger.info("Reading portscanner DB: %s target(s) present", len(portscanner_data))
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
        logger.info("Reading webscanner DB: %s target(s) present", len(webscanner_data))
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

    total_services = sum(len(t.get("services", {})) for t in targets.values())
    logger.info("Collected %s target(s) with %s service(s) total for Metasploit correlation",
                len(targets), total_services)
    return targets


def assess_service(target, port_proto, service_record, system_info=None, enable_msf_search=False,
                   use_metadata=True, filter_platform=True, product_fallback=False, timeout=90, limit=5):
    evidence = service_record.get("evidence", {})
    cves = extract_cves(evidence)
    platform_tokens = target_platform_tokens(system_info)
    service_label = service_record.get("service", "unknown")

    if cves:
        logger.info("Correlating %s %s (%s): %s CVE(s) in evidence [%s], target platform=%s",
                    target, port_proto, service_label, len(cves), ", ".join(cves[:5]),
                    sorted(platform_tokens) or "unknown")
    else:
        logger.debug("Correlating %s %s (%s): no CVEs found in scanner evidence; nothing to correlate",
                     target, port_proto, service_label)

    modules = []
    matched_cves = []
    search_terms = []
    correlation_method = "none"
    search_error = ""

    # Preferred path: precise CVE->module correlation from the local metadata cache.
    if use_metadata and cves:
        modules, matched_cves, search_error = correlate_via_metadata(
            cves, platform_tokens, filter_platform=filter_platform, limit=limit)
        if modules:
            correlation_method = "metadata_cache"
            logger.info("%s %s: metadata cache matched %s module(s) for CVE(s) %s",
                        target, port_proto, len(modules), ", ".join(matched_cves))
        elif search_error:
            logger.warning("%s %s: metadata correlation could not run: %s",
                           target, port_proto, search_error)

    # Fallback path: live msfconsole search (CVE-first; product keyword optional).
    if not modules and enable_msf_search:
        search_terms = build_search_terms(
            service_record.get("service", ""), service_record.get("product", ""), cves,
            product_fallback=product_fallback)
        if search_terms:
            logger.info("%s %s: falling back to msfconsole search with terms: %s",
                        target, port_proto, search_terms)
            modules, fallback_error = search_metasploit_modules(
                search_terms, platform_tokens=platform_tokens, filter_platform=filter_platform,
                timeout=timeout, limit=limit)
            if modules:
                correlation_method = "msfconsole_search"
                logger.info("%s %s: msfconsole search matched %s module(s)",
                            target, port_proto, len(modules))
            if fallback_error:
                logger.warning("%s %s: msfconsole search reported: %s",
                               target, port_proto, fallback_error)
            search_error = "; ".join(filter(None, [search_error, fallback_error]))

    if cves and not modules:
        logger.info("%s %s: %s CVE(s) found but no Metasploit module correlates to them "
                    "(this is normal — not every CVE has a public module)",
                    target, port_proto, len(cves))

    confidence = "high" if cves and modules else "medium" if cves or modules else "low"
    if modules:
        action = "manual_validation_required"
    elif cves:
        action = "metasploit_module_not_found"
    else:
        action = "review"

    return {
        "id": stable_id(target, port_proto, service_record.get("service", ""), service_record.get("product", ""), ",".join(cves)),
        "target": target,
        "port": port_proto,
        "service": service_record.get("service", "unknown"),
        "product": service_record.get("product", ""),
        "state": service_record.get("state", "unknown"),
        "source_modules": service_record.get("source_modules", []),
        "target_platform": sorted(platform_tokens),
        "cves": cves,
        "matched_cves": matched_cves,
        "search_terms": search_terms,
        "correlation_method": correlation_method,
        "metasploit_modules": modules,
        "confidence": confidence,
        "recommended_action": action,
        "safety_note": "This module only correlates evidence with Metasploit module candidates; it does not run exploits or payloads.",
        "errors": search_error,
    }


def _source_stats():
    stats = {}
    for name, path in (("portscanner", PORTSCANNER_DB), ("webscanner", WEBSCANNER_DB)):
        data = siaas_aux.read_from_local_file(path) or {}
        if isinstance(data, dict):
            stats[name] = {
                "db_path": path,
                "exists": os.path.exists(path),
                "num_targets": len(data),
            }
        else:
            stats[name] = {
                "db_path": path,
                "exists": os.path.exists(path),
                "num_targets": 0,
                "error": "database did not contain a dictionary",
            }
    return stats


def main():
    start_time = time.time()
    enable_msf_search = _config_bool("metasploit_enable_msfconsole_search", default=False)
    use_metadata = _config_bool("metasploit_use_metadata_cache", default=True)
    filter_platform = _config_bool("metasploit_filter_by_platform", default=True)
    product_fallback = _config_bool("metasploit_product_fallback_search", default=False)
    timeout = _config_int("metasploit_msfconsole_timeout_sec", 90)
    limit = _config_int("metasploit_search_result_limit", 5)
    max_workers = _config_int("metasploit_max_parallel_workers", 2)
    if max_workers < 1:
        max_workers = 1

    logger.info(
        "Metasploit correlation starting (metadata_cache=%s, platform_filter=%s, "
        "msfconsole_fallback=%s, product_fallback=%s, max_workers=%s, result_limit=%s)",
        use_metadata, filter_platform, enable_msf_search, product_fallback, max_workers, limit)

    metadata_status = ""
    if use_metadata:
        _, metadata_status = load_metadata_index()
        if _METADATA_INDEX is None:
            logger.warning("Metasploit metadata cache unavailable: %s", metadata_status)

    targets = collect_target_services()
    output = {
        "@generated": siaas_aux.get_now_utc_str(),
        "module_mode": "defensive_correlation",
        "msfconsole_search_enabled": enable_msf_search,
        "metadata_cache_enabled": use_metadata,
        "metadata_cache_source": _METADATA_SOURCE if use_metadata else None,
        "platform_filtering_enabled": filter_platform,
        "targets": {},
        "stats": {
            "num_targets": len(targets),
            "num_services": 0,
            "num_candidate_modules": 0,
            "time_taken_sec": 0,
            "input_sources": _source_stats(),
        },
    }

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for target, target_record in targets.items():
            system_info = target_record.get("system_info", {})
            output["targets"][target] = {
                "system_info": system_info,
                "services": {},
            }
            for port_proto, service_record in target_record.get("services", {}).items():
                futures.append((target, port_proto, executor.submit(
                    assess_service, target, port_proto, service_record, system_info,
                    enable_msf_search, use_metadata, filter_platform, product_fallback, timeout, limit
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
    logger.info(
        "Metasploit correlation ended: %s target(s), %s service(s) assessed, %s candidate module(s) found. "
        "Elapsed time: %s seconds",
        output["stats"]["num_targets"], output["stats"]["num_services"],
        output["stats"]["num_candidate_modules"], output["stats"]["time_taken_sec"])
    if use_metadata and (_METADATA_INDEX is None):
        output["operator_note"] = (
            "Metasploit metadata cache could not be loaded (" + str(metadata_status) + "). "
            "Run msfconsole once to generate it, set metasploit_metadata_path, or enable "
            "metasploit_enable_msfconsole_search=true as a fallback."
        )
    elif not enable_msf_search and not use_metadata:
        output["operator_note"] = (
            "Both correlation methods are disabled. Enable metasploit_use_metadata_cache=true "
            "(recommended) and/or metasploit_enable_msfconsole_search=true to populate "
            "metasploit_modules."
        )
    if not targets:
        output["operator_note"] = (
            "No portscanner/webscanner targets were available when the Metasploit assistant ran. "
            "This usually means those scanners have not written var/portscanner.db or "
            "var/webscanner.db yet; the loop will retry using metasploit_no_data_retry_interval_sec."
        )
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

        results = None
        try:
            results = main()
            siaas_aux.write_to_local_file(METASPLOIT_DB, results)
            if len(results.get("targets", {})) == 0:
                logger.warning(
                    "Metasploit assistant found 0 targets. Waiting for scanner DB data; source stats: %s",
                    results.get("stats", {}).get("input_sources", {})
                )
            else:
                logger.info(
                    "Metasploit assistant saved results for %s targets and %s candidate modules",
                    len(results.get("targets", {})),
                    results.get("stats", {}).get("num_candidate_modules", 0)
                )
        except Exception as exc:
            logger.error(f"Metasploit assistant cycle failed: {exc}")

        if results is not None and len(results.get("targets", {})) == 0:
            sleep_time = _config_int("metasploit_no_data_retry_interval_sec", 300)
        else:
            sleep_time = _config_int("metasploit_loop_interval_sec", 3600)
        logger.debug("Sleeping for %s seconds before next Metasploit assistant loop ...", sleep_time)
        if siaas_aux.interruptible_sleep("metasploit", sleep_time):
            logger.info("Metasploit module woke up early due to a manual run trigger.")


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
