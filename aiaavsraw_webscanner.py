# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - WebScanner module (OWASP ZAP via Docker)
# Extended by <O TEU NOME>, 2026

import siaas_aux
import os
import sys
import time
import json
import logging
import subprocess
import tempfile
import requests
import urllib3
import threading
import uuid
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)
ZAP_DAEMON_READY = False
ZAP_DAEMON_START_ATTEMPTED = False
ZAP_DAEMON_LAST_ERROR = None
ZAP_API_SCAN_LOCK = threading.Lock()

BASE_DIR = sys.path[0]
VAR_DIR = os.path.join(BASE_DIR, "var")
WEB_DB = os.path.join(VAR_DIR, "webscanner.db")
PORT_DB = os.path.join(VAR_DIR, "portscanner.db")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------
# AUXILIARY FUNCTIONS
# --------------------------------------------------

def is_web_service(port, protocol, service=None):
    """
    Identifies web services based on port, protocol or service name
    """
    if protocol.lower() != "tcp":
        return False

    common_ports = ["80", "443", "8080", "8000", "8443", "3000", "5000", "9000"]
    if port in common_ports:
        return True

    if service and "http" in service.lower():
        return True

    return False




def get_candidate_urls(host, port):
    """
    Builds ordered candidate URLs for a host/port based on common scheme usage
    """
    port = str(port)

    if port in ["443", "8443"]:
        primary = ["https", "http"]
    elif port in ["80", "8080", "8000", "3000", "5000", "9000"]:
        primary = ["http", "https"]
    else:
        primary = ["http", "https"]

    candidates = []
    for scheme in primary:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            candidates.append(f"{scheme}://{host}")
        else:
            candidates.append(f"{scheme}://{host}:{port}")

    return candidates
def build_url(host, port):
    """
    Builds a valid URL from host and port.
    Tries candidates, then falls back to conventional scheme for the port.
    """
    candidates = get_candidate_urls(host, port)

    for candidate in candidates:
        if check_url_accessible(candidate):
            return candidate

    # Nothing reachable at probe time; return best-effort default
    return candidates[0]


def check_url_accessible(url, timeout=5):
    """
    Check if URL is accessible
    """
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return response.status_code < 500  # Accept any status except server errors
    except:
        return False


def get_web_app_info(url):
    """
    Get basic web application information
    """
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        server_info = {
            "scanned_url": url,
            "status_code": response.status_code,
            "server": response.headers.get('Server', 'Unknown'),
            "content_type": response.headers.get('Content-Type', 'Unknown'),
            "content_length": len(response.content)
        }
        
        # Extract endpoints from page
        endpoints = {}
        if response.status_code == 200:
            # Extract links from HTML
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for link in links[:10]:  # Limit to first 10 links
                if link and not link.startswith(('#', 'javascript:', 'mailto:')):
                    full_url = urlparse(url)._replace(path=link).geturl()
                    endpoints[full_url] = {
                        'status': 'found',
                        'source': 'page_link'
                    }
        
        return server_info, endpoints
        
    except Exception as e:
        logger.error(f"Error getting web app info for {url}: {str(e)}")
        return {"scanned_url": url, "error": str(e)}, {}


# --------------------------------------------------
# OWASP ZAP API HELPERS
# --------------------------------------------------

# Severity ranking used to keep the highest severity seen across the many
# instances ZAP reports for the same alert type.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _cfg_str(name, default=""):
    value = siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True)
    return value if value not in (None, "") else default


def _cfg_int(name, default):
    try:
        return int(siaas_aux.get_config_from_configs_db(config_name=name, convert_to_string=True))
    except Exception:
        return default


def _risk_to_severity(riskdesc):
    risk = (riskdesc or "").lower()
    if "high" in risk:
        return "high"
    if "medium" in risk:
        return "medium"
    if "low" in risk:
        return "low"
    if "informational" in risk or "info" in risk:
        return "info"
    return "medium"


def get_zap_api_settings():
    """
    Loads ZAP API settings from config DB, with sane defaults.
    """
    zap_api_base = siaas_aux.get_config_from_configs_db(
        config_name="zap_api_base", convert_to_string=True
    ) or "http://127.0.0.1:8090"
    zap_api_key = siaas_aux.get_config_from_configs_db(
        config_name="zap_api_key", convert_to_string=True
    ) or ""
    zap_timeout = siaas_aux.get_config_from_configs_db(
        config_name="zap_scan_timeout_sec", convert_to_string=True
    )
    try:
        zap_timeout = int(zap_timeout)
    except:
        zap_timeout = 900

    zap_use_docker = siaas_aux.validate_bool_string(
        siaas_aux.get_config_from_configs_db(
            config_name="zap_use_docker_daemon", convert_to_string=True
        ) or "true"
    )

    return {
        "base": zap_api_base.rstrip('/'),
        "key": zap_api_key,
        "timeout": zap_timeout,
        "use_docker": zap_use_docker,
    }


def zap_api_get(zap_base, component, call, params=None, timeout=30):
    """
    Calls a ZAP JSON API endpoint and returns parsed JSON.
    """
    if params is None:
        params = {}
    endpoint = f"{zap_base}/JSON/{component}/{call}/"
    response = requests.get(
        endpoint, params=params, timeout=timeout, verify=False, allow_redirects=True
    )
    response.raise_for_status()
    return response.json()


def ensure_zap_daemon(settings):
    """
    Ensures ZAP daemon API is available.
    Optionally starts a dockerized daemon when configured.
    """
    global ZAP_DAEMON_READY, ZAP_DAEMON_START_ATTEMPTED, ZAP_DAEMON_LAST_ERROR

    zap_base = settings["base"]
    zap_key = settings.get("key", "")
    zap_url = urlparse(zap_base)
    zap_host = zap_url.hostname or "127.0.0.1"
    zap_port = zap_url.port or 8090
    health_params = {"apikey": zap_key} if zap_key else {}

    if ZAP_DAEMON_READY:
        return True

    # Fast-path: already available
    try:
        zap_api_get(zap_base, "core", "view/version", params=health_params)
        ZAP_DAEMON_READY = True
        return True
    except Exception:
        pass

    if not settings["use_docker"]:
        ZAP_DAEMON_LAST_ERROR = f"ZAP API not reachable at {zap_base} and docker autostart is disabled"
        logger.error(ZAP_DAEMON_LAST_ERROR)
        return False

    if ZAP_DAEMON_START_ATTEMPTED:
        if ZAP_DAEMON_LAST_ERROR:
            logger.error(f"ZAP daemon is still unavailable: {ZAP_DAEMON_LAST_ERROR}")
        return False

    ZAP_DAEMON_START_ATTEMPTED = True
    logger.warning(f"ZAP API unavailable at {zap_base}. Trying to start dockerized ZAP daemon ...")
    try:
        docker_info = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if docker_info.returncode != 0:
            ZAP_DAEMON_LAST_ERROR = "Docker daemon is unavailable"
            logger.error(f"{ZAP_DAEMON_LAST_ERROR}: {docker_info.stderr.strip()}")
            return False

        subprocess.run(
            ["docker", "rm", "-f", "siaas-zap-daemon"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", "siaas-zap-daemon",
                "-p", f"{zap_host}:{zap_port}:{zap_port}",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap.sh", "-daemon",
                "-host", "0.0.0.0",
                "-port", str(zap_port),
                "-config", "api.disablekey=true" if not zap_key else "api.disablekey=false",
                "-config", f"api.key={zap_key}" if zap_key else "api.key=",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
    except Exception as e:
        ZAP_DAEMON_LAST_ERROR = f"Failed to start ZAP daemon container: {e}"
        logger.error(ZAP_DAEMON_LAST_ERROR)
        return False

    # Wait for API readiness
    for _ in range(30):
        try:
            zap_api_get(zap_base, "core", "view/version", params=health_params)
            logger.info("ZAP daemon API is ready")
            ZAP_DAEMON_READY = True
            ZAP_DAEMON_LAST_ERROR = None
            return True
        except Exception:
            time.sleep(2)

    ZAP_DAEMON_LAST_ERROR = "ZAP daemon did not become ready in time"
    logger.error(ZAP_DAEMON_LAST_ERROR)
    return False

def run_zap_scan(url, timeout=1800):
    """
    Runs an OWASP ZAP scan via the API and returns report-like JSON.

    The scan weight is controlled by zap_scan_mode:
      - "passive" (default): spider (bounded) + passive analysis only. Much lighter,
        suitable for low-resource hosts like a Raspberry Pi. Finds misconfigurations,
        missing headers, information leaks, etc., but does not attack the target.
      - "spider": spider only (whatever passive alerts are produced during crawl).
      - "active": spider + full active scan (the heavy mode; attacks every endpoint).
    The spider is bounded by zap_spider_max_children, and each phase has its own
    time budget so a single target cannot run away with the host's resources.
    """
    settings = get_zap_api_settings()
    zap_base = settings["base"]
    zap_key = settings["key"]
    api_timeout = min(timeout, settings["timeout"])

    mode = _cfg_str("zap_scan_mode", "passive").lower().strip()
    if mode not in ("passive", "spider", "active"):
        mode = "passive"
    spider_max_children = _cfg_int("zap_spider_max_children", 10)
    spider_deadline_sec = _cfg_int("zap_spider_timeout_sec", min(api_timeout, 300))
    passive_deadline_sec = _cfg_int("zap_passive_timeout_sec", 120)
    ascan_deadline_sec = _cfg_int("zap_ascan_timeout_sec", api_timeout)

    logger.info(f"Running OWASP ZAP scan against {url} (mode={mode}, spider_max_children={spider_max_children})")

    if not ensure_zap_daemon(settings):
        reason = ZAP_DAEMON_LAST_ERROR or f"ZAP API unavailable at {zap_base}"
        return create_minimal_report(url, reason)

    params = {}
    if zap_key:
        params["apikey"] = zap_key

    try:
        # ZAP daemon is single-session oriented; serialize scans to avoid cross-thread session conflicts.
        with ZAP_API_SCAN_LOCK:
            session_name = f"siaas_webscan_{uuid.uuid4().hex[:12]}"
            zap_api_get(
                zap_base, "core", "action/newSession",
                dict(params, **{"name": session_name, "overwrite": "true"}),
                timeout=30
            )

            # Spider (bounded by maxChildren and a time budget)
            spider_resp = zap_api_get(
                zap_base, "spider", "action/scan",
                dict(params, **{"url": url, "maxChildren": str(spider_max_children), "recurse": "true"}),
                timeout=30
            )
            spider_id = spider_resp.get("scan")
            if spider_id is not None:
                spider_deadline = time.time() + spider_deadline_sec
                while time.time() < spider_deadline:
                    status = zap_api_get(
                        zap_base, "spider", "view/status",
                        dict(params, **{"scanId": spider_id}),
                        timeout=30
                    ).get("status", "0")
                    if str(status) == "100":
                        break
                    time.sleep(2)
                else:
                    logger.warning(f"ZAP spider time budget reached for {url}; stopping spider.")
                    try:
                        zap_api_get(zap_base, "spider", "action/stop", dict(params, **{"scanId": spider_id}), timeout=30)
                    except Exception:
                        pass

            if mode in ("passive", "spider"):
                # Let the passive scanner drain its queue, then collect alerts. No attacks.
                passive_deadline = time.time() + passive_deadline_sec
                while time.time() < passive_deadline:
                    try:
                        records = zap_api_get(
                            zap_base, "pscan", "view/recordsToScan", params, timeout=30
                        ).get("recordsToScan", "0")
                    except Exception:
                        break
                    if str(records) == "0":
                        break
                    time.sleep(2)
            else:
                # Active scan: spider + attack each endpoint, bounded by a time budget.
                ascan_resp = zap_api_get(
                    zap_base, "ascan", "action/scan",
                    dict(params, **{"url": url, "recurse": "true", "inScopeOnly": "false"}),
                    timeout=30
                )
                ascan_id = ascan_resp.get("scan")
                if ascan_id is not None:
                    ascan_deadline = time.time() + ascan_deadline_sec
                    while time.time() < ascan_deadline:
                        status = zap_api_get(
                            zap_base, "ascan", "view/status",
                            dict(params, **{"scanId": ascan_id}),
                            timeout=30
                        ).get("status", "0")
                        if str(status) == "100":
                            break
                        time.sleep(3)
                    else:
                        logger.warning(f"ZAP active scan time budget reached for {url}; stopping scan.")
                        try:
                            zap_api_get(zap_base, "ascan", "action/stop", dict(params, **{"scanId": ascan_id}), timeout=30)
                        except Exception:
                            pass

            # Collect alerts for the target base URL
            alerts = zap_api_get(
                zap_base, "core", "view/alerts",
                dict(params, **{"baseurl": url, "start": "0", "count": "9999"}),
                timeout=60
            ).get("alerts", [])

            report_alerts = []
            for a in alerts:
                report_alerts.append({
                    "pluginid": str(a.get("pluginId", "unknown")),
                    "alert": a.get("alert", "Unknown"),
                    "riskdesc": f"{a.get('risk', 'Informational')} ({a.get('risk', 'Informational')})",
                    "confidence": a.get("confidence", "Medium"),
                    "desc": a.get("description", ""),
                    "solution": a.get("solution", ""),
                    "reference": a.get("reference", ""),
                    "cweid": str(a.get("cweid", "0")),
                    "wascid": str(a.get("wascid", "0")),
                    "sourceid": "1",
                    "url": a.get("url", url)
                })

        logger.info(f"ZAP API scan completed for {url}: {len(report_alerts)} alerts")
        return {
            "@generated": siaas_aux.get_now_utc_str(),
            "@version": "2.11.1",
            "site": [{
                "@name": url,
                "@host": urlparse(url).hostname or urlparse(url).netloc,
                "@port": urlparse(url).port or (443 if url.startswith("https://") else 80),
                "alerts": report_alerts
            }]
        }

    except Exception as e:
        logger.error(f"ZAP API scan failed for {url}: {e}")
        return create_minimal_report(url, f"API scan error: {e}")


def create_minimal_report(url, reason=""):
    """
    Create a minimal report when ZAP fails
    """
    return {
        "@generated": siaas_aux.get_now_utc_str(),
        "@version": "2.11.1",
        "site": [{
            "@name": url,
            "@host": urlparse(url).netloc,
            "@port": urlparse(url).port or 80,
            "alerts": [{
                "pluginid": "99999",
                "alert": "Scan Failed",
                "riskdesc": "High (Medium)",
                "confidence": "Medium",
                "desc": f"ZAP scan could not complete: {reason}",
                "solution": "Check target accessibility and ZAP configuration",
                "reference": "",
                "cweid": "0",
                "wascid": "0",
                "sourceid": "1",
                "url": url
            }]
        }]
    }


# --------------------------------------------------
# REPORT PARSING - SIAAS COMPATIBLE FORMAT
# --------------------------------------------------

def parse_zap_report(report, url):
    """
    Parses a ZAP JSON report into SIAAS-compatible format.

    ZAP emits one alert *instance* per URL/parameter where a weakness triggers, so
    the same weakness type (plugin) can appear hundreds of times. We deduplicate by
    plugin ID into unique findings, but record how many instances each had and a few
    example URLs, so the summary count matches the detail table instead of reporting
    raw instance counts. Returns (scan_results, num_unique_findings, num_unique_high).
    """
    scan_results = {}

    if not report or "site" not in report:
        # Create empty result structure
        scan_results["zap_scan"] = {
            "response_code": 0,
            "content_length": 0,
            "num_unique": 0,
            "num_instances": 0,
            "vuln": {}
        }
        return scan_results, 0, 0

    total_instances = 0
    vuln_dict = {}

    for site in report["site"]:
        for alert in site.get("alerts", []):
            vuln_id = f"zap_{alert.get('pluginid', 'unknown')}"
            severity = _risk_to_severity(alert.get("riskdesc", ""))
            alert_url = alert.get("url", "")

            entry = vuln_dict.get(vuln_id)
            if entry is None:
                entry = {
                    "type": "vulnerability",
                    "severity": severity,
                    "description": alert.get("desc", alert.get("alert", "Unknown")),
                    "source": "OWASP ZAP",
                    "confidence": alert.get("confidence", "Medium"),
                    "reference": alert.get("reference", ""),
                    "cwe": alert.get("cweid", ""),
                    "solution": alert.get("solution", ""),
                    "instances": 0,
                    "example_urls": [],
                }
                vuln_dict[vuln_id] = entry

            entry["instances"] += 1
            # Keep the highest severity observed across this plugin's instances.
            if SEVERITY_ORDER.get(severity, 1) > SEVERITY_ORDER.get(entry["severity"], 1):
                entry["severity"] = severity
            if alert_url and alert_url not in entry["example_urls"] and len(entry["example_urls"]) < 5:
                entry["example_urls"].append(alert_url)

            total_instances += 1

    # Unique-type counts so the summary matches what the detail table shows.
    total_vulns = len(vuln_dict)
    total_exploits = sum(1 for v in vuln_dict.values() if v["severity"] == "high")

    scan_results["zap_scan"] = {
        "response_code": 200,  # Placeholder
        "content_length": 0,   # Placeholder
        "num_unique": total_vulns,
        "num_instances": total_instances,
        "vuln": vuln_dict
    }

    return scan_results, total_vulns, total_exploits




# --------------------------------------------------
# MAIN WEB SCAN LOGIC - ADAPTED FROM PORTSCANNER LOGIC
# --------------------------------------------------

def scan_web_port(target, port, protocol, timeout=1200):
    """
    Similar to scan_per_port in portscanner.py
    Receives a target host, port, protocol and scans this specific web port
    Returns a tuple with the findings dict, number of valid scripts run, number of vulnerabilities, and number of exploits found
    """
    logger.info(f"Scanning web service at {target}:{port}/{protocol} ...")
    
    scan_results_dict = {}
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0

    candidate_urls = get_candidate_urls(target, port)
    url = build_url(target, port)

    # Ensure selected URL is attempted first, while keeping fallback scheme
    ordered_urls = [url] + [u for u in candidate_urls if u != url]

    # ZAP-only scan: try all candidate URL schemes until a non-synthetic report is produced
    zap_report = None
    zap_url_used = None
    for candidate_url in ordered_urls:
        logger.info(f"Running ZAP scan for {candidate_url}")
        candidate_report = run_zap_scan(candidate_url, timeout=timeout)

        if not candidate_report:
            continue

        zap_report = candidate_report
        zap_url_used = candidate_url

        try:
            alerts = zap_report.get("site", [{}])[0].get("alerts", [])
            only_failed = len(alerts) == 1 and alerts[0].get("pluginid") == "99999"
        except Exception:
            only_failed = True

        if not only_failed:
            break

    if zap_report:
        zap_script = "zap_scan"
        zap_results, zap_vulns, zap_exploits = parse_zap_report(zap_report, zap_url_used or url)
        scan_results_dict[zap_script] = zap_results
        scan_results_dict[zap_script]["scanned_url"] = zap_url_used or url

        total_valid_scripts.add(zap_script)
        total_vulns += zap_vulns
        total_exploits += zap_exploits

    logger.info(f"Web scan ended for {target}:{port}/{protocol}: {total_vulns} vulnerabilities ({total_exploits} exploits)")

    return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)


def normalize_web_target_to_url(target):
    """
    Converts a configured web target (host or URL) to a scan URL.
    Prefers the original URL when scheme is already provided.
    """
    target = (target or "").strip()
    if not target:
        return None

    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip('/')

    # If target is only a hostname/domain/IP, probe common schemes without forcing explicit ports
    candidates = [f"https://{target}", f"http://{target}"]
    for candidate in candidates:
        if check_url_accessible(candidate):
            return candidate

    return candidates[0]


def scan_web_target_url(url, timeout=1200):
    """
    Runs ZAP scan directly against a single web target URL.
    """
    logger.info(f"Scanning configured web target URL {url} ...")

    scan_results_dict = {}
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0

    zap_report = run_zap_scan(url, timeout=timeout)
    if zap_report:
        zap_script = "zap_scan"
        zap_results, zap_vulns, zap_exploits = parse_zap_report(zap_report, url)
        scan_results_dict[zap_script] = zap_results
        scan_results_dict[zap_script]["scanned_url"] = url
        total_valid_scripts.add(zap_script)
        total_vulns += zap_vulns
        total_exploits += zap_exploits

    logger.info(f"Web scan ended for {url}: {total_vulns} vulnerabilities ({total_exploits} exploits)")
    return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)


def get_web_service_info(target, specific_ports=None):
    """
    Similar to get_system_info in portscanner.py
    Gets web service information for specific ports
    Returns a tuple with two dicts: system info, and scanned ports info
    """
    logger.info(f"Getting web service info for {target} ...")
    
    sysinfo_dict = {}
    scanned_ports = {}
    
    # Get target IP for consistency with portscanner
    try:
        scanned_ip = siaas_aux.get_all_ips_for_name(target)[0]
        sysinfo_dict["scanned_ip"] = scanned_ip
        sysinfo_dict["hostname"] = target
    except Exception as e:
        logger.warning(f"Could not resolve IP for {target}: {e}")
        sysinfo_dict["hostname"] = target
    
    # For web scanner, we need to check which ports to scan
    # Read from portscanner to get actual open ports
    try:
        portscanner_data = siaas_aux.read_from_local_file(PORT_DB)
        if target in portscanner_data:
            host_ports = portscanner_data[target].get("scanned_ports", {})
            
            # Filter only web ports
            for port_str, port_info in host_ports.items():
                port, proto = port_str.split("/")
                service = port_info.get("service", "")
                
                if is_web_service(port, proto, service):
                    # Create entry in scanned_ports similar to portscanner
                    scanned_ports[f"{port}/{proto}"] = {}
                    scanned_ports[f"{port}/{proto}"]["state"] = port_info.get("state", "unknown")
                    
                    if "service" in port_info:
                        scanned_ports[f"{port}/{proto}"]["service"] = port_info["service"]
                    
                    if "site" in port_info:
                        scanned_ports[f"{port}/{proto}"]["site"] = port_info["site"]
                    
                    if "product" in port_info:
                        scanned_ports[f"{port}/{proto}"]["product"] = port_info["product"]
                    
                    logger.info(f"Web service in {target} at {port}/{proto}: {port_info.get('service', 'unknown')}")
    
    except Exception as e:
        logger.error(f"Error reading portscanner data: {str(e)}")
    
    # If no ports from portscanner, use configured or default ports
    if not scanned_ports and specific_ports:
        for port in specific_ports.split(','):
            port = port.strip()
            if port:
                scanned_ports[f"{port}/tcp"] = {
                    "state": "unknown",
                    "service": "http"
                }
    
    if not scanned_ports:
        # Default web ports
        default_ports = ["80", "443", "8080"]
        for port in default_ports:
            scanned_ports[f"{port}/tcp"] = {
                "state": "unknown",
                "service": "http"
            }
    
    return (sysinfo_dict, scanned_ports)


def main_web_target(target="localhost"):
    """
    Main WebScanner logic (similar to main() in portscanner.py)
    Gets a specific target host, runs web scans on web ports
    """
    logger.info(f"Starting main web scan for {target}")
    
    target_info = {}
    target_info["system_info"] = {}
    target_info["scanned_ports"] = {}
    
    start_time = time.time()
    
    scan_url = normalize_web_target_to_url(target)
    if not scan_url:
        logger.error(f"Invalid web target: {target}")
        return (target, target_info)

    parsed = urlparse(scan_url)
    target_info["system_info"]["hostname"] = parsed.hostname or target
    target_info["system_info"]["scanned_url"] = scan_url
    scanned_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scanned_ports = {f"{scanned_port}/tcp": {"state": "unknown", "service": parsed.scheme}}
    
    total_ports = len(scanned_ports)
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0
    
    # Single URL scan per configured target
    port_str = list(scanned_ports.keys())[0]
    target_info["scanned_ports"][port_str] = scanned_ports[port_str]
    target_info["scanned_ports"][port_str]["scan_results"] = {}
    try:
        scan_results, scripts_port, n_vulns_port, n_exploits_port = scan_web_target_url(
            scan_url, timeout=1200
        )
        target_info["scanned_ports"][port_str]["scan_results"] = scan_results
        total_valid_scripts.update(scripts_port)
        total_vulns += n_vulns_port
        total_exploits += n_exploits_port
    except Exception as e:
        logger.error(f"Error scanning target URL {scan_url}: {e}")
    
    elapsed_time_sec = int(time.time() - start_time)
    
    logger.info(f"Web scanning ended for {target}: {total_vulns} vulnerabilities were detected ({total_exploits} confirmed exploits), across {total_ports} ports and using {len(total_valid_scripts)} valid scripts. Elapsed time: {elapsed_time_sec} seconds")
    
    # Count raw alert instances (across all URLs) separately from unique findings.
    total_instances = 0
    for scan_result in target_info["scanned_ports"][port_str]["scan_results"].values():
        if isinstance(scan_result, dict):
            total_instances += scan_result.get("zap_scan", {}).get("num_instances", 0)

    # Stats similar to portscanner
    target_info["stats"] = {}
    target_info["stats"]["num_scanned_ports"] = total_ports
    target_info["stats"]["num_valid_scripts"] = len(total_valid_scripts)
    target_info["stats"]["total_num_vulnerabilities"] = total_vulns
    target_info["stats"]["total_num_instances"] = total_instances
    target_info["stats"]["total_num_exploits"] = total_exploits
    target_info["stats"]["time_taken_sec"] = elapsed_time_sec
    target_info["last_check"] = siaas_aux.get_now_utc_str()
    
    return (target, target_info)


# --------------------------------------------------
# LOOP - USING SAME STRUCTURE AS PORTSCANNER
# --------------------------------------------------

def loop():
    """
    Main loop for web scanner - using same structure as portscanner
    """
    # Initialize database
    os.makedirs(VAR_DIR, exist_ok=True)
    siaas_aux.write_to_local_file(WEB_DB, {})
    
    while True:
        webscanner_dict = {}
        scan_results_all = {}
        all_targets_to_scan = []
        
        logger.debug("Web scanner loop running...")
        
        # Check if disabled
        disable = siaas_aux.get_config_from_configs_db(
            config_name="disable_webscanner",
            convert_to_string=True
        )
        
        if siaas_aux.validate_bool_string(disable):
            logger.warning("Web scanner disabled by configuration")
            time.sleep(60)
            continue

        # Pre-flight: ensure ZAP API/daemon is ready before scanning targets
        zap_settings = get_zap_api_settings()
        if not ensure_zap_daemon(zap_settings):
            logger.error(
                f"Skipping this web scan cycle because ZAP is unavailable: {ZAP_DAEMON_LAST_ERROR or 'Unknown error'}"
            )
            time.sleep(60)
            continue
        
        # Webscanner now scans only explicitly configured web targets
        web_targets_string = siaas_aux.get_config_from_configs_db(
            config_name="web_targets", convert_to_string=True
        )
        
        if web_targets_string:
            for target in web_targets_string.split(','):
                target = target.strip()
                if target and not target.startswith('#') and target not in all_targets_to_scan:
                    all_targets_to_scan.append(target)
        
        if not all_targets_to_scan:
            logger.warning("No web_targets configured to scan")
            time.sleep(60)
            continue
        
        logger.info(f"Scanning {len(all_targets_to_scan)} web targets")
        
        # Create parallel workers like portscanner
        try:
            max_workers = int(siaas_aux.get_config_from_configs_db(
                config_name="webscanner_max_parallel_workers", convert_to_string=True
            ) or 3)
            if max_workers < 1:
                max_workers = 3
        except:
            max_workers = 3

        # A single ZAP daemon/session backend is used, so scans are executed one-by-one for consistency.
        if max_workers != 1:
            logger.warning(
                f"webscanner_max_parallel_workers={max_workers} requested, but ZAP scans are serialized; forcing max_workers=1."
            )
            max_workers = 1
        
        logger.debug(f"Using {max_workers} worker(s)")

        # Sequential by design for deterministic behavior with a single shared ZAP backend.
        for target in all_targets_to_scan:
            try:
                logger.info(f"Starting web scan for configured target: {target}")
                result = main_web_target(target=target)
                if result:
                    target_name, target_info = result
                    scan_results_all[target_name] = target_info
                    logger.info(f"Completed scan for {target_name}")
                else:
                    logger.warning(f"No result returned for target {target}")
            except Exception as e:
                logger.error(f"Error scanning target {target}: {str(e)}")
        
        # Create webscanner dict and sort like portscanner
        try:
            webscanner_dict = siaas_aux.sort_ip_dict(scan_results_all)
            
            # Write to database
            siaas_aux.write_to_local_file(WEB_DB, webscanner_dict)
            
            logger.info(f"Saved web scanner results for {len(webscanner_dict)} hosts")
            
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
        
        # Sleep interval
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="webscanner_loop_interval_sec"
            ))
        except:
            sleep_time = 21600  # 6 hours default
        
        logger.info(f"Web scanner sleeping for {sleep_time} seconds")
        time.sleep(sleep_time)


# --------------------------------------------------
# DOCKER CHECK AND SETUP
# --------------------------------------------------

def check_docker_available():
    """
    Check if Docker is available and ZAP image is present
    """
    try:
        # Check Docker daemon
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            logger.error("Docker daemon not available")
            return False
        
        # Check if ZAP image exists
        result = subprocess.run(
            ["docker", "images", "ghcr.io/zaproxy/zaproxy:stable", "--format", "{{.Repository}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if "zaproxy" not in result.stdout:
            logger.warning("ZAP Docker image not found, attempting to pull...")
            
            # Try to pull the image
            pull_result = subprocess.run(
                ["docker", "pull", "ghcr.io/zaproxy/zaproxy:stable"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            if pull_result.returncode != 0:
                logger.error("Failed to pull ZAP Docker image")
                return False
        
        logger.info("Docker and ZAP image are available")
        return True
        
    except Exception as e:
        logger.error(f"Docker check failed: {str(e)}")
        return False


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    # Setup logging
    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=log_level
    )
    
    # Check root privileges
    if os.geteuid() != 0:
        print("You need to be root to run this module.", file=sys.stderr)
        sys.exit(1)
    
    # Run the loop
    loop()
