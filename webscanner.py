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
import concurrent.futures  # ADICIONADO ESTE IMPORT
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

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


def build_url(host, port):
    """
    Builds a valid URL from host and port
    """
    try:
        # First try HTTPS if it's common HTTPS port
        if port in ["443", "8443"]:
            https_url = f"https://{host}:{port}" if port != "443" else f"https://{host}"
            if check_url_accessible(https_url):
                return https_url
        
        # Try HTTP
        http_url = f"http://{host}:{port}" if port != "80" else f"http://{host}"
        if check_url_accessible(http_url):
            return http_url
        
        # If neither works, return HTTP as default
        return http_url
    except:
        # Default to HTTP
        if port in ["443", "8443"]:
            return f"https://{host}:{port}" if port != "443" else f"https://{host}"
        else:
            return f"http://{host}:{port}" if port != "80" else f"http://{host}"


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
# OWASP ZAP (DOCKER) - CORRECTED VERSION
# --------------------------------------------------

def run_zap_scan(url, timeout=1800):
    """
    Runs OWASP ZAP baseline scan using Docker with correct command
    """
    logger.info(f"Running OWASP ZAP scan against {url}")
    
    # Create temporary directory for reports
    with tempfile.TemporaryDirectory() as tmpdir:
        # Generate unique filenames
        json_report = os.path.join(tmpdir, "zap_report.json")
        html_report = os.path.join(tmpdir, "zap_report.html")
        
        # CORRECTED: Use zap-baseline.sh with correct syntax
        # Also add -I flag to ignore warnings about missing alert filters
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmpdir}:/zap/wrk",
            "-u", "zap",  # Run as zap user to avoid permission issues
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t", url,
            "-J", "/zap/wrk/zap_report.json",
            "-r", "/zap/wrk/zap_report.html",
            "-I",  # Ignore warnings about missing alert filters
            "-j"   # Use JSON output format
        ]
        
        logger.debug(f"Executing ZAP command: {' '.join(cmd)}")
        
        try:
            # Run with longer timeout for ZAP
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            # Log ZAP output for debugging
            if result.stdout:
                logger.debug(f"ZAP stdout (first 500 chars): {result.stdout[:500]}")
            if result.stderr:
                logger.debug(f"ZAP stderr (first 500 chars): {result.stderr[:500]}")
            
            # Check if report was generated
            if not os.path.exists(json_report):
                logger.warning(f"ZAP report not found at {json_report}")
                
                # Try alternative location
                alt_json = os.path.join(tmpdir, "report.json")
                if os.path.exists(alt_json):
                    json_report = alt_json
                else:
                    # Try to create a minimal report from stdout
                    logger.info("Creating minimal report from ZAP output")
                    return create_minimal_report(url, result.stdout)
            
            # Read and parse the report
            try:
                with open(json_report, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    
                if not content:
                    logger.warning(f"ZAP report is empty for {url}")
                    return create_minimal_report(url, "Empty report")
                    
                report_data = json.loads(content)
                logger.info(f"ZAP scan completed for {url}")
                return report_data
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ZAP JSON for {url}: {str(e)}")
                return create_minimal_report(url, f"JSON parse error: {str(e)}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"ZAP scan timed out for {url} after {timeout}s")
            return create_minimal_report(url, "Scan timeout")
            
        except Exception as e:
            logger.error(f"ZAP scan failed for {url}: {str(e)}")
            return create_minimal_report(url, f"Scan error: {str(e)}")


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
    Parses ZAP JSON report into SIAAS-compatible format
    Returns organized scan_results dict
    """
    scan_results = {}
    
    if not report or "site" not in report:
        # Create empty result structure
        scan_results["zap_scan"] = {
            "response_code": 0,
            "content_length": 0,
            "vuln": {}
        }
        return scan_results, 0, 0
    
    total_vulns = 0
    total_exploits = 0
    vuln_dict = {}
    
    for site in report["site"]:
        for alert in site.get("alerts", []):
            vuln_id = f"zap_{alert.get('pluginid', 'unknown')}"
            
            # Determine severity
            risk = alert.get("riskdesc", "").lower()
            severity = "medium"
            if "high" in risk:
                severity = "high"
                total_exploits += 1
            elif "medium" in risk:
                severity = "medium"
            elif "low" in risk:
                severity = "low"
            elif "informational" in risk:
                severity = "info"
            
            # Create vulnerability entry
            vuln_dict[vuln_id] = {
                "type": "vulnerability",
                "severity": severity,
                "description": alert.get("desc", alert.get("alert", "Unknown")),
                "source": "OWASP ZAP",
                "confidence": alert.get("confidence", "Medium"),
                "reference": alert.get("reference", ""),
                "cwe": alert.get("cweid", ""),
                "solution": alert.get("solution", "")
            }
            
            total_vulns += 1
    
    # Organize like portscanner
    scan_results["zap_scan"] = {
        "response_code": 200,  # Placeholder
        "content_length": 0,   # Placeholder
        "vuln": vuln_dict
    }
    
    return scan_results, total_vulns, total_exploits


def run_basic_http_scan(url):
    """
    Run basic HTTP security checks as fallback
    """
    scan_results = {}
    total_vulns = 0
    
    try:
        response = requests.get(url, timeout=30, verify=False, allow_redirects=True)
        
        # Basic security checks
        vulnerabilities = []
        
        # Check security headers
        security_headers = [
            ('Content-Security-Policy', 'medium'),
            ('X-Frame-Options', 'medium'),
            ('X-Content-Type-Options', 'medium'),
            ('Strict-Transport-Security', 'high'),
        ]
        
        for header, severity in security_headers:
            if header not in response.headers:
                vulnerabilities.append({
                    'type': 'Security Header Missing',
                    'severity': severity,
                    'description': f'Missing {header} header',
                    'finding_id': f"missing_header_{header.lower().replace('-', '_')}"
                })
        
        # Information disclosure
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in info_headers:
            if header in response.headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'low',
                    'description': f'{header}: {response.headers[header]}',
                    'finding_id': f"info_{header.lower().replace('-', '_')}"
                })
        
        # Organize vulnerabilities
        vuln_dict = {}
        for idx, vuln in enumerate(vulnerabilities):
            vuln_key = vuln.get('finding_id', f"http_vuln_{idx}")
            vuln_dict[vuln_key] = {
                'type': vuln.get('type', 'vulnerability'),
                'severity': vuln.get('severity', 'medium'),
                'description': vuln.get('description', ''),
                'source': 'HTTP Basic Scan'
            }
        
        scan_results["http_basic_scan"] = {
            'response_code': response.status_code,
            'content_length': len(response.content),
            'vuln': vuln_dict
        }
        
        total_vulns = len(vulnerabilities)
        
    except Exception as e:
        logger.error(f"Basic HTTP scan failed for {url}: {str(e)}")
        scan_results["http_basic_scan"] = {
            'response_code': 0,
            'content_length': 0,
            'error': str(e)
        }
    
    return scan_results, total_vulns, 0


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
    
    url = build_url(target, port)
    
    # Scan with ZAP (similar to Nmap scripts in portscanner)
    logger.info(f"Running ZAP scan for {url}")
    zap_report = run_zap_scan(url, timeout=timeout)
    
    if zap_report:
        zap_script = "zap_scan"
        scan_results_dict[zap_script] = {}
        
        zap_results, zap_vulns, zap_exploits = parse_zap_report(zap_report, url)
        if zap_results:
            scan_results_dict[zap_script] = zap_results
            total_valid_scripts.add(zap_script)
            total_vulns += zap_vulns
            total_exploits += zap_exploits
            scan_results_dict[zap_script]["scanned_url"] = url
    
    # Also run basic HTTP scan
    logger.info(f"Running basic HTTP scan for {url}")
    http_script = "http_basic_scan"
    http_results, http_vulns, http_exploits = run_basic_http_scan(url)
    if http_results:
        scan_results_dict[http_script] = http_results
        total_valid_scripts.add(http_script)
        total_vulns += http_vulns
    
    logger.info(f"Web scan ended for {target}:{port}/{protocol}: {total_vulns} vulnerabilities ({total_exploits} exploits)")
    
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
    
    try:
        # Get web service information and detected ports
        system_info_output = get_web_service_info(
            target, specific_ports=siaas_aux.get_config_from_configs_db(
                config_name="web_target_ports", convert_to_string=True
            )
        )
        target_info["system_info"] = system_info_output[0]
        scanned_ports = system_info_output[1]
    except Exception as e:
        logger.error(f"Error getting web service info for {target}: {e}")
        scanned_ports = {}
    
    total_ports = len(scanned_ports)
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0
    
    # Scanning each detected web port
    for port_str in scanned_ports.keys():
        try:
            port, protocol = port_str.split("/")
            
            # Initialize port entry similar to portscanner
            target_info["scanned_ports"][port_str] = {}
            target_info["scanned_ports"][port_str]["scan_results"] = {}
            
            # Copy basic port info from get_web_service_info
            target_info["scanned_ports"][port_str] = scanned_ports[port_str]
            
            # Run the web scan on this port
            scan_results, scripts_port, n_vulns_port, n_exploits_port = scan_web_port(
                target, port, protocol,
                timeout=1200  # Default timeout
            )
            
            # Store scan results
            target_info["scanned_ports"][port_str]["scan_results"] = scan_results
            total_valid_scripts.update(scripts_port)
            total_vulns += n_vulns_port
            total_exploits += n_exploits_port
            
        except Exception as e:
            logger.error(f"Error scanning port {port_str} for {target}: {e}")
    
    elapsed_time_sec = int(time.time() - start_time)
    
    logger.info(f"Web scanning ended for {target}: {total_vulns} vulnerabilities were detected ({total_exploits} confirmed exploits), across {total_ports} ports and using {len(total_valid_scripts)} valid scripts. Elapsed time: {elapsed_time_sec} seconds")
    
    # Stats similar to portscanner
    target_info["stats"] = {}
    target_info["stats"]["num_scanned_ports"] = total_ports
    target_info["stats"]["num_valid_scripts"] = len(total_valid_scripts)
    target_info["stats"]["total_num_vulnerabilities"] = total_vulns
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
        
        scan_only_manual_hosts = siaas_aux.get_config_from_configs_db(
            config_name="scan_only_manual_hosts", convert_to_string=True
        )
        only_manual = siaas_aux.validate_bool_string(scan_only_manual_hosts)
        
        # Read neighborhood data like portscanner does
        try:
            neighborhood = siaas_aux.read_from_local_file(
                os.path.join(BASE_DIR, "var/neighborhood.db")
            )
            
            if not neighborhood:
                logger.warning("No neighborhood data found")
                time.sleep(60)
                continue
                
        except Exception as e:
            logger.error(f"Error reading neighborhood data: {str(e)}")
            time.sleep(60)
            continue
        
        # Get targets to scan (same logic as portscanner)
        for neighbor in neighborhood.keys():
            if only_manual and neighborhood[neighbor].get("discovery_type") != "manual":
                logger.warning(f"Ignoring host {neighbor} as only manual hosts are being scanned")
                continue
            
            if "manual_entries" not in neighborhood[neighbor]:
                all_targets_to_scan.append(neighbor)
            else:
                for manual_entry in neighborhood[neighbor]["manual_entries"]:
                    if manual_entry and manual_entry not in all_targets_to_scan:
                        all_targets_to_scan.append(manual_entry)
        
        # Also add configured web targets
        web_targets_string = siaas_aux.get_config_from_configs_db(
            config_name="web_targets", convert_to_string=True
        )
        
        if web_targets_string:
            for target in web_targets_string.split(','):
                target = target.strip()
                if target and not target.startswith('#') and target not in all_targets_to_scan:
                    all_targets_to_scan.append(target)
        
        if not all_targets_to_scan:
            logger.warning("No targets to scan")
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
        
        logger.debug(f"Using {max_workers} parallel workers")
        
        # Use ThreadPoolExecutor like portscanner
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for target in all_targets_to_scan:
                    futures.append(executor.submit(main_web_target, target=target))
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            target_name, target_info = result
                            scan_results_all[target_name] = target_info
                            logger.info(f"Completed scan for {target_name}")
                    except Exception as e:
                        logger.error(f"Error scanning target: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Error in ThreadPoolExecutor: {str(e)}")
            # Fallback to sequential scanning
            for target in all_targets_to_scan:
                try:
                    result = main_web_target(target=target)
                    if result:
                        target_name, target_info = result
                        scan_results_all[target_name] = target_info
                        logger.info(f"Completed scan for {target_name}")
                except Exception as e2:
                    logger.error(f"Error scanning target {target}: {str(e2)}")
        
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
    
    # Check Docker availability
    if not check_docker_available():
        logger.warning("Docker not available. Web scanner will use basic HTTP checks only.")
    
    # Run the loop
    loop()