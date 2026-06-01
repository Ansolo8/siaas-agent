# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Portscanner module
# By João Pedro Seara, 2022-2024

import siaas_aux
import os
import sys
import logging
import time
import nmap3
import concurrent.futures
import pprint

logger = logging.getLogger(__name__)


def parse_raw_output_from_nmap_scan(script_name="generic", raw_data=""):
    """
    Gets the Nmap raw output and parses it
    If the data is from vulners/vulscan, it uses a specialized parser which tags exploits as well
    Otherwise, it uses a generic parser
    Returns a tuple with the findings dict, total number of vulnerabilities, and total number of exploits
    """
    out_dict = {}

    if type(script_name) is not str or type(raw_data) is not str:

        logger.error("Invalid input was provided. Not parsing nmap raw data.")
        return out_dict

    total_vulns = 0
    total_exploits = 0

    if "vulners" in script_name or "vulscan" in script_name:

        logger.debug(
            "Parsing raw data using vulners/vulscan parser for sub-script '"+str(script_name)+"' ...")

        current_section = ""
        for line in raw_data.splitlines():
            if len(line or '') > 0:
                clean_line = line.strip()
                if clean_line.endswith(":"):  # section header
                    current_section = clean_line.rstrip(":")
                    out_dict[current_section] = {}
                else:  # vulnerability within the section
                    if current_section != "":
                        total_vulns += 1
                        vuln_id = clean_line.split(maxsplit=1)[
                            0].lstrip("[").rstrip("]")
                        content_list = clean_line.split(
                            maxsplit=1)[1].split("\t")
                        # check if it's an exploit (check section name, vulnerability name, and vulnerability description contents)
                        if "exploit" in current_section.lower() or "exploit" in str(vuln_id).lower() or "exploit" in str(content_list).lower():
                            total_exploits += 1
                            content_list.append("siaas_exploit_tag")
                        out_dict[current_section][vuln_id] = content_list

    else:

        logger.debug(
            "Parsing raw nmap data using a generic parser for sub-script '"+str(script_name)+"' ...")

        out_list = []
        for line in raw_data.splitlines():
            if len(line or '') > 0:
                clean_line = line.strip()
                try:
                    formatted_clean_line = clean_line.replace(
                        "\t", " | ").strip()
                    # total_vulns+=1 # not counting raw lines as vulnerabilities as there's lots of trash in there (fingerprints, banners, etc)
                    out_list.append(formatted_clean_line)
                except:
                    logger.warning(
                        "Couldn't append line to list of results: "+str(clean_line))
        out_dict["raw_lines"] = out_list

    return (out_dict, total_vulns, total_exploits)


def scan_per_port(target, port, protocol, nmap_scripts_string=None, timeout=600):
    """"
    Receives a target host, port, protocol, and a list of nmap scripts and scans this specific port
    Returns a tuple with the findings dict, number of valid scripts run, number of vulnerabilities, and number of exploits found
    Returns an empty dict if something failed or no findings at all
    """
    logger.info("Scanning " + target +
                " at " + str(port) + "/" + protocol+" ...")

    scan_results_dict = {}
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0

    if type(nmap_scripts_string) is not str:
        logger.warning(
            "Nmap scripts string is undefined or invalid. Bypassing scan.")
        return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)

    if len(nmap_scripts_string or '') == 0:
        logger.warning(
            "Nmap scripts string is undefined or invalid. Bypassing scan.")
        return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)

    try:
        timeout = int(timeout)
    except:
        timeout = 600
        logger.warning(
            "Input timeout for port scanning is not configured or in an invalid format. Using 10 minutes by default.")

    try:
        ipv = siaas_aux.is_ipv4_or_ipv6(
            siaas_aux.get_all_ips_for_name(target)[0])
    except:
        ipv = None
    if ipv == None:
        logger.error("Can't scan "+target+" at " +
                     str(port)+"/" + protocol+"+ as it is not from a valid IP protocol.")
        return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)

    nmap_scripts_list = sorted(set(nmap_scripts_string.split(
        ',')), key=lambda x: x.casefold() if len(x or "") > 0 else "")

    for nmap_script_raw in nmap_scripts_list:

        nmap_script_uncommented = nmap_script_raw.split('#')[0]
        nmap_script = nmap_script_uncommented.split(
            '\t')[0].split('\n')[0].strip()

        if len(nmap_script_uncommented) > 0 and len(nmap_script) == 0:
            logger.warning("Nmap script '" +
                           nmap_script_uncommented+"' is invalid. Skipped.")

        logger.debug("Now scanning using script '"+nmap_script +
                     "' for "+target+" at " + str(port)+"/" + protocol+" ...")

        nmap = nmap3.Nmap()

        if protocol == "udp":
            prot_flag = "U"
        else:
            prot_flag = "T"

        try:

            scan_results_dict[nmap_script] = {}

            #results = nmap.nmap_version_detection(target, args="-%s -p%s:%s --script %s -Pn --script-args mincvss+5.0 --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
            results = nmap.nmap_version_detection(
                target, args="-%s -p%s:%s --script %s -Pn --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
            logger.debug("Nmap raw output for vulnerability scan using script '"+nmap_script +
                         "' in "+target+" at "+str(port)+"/"+protocol+":\n"+pprint.pformat(results, sort_dicts=False))

            for t in results["task_results"]:
                if "extrainfo" in t.keys():
                    if "timed out".casefold() in t["extrainfo"].casefold():
                        raise TimeoutError(str(timeout))

            scanned_ip = None
            host_results = {}
            for k in results.keys():
                if siaas_aux.is_ipv4_or_ipv6(k):
                    host_results = results[k]
                    scanned_ip = k
                    break
            if not scanned_ip:
                raise Exception(
                    "Could not find a valid IP key in the results.")

            script_vulns = 0
            script_exploits = 0

            for d in host_results["ports"][0]["scripts"]:
                raw = ""
                if "raw" in d.keys():
                    raw = d["raw"]
                sub_script = "main"
                if "name" in d.keys():
                    sub_script = d["name"]
                scan_results_dict[nmap_script][sub_script], n_vulns, n_exploits = parse_raw_output_from_nmap_scan(
                    sub_script, raw)
                total_vulns += n_vulns
                total_exploits += n_exploits
                script_vulns += n_vulns
                script_exploits += n_exploits
                # scan_results_dict[nmap_script]["raw"]=raw

            total_valid_scripts.add(nmap_script)

        except TimeoutError as e:
            logger.warning("Nmap timed out while scanning using script '"+nmap_script+"' for " +
                           target+" at "+str(port)+"/"+protocol+": "+str(e)+" sec. Maybe it needs to be increased?")
            continue
        except LookupError as e:
            logger.warning("Nmap returned an empty reply while scanning using script '"+nmap_script +
                           "' in "+target+" at "+str(port)+"/"+protocol+". Possible timeout, or maybe the host or port are down?")
            continue
        except Exception as e:
            logger.error("Nmap threw an invalid reply while scanning using script '" +
                         nmap_script+"' in "+target+" at "+str(port)+"/"+protocol+": "+str(e))
            continue

        scan_results_dict[nmap_script]["scanned_ip"] = scanned_ip

        if script_vulns == 0:
            logger.info("Scan ended using script '" +
                        nmap_script+"' for "+target+" at "+str(port)+"/"+protocol+". No vulnerabilities found.")
        else:
            logger.info("Scan ended. "+str(script_vulns)+" vulnerabilities ("+str(script_exploits) +
                        " confirmed exploits) were found while using script '"+nmap_script + "' in "+target+" at "+str(port)+"/"+protocol+".")

    return (scan_results_dict, total_valid_scripts, total_vulns, total_exploits)


def get_system_info(target, specific_ports=None, timeout=600):
    """
    Gets a target host and an eventual list of specific ports
    Grabs OS info and the status and services running in the ports
    Returns a tuple with two dicts: OS findings, and port information findings
    """
    logger.info("Scanning " + target + " for system information ...")

    sysinfo_dict = {}
    scanned_ports = {}

    try:
        timeout = int(timeout)
    except:
        timeout = 600
        logger.warning(
            "Input timeout for system information scanning is not configured or in an invalid format. Using 10 minutes by default.")

    try:
        ipv = siaas_aux.is_ipv4_or_ipv6(
            siaas_aux.get_all_ips_for_name(target)[0])
    except:
        ipv = None
    if ipv == None:
        logger.warning("Can't get system information for " +
                       target+" as it is not from a valid IP protocol.")
        return (sysinfo_dict, scanned_ports)

    nmap = nmap3.Nmap()

    try:
        if type(specific_ports) is int:
            specific_ports = str(specific_ports)

        if len(specific_ports or '') == 0:
            results = nmap.nmap_os_detection(
                target, args="-%s -sV -Pn --host-timeout %s" % (ipv, timeout))
        else:
            logger.debug("Restricting system info scan in "+target +
                         " to the configured port interval: "+specific_ports)
            results = nmap.nmap_os_detection(
                target, args="-%s -sV -Pn -p%s --host-timeout %s" % (ipv, specific_ports, timeout))
        logger.debug("Nmap raw output for system info scan in " +
                     target+":\n"+pprint.pformat(results, sort_dicts=False))

        for t in results["task_results"]:
            if "extrainfo" in t.keys():
                if "timed out" in t["extrainfo"]:
                    raise TimeoutError(str(timeout))

        scanned_ip = None
        host_results = {}
        for k in results.keys():
            if siaas_aux.is_ipv4_or_ipv6(k):
                host_results = results[k]
                scanned_ip = k
                break
        if not scanned_ip:
            raise Exception("Could not find a valid IP key in the results.")

    except TimeoutError as e:
        logger.warning("Nmap timed out while grabbing system info for " +
                       target+": "+str(e)+" sec. Maybe it needs to be increased?")
        return (sysinfo_dict, scanned_ports)
    except LookupError as e:
        logger.warning("Nmap returned an empty reply while grabbing system info for " +
                       target+". Possible timeout, or maybe the port is down?")
        return (sysinfo_dict, scanned_ports)
    except Exception as e:
        logger.error(
            "Nmap returned an unknown error while grabbing system info for "+target+": "+str(e))
        return (sysinfo_dict, scanned_ports)

    # UDP ports
    try:
        if len(specific_ports or '') == 0:
            results_u = nmap.scan_top_ports(
                scanned_ip, args="-%s -sU --top-ports 10 -Pn --host-timeout %s" % (ipv, timeout))  # UDP is very slow when scanning ports, so let's just scan the 10 most famous ones
        else:
            logger.debug("Restricting UDP port scan in "+target +
                         " to the configured port interval: "+specific_ports)
            results_u = nmap.scan_top_ports(
                scanned_ip, args="-%s -sU -Pn -p%s --host-timeout %s" % (ipv, specific_ports, timeout))
        logger.debug("Nmap raw output for UDP system info scan in " +
                     scanned_ip+":\n"+pprint.pformat(results_u, sort_dicts=False))

        for t in results_u["task_results"]:
            if "extrainfo" in t.keys():
                if "timed out" in t["extrainfo"]:
                    raise TimeoutError(str(timeout))

        host_results["ports"] = host_results["ports"] + \
            results_u[scanned_ip]["ports"]

    except Exception as e:
        logger.error(
            "Nmap returned an error while grabbing UDP system info for "+target+": "+str(e)+". Ignoring UDP ports.")
        pass

    try:
        sysinfo_dict["hostname"] = host_results["hostname"][0]["name"]
    except:
        pass

    try:
        sysinfo_dict["mac_address"] = host_results["macaddress"]["addr"]
        sysinfo_dict["nic_vendor"] = host_results["macaddress"]["vendor"]
    except:
        pass

    try:
        sysinfo_dict["os_name"] = host_results["osmatch"][0]["name"]
        sysinfo_dict["os_family"] = host_results["osmatch"][0]["osclass"]["osfamily"]
        sysinfo_dict["os_gen"] = host_results["osmatch"][0]["osclass"]["osgen"]
        sysinfo_dict["os_vendor"] = host_results["osmatch"][0]["osclass"]["vendor"]
        sysinfo_dict["os_type"] = host_results["osmatch"][0]["osclass"]["type"]
    except:
        pass

    sysinfo_dict["scanned_ip"] = scanned_ip

    sorted_ports = sorted(
        host_results["ports"], key=lambda x: int(x["portid"]))
    for p in sorted_ports:

        # If we're scanning all ports, skip closed ones
        if len(specific_ports or '') == 0 and p["state"] == "closed":
            continue

        name = ""
        prod_name = ""
        hostname = ""

        scanned_ports[p["portid"]+"/"+p["protocol"]] = {}
        scanned_ports[p["portid"]+"/"+p["protocol"]]["state"] = p["state"]

        if "name" in p["service"].keys():
            if len(p["service"]["name"]) > 0:
                scanned_ports[p["portid"]+"/"+p["protocol"]
                              ]["service"] = p["service"]["name"]
                name = p["service"]["name"]

        if "hostname" in p["service"].keys():
            if len(p["service"]["hostname"]) > 0:
                scanned_ports[p["portid"]+"/"+p["protocol"]
                              ]["site"] = p["service"]["hostname"]

        if "product" in p["service"].keys():
            prod_name = p["service"]["product"]
            if "version" in p["service"].keys():
                prod_name += " "+p["service"]["version"]
            if "extrainfo" in p["service"].keys():
                prod_name += " (" + \
                    p["service"]["extrainfo"].lstrip('(').rstrip(')')+")"
            if len(p["service"]["product"]) > 0:
                scanned_ports[p["portid"]+"/" +
                              p["protocol"]]["product"] = prod_name

        logger.info("Service in "+target+" at " +
                    p["portid"]+"/"+p["protocol"]+": "+name)

    if len(host_results["ports"]) == 0:
        logger.info("Found no ports/services reachable for host "+target+".")

    return (sysinfo_dict, scanned_ports)


def main(target="localhost"):
    """
    Main Portscanner logic (gets a specific target host, runs Nmap scans)
    """
    timeout = 15
    target_info = {}
    target_info["system_info"] = {}
    target_info["scanned_ports"] = {}
    system_info_output = ({}, {})

    start_time = time.time()

    # Grab system information and detected ports
    system_info_output = get_system_info(
        target, specific_ports=siaas_aux.get_config_from_configs_db(config_name="target_specific_ports"), timeout=siaas_aux.get_config_from_configs_db(config_name="nmap_sysinfo_timeout_sec"))
    target_info["system_info"] = system_info_output[0]
    scanned_ports = system_info_output[1]

    total_ports = len(scanned_ports)
    total_valid_scripts = set()
    total_vulns = 0
    total_exploits = 0

    # Scanning each detected port
    for port in scanned_ports.keys():
        target_info["scanned_ports"][port] = {}
        target_info["scanned_ports"][port]["scan_results"] = {}
        target_info["scanned_ports"][port] = scanned_ports[port]
        target_info["scanned_ports"][port]["scan_results"], scripts_port, n_vulns_port, n_exploits_port = scan_per_port(target, port.split("/")[0], port.split(
            "/")[1], nmap_scripts_string=siaas_aux.get_config_from_configs_db(config_name="nmap_scripts"), timeout=siaas_aux.get_config_from_configs_db(config_name="nmap_portscan_timeout_sec"))
        total_valid_scripts.update(scripts_port)
        total_vulns += n_vulns_port
        total_exploits += n_exploits_port

    elapsed_time_sec = int(time.time() - start_time)

    logger.info("Port scanning ended for %s: %s vulnerabilities were detected (%s confirmed exploits), across %s ports and using %s valid Nmap scripts. You might have duplicated outputs if you use multiple scripts. Elapsed time: %s seconds" % (
        target, total_vulns, total_exploits, total_ports, len(total_valid_scripts), elapsed_time_sec))
    target_info["stats"] = {}
    target_info["stats"]["num_scanned_ports"] = total_ports
    target_info["stats"]["num_valid_scripts"] = len(total_valid_scripts)
    target_info["stats"]["total_num_vulnerabilities"] = total_vulns
    target_info["stats"]["total_num_exploits"] = total_exploits
    target_info["stats"]["time_taken_sec"] = elapsed_time_sec
    target_info["last_check"] = siaas_aux.get_now_utc_str()

    return (target, target_info)


def loop():
    """
    Portscanner module loop (gets neighborhood hosts found by the Neighborhood module, calls the main scanning function)
    """
    # Initializing the portscanner local DB
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
    siaas_aux.write_to_local_file(os.path.join(
        sys.path[0], 'var/portscanner.db'), {})
    os.chmod(os.path.join(sys.path[0], 'var/portscanner.db'), os.stat(
        os.path.join(sys.path[0], 'var/portscanner.db')).st_mode & ~0o007)

    while True:

        portscanner_dict = {}
        scan_results_all = {}
        all_ips_and_domains_to_scan = []

        logger.debug("Loop running ...")

        disable_portscanner = siaas_aux.get_config_from_configs_db(
            config_name="disable_portscanner", convert_to_string=True)
        if siaas_aux.validate_bool_string(disable_portscanner):
            logger.warning(
                "Portscanner is disabled as per configuration! Not running.")
            time.sleep(60)
            continue

        scan_only_manual_hosts = siaas_aux.get_config_from_configs_db(
            config_name="scan_only_manual_hosts", convert_to_string=True)
        only_manual = siaas_aux.validate_bool_string(scan_only_manual_hosts)

        neighborhood = siaas_aux.read_from_local_file(
            os.path.join(sys.path[0], 'var/neighborhood.db'))
        if len(neighborhood or '') == 0:
            logger.warning(
                "Couldn't read neighborhood data. Either it's still being populated, or no neighbors exist at the moment. Trying again ...")
            time.sleep(60)
            continue

        # Not only the IPs must be scanned, but the FQDNs manually added and the discovered domain names as well. We create a tuple with the IP/domain/FQDN and the raw IP where it belongs to
        for neighbor in neighborhood.keys():
            if only_manual and neighborhood[neighbor]["discovery_type"] != "manual":
                logger.warning("Ignoring host " + neighbor +
                               " as only manual configured hosts are being scanned, as per configuration!")
                continue
            if "manual_entries" not in neighborhood[neighbor].keys():
                all_ips_and_domains_to_scan.append(neighbor)
            else:
                for manual_entry in neighborhood[neighbor]["manual_entries"]:
                    if len(manual_entry or '') > 0:
                        if manual_entry not in all_ips_and_domains_to_scan:
                            all_ips_and_domains_to_scan.append(manual_entry)

        # Creating a pool executor and launchng parallel port scanners against the targets
        try:
            max_workers = int(siaas_aux.get_config_from_configs_db(
                config_name="portscanner_max_parallel_workers"))
            if max_workers < 1:
                raise ValueError(
                    "Max number of workers can't be less than 1.")
            logger.debug(
                "Using a fixed maximum number of parallel workers as per configuration: "+str(max_workers))
        except:
            max_workers = None
            logger.debug(
                "The number of maximum parallel port scanning workers is not configured or is invalid. Python will automatically manage this number ...")
        # with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for ip_or_domain in all_ips_and_domains_to_scan:
                futures.append(executor.submit(main, target=ip_or_domain))
            for future in concurrent.futures.as_completed(futures):
                scan_results_all[future.result()[0]] = (future.result()[1])

        # Creating portscanner dict
        portscanner_dict = siaas_aux.sort_ip_dict(scan_results_all)

        # Writing in local database
        siaas_aux.write_to_local_file(os.path.join(
            sys.path[0], 'var/portscanner.db'), portscanner_dict)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="portscanner_loop_interval_sec"))
            logger.debug("Sleeping for "+str(sleep_time) +
                         " seconds before next loop ...")
            if siaas_aux.interruptible_sleep("portscanner", sleep_time):
                logger.info("Port scanner woke up early due to a manual run trigger.")
        except:
            logger.debug(
                "The interval loop time is not configured or is invalid. Sleeping now for 1 day by default ...")
            if siaas_aux.interruptible_sleep("portscanner", 86400):
                logger.info("Port scanner woke up early due to a manual run trigger.")


if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    target = input('\nEnter target to port scan: ')

    if target == "":
        target = "localhost"

    print('\n')

    main(target)

    print('\nAll done. Bye!\n')
