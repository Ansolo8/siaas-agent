# Intelligent System for Automation of Security Audits (SIAAS)
# Agent
# By João Pedro Seara, 2022-2024

import os
import sys
import logging
import time
import multiprocessing_logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
from multiprocessing import Process

app = Flask(__name__)
logger = logging.getLogger(__name__)

SIAAS_VERSION = "1.0.1"
LOG_DIR = "log"
API_PORT = 5001
SWAGGER_URL = "/docs"  # route for exposing Swagger UI
SWAGGER_JSON_URL = "/static/swagger_siaas_agent.json"
SWAGGER_APP_NAME = "SIAAS Agent"

if __name__ == "__main__":

    import siaas_aux
    import siaas_datatransfer
    import siaas_neighborhood
    import siaas_platform
    import siaas_portscanner
    import siaas_routes
    #import siaas_metasploit #metasplit added
    import webscanner #webscanner added

    print('\n')

    # No Windows can do ; - )
    if os.name != "posix":
        logger.critical(
            "\nThis program can only be run in Linux or Raspberry Pi. Exiting!\n")
        sys.exit(1)

    # Needs to be root
    if os.geteuid() != 0:
        logger.critical(
            "\nThis script must be run as root or using sudo!\n")
        sys.exit(1)

    # Create local directories
    os.makedirs(os.path.join(sys.path[0], 'conf'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'tmp'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)

    # Deleting any existing databases leftovers
    old_dbs = os.listdir(os.path.join(sys.path[0], 'var/'))
    for db in old_dbs:
        if db.endswith(".db"):
            os.remove(os.path.join(sys.path[0], 'var/'+db))

    # Initializing local databases for configurations
    siaas_aux.write_to_local_file(
        os.path.join(sys.path[0], 'var/config.db'), {})
    os.chmod(os.path.join(sys.path[0], 'var/config.db'), os.stat(
        os.path.join(sys.path[0], 'var/config.db')).st_mode & ~0o007)
    siaas_aux.write_to_local_file(os.path.join(
        sys.path[0], 'var/config_local.db'), {})
    os.chmod(os.path.join(sys.path[0], 'var/config_local.db'), os.stat(
        os.path.join(sys.path[0], 'var/config_local.db')).st_mode & ~0o007)

    # Read local configuration file and insert in local databases
    siaas_aux.write_config_db_from_conf_file(
        output=os.path.join(sys.path[0], 'var/config.db'))
    siaas_aux.write_config_db_from_conf_file(
        output=os.path.join(sys.path[0], 'var/config_local.db'))

    # Define logging level according to user config
    os.makedirs(os.path.join(sys.path[0], LOG_DIR), exist_ok=True)
    log_file = os.path.join(os.path.join(
        sys.path[0], LOG_DIR), "siaas-agent.log")
    log_level = siaas_aux.get_config_from_configs_db(config_name="log_level")
    log_max_bytes = 10240000
    log_backup_count = 3
    while len(logging.root.handlers) > 0:
        logging.root.removeHandler(logging.root.handlers[-1])
    try:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=log_max_bytes, backupCount=log_backup_count)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=eval("logging."+log_level.upper()))
    except:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=log_max_bytes, backupCount=log_backup_count)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
    multiprocessing_logging.install_mp_handler()

    # Grabbing a unique system ID before proceeding
    agent_uid = siaas_aux.get_or_create_unique_system_id()
    if agent_uid == "00000000-0000-0000-0000-000000000000":
        logger.critical(
            "Can't proceed without an unique system ID. Aborting !")
        sys.exit(1)

    print("\nSIAAS Agent v"+SIAAS_VERSION +
          " starting ["+agent_uid+"]\n\nLogging to: "+os.path.join(sys.path[0], log_file)+"\n")
    logger.info("SIAAS Agent v"+SIAAS_VERSION+" starting ["+agent_uid+"]")

    # Main logic

    platform = Process(target=siaas_platform.loop, args=(SIAAS_VERSION,))
    #neighborhood = Process(target=siaas_neighborhood.loop, args=("enp1s0",))
    neighborhood = Process(target=siaas_neighborhood.loop, args=())
    portscanner = Process(target=siaas_portscanner.loop, args=())
    datatransfer = Process(target=siaas_datatransfer.loop, args=())
    webscanner = Process(target=webscanner.loop, args=()) #added webscanner
    #metasploit = Process(target=siaas_metasploit.loop, args=()) #added metaploit

    platform.start()
    # give the platform module some seconds to grab system info
    time.sleep(10)
    datatransfer.start()
    # give the datatransfer module some seconds to grab published configurations on first run
    time.sleep(15)
    neighborhood.start()
    portscanner.start()
    webscanner.start() #added webscanner
    #metasploit.start() #added metasploit

    # give the modules some time to start before launching the local API
    time.sleep(5)
    enable_internal_api = siaas_aux.get_config_from_configs_db(
        config_name="enable_internal_api", convert_to_string=True)
    if siaas_aux.validate_bool_string(enable_internal_api):
        logger.info("Internal API is now starting on port " +
                    str(API_PORT)+" ...")
        app.register_blueprint(get_swaggerui_blueprint(SWAGGER_URL, SWAGGER_JSON_URL, config={
                               'app_name': SWAGGER_APP_NAME, 'validatorUrl': 'none'}), url_prefix=SWAGGER_URL)
        app.run(debug=True, use_reloader=False, host="0.0.0.0", port=API_PORT)

    platform.join()
    neighborhood.join()
    portscanner.join()
    webscanner.join() #webscanner added
    #metasploit.join() #metasploit added
    datatransfer.join()

sys.exit(0)
