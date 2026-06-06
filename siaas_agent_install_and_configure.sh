#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

cd ${SCRIPT_DIR}

# INSTALL PACKAGES
apt-get update
apt-get install -y python3 python3-pip python3-venv git nmap dmidecode ca-certificates || exit 1

# DOCKER (required for the WebScanner module — OWASP ZAP runs as a Docker container)
if ! command -v docker &>/dev/null; then
    echo "Installing Docker..."
    apt-get install -y ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    echo "Docker installed. The OWASP ZAP image (ghcr.io/zaproxy/zaproxy:stable) will be pulled automatically on first web scan."
else
    echo "Docker already installed — skipping."
fi

# METASPLOIT FRAMEWORK (required for the Metasploit correlation module)
# Installed via snap (stable, self-updating, works on Ubuntu/Debian).
# To use a different installation method see the README.
if ! command -v msfconsole &>/dev/null; then
    if command -v snap &>/dev/null; then
        echo "Installing Metasploit Framework via snap..."
        snap install metasploit-framework
        echo "Metasploit installed. Run 'msfconsole' once as the agent user to generate the module metadata cache."
    else
        echo "WARNING: snap not available. Install Metasploit Framework manually and ensure msfconsole is in PATH."
        echo "See: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
    fi
else
    echo "Metasploit already installed — skipping."
fi

# CRONTAB
cat << EOF | tee /etc/cron.daily/siaas-agent
#!/bin/bash
echo "Starting SIAAS Agent cronjob: "\$(date) > /tmp/siaas_agent_last_cronjob
${SCRIPT_DIR}/siaas_agent_refresh_nmap_scripts_repos.sh | tee -a /tmp/siaas_agent_last_cronjob
echo "Ending SIAAS Agent cronjob: "\$(date) >> /tmp/siaas_agent_last_cronjob
EOF
chmod 755 /etc/cron.daily/siaas-agent

# SERVICE CONFIGURATION
mkdir -p ssl
cp -n conf/siaas_agent.cnf.orig conf/siaas_agent.cnf
chmod o-rwx conf/siaas_agent.cnf
ln -fsT ${SCRIPT_DIR}/log /var/log/siaas-agent
cat << EOF | tee /etc/systemd/system/siaas-agent.service
[Unit]
Description=SIAAS Agent
# if SIAAS Server is installed (AIO setup), let it start first
After=siaas-server.service

[Service]
ExecStart=${SCRIPT_DIR}/siaas_agent_run.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable siaas-agent

# INITIALIZE
#sudo rm -rf ${SCRIPT_DIR}/venv
${SCRIPT_DIR}/siaas_agent_venv_setup.sh
${SCRIPT_DIR}/siaas_agent_refresh_nmap_scripts_repos.sh

echo -e "\nSIAAS Agent will be started on boot.\n\nTo start (or restart) manually right now: sudo systemctl [start/restart] siaas-agent\n"
