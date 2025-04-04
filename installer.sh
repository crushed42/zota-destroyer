#!/bin/bash

# Zeta Warfare Engine - Complete Installation Script
# This installs ALL required dependencies for all attack vectors shown in the code

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Update package lists
echo "[*] Updating package lists..."
apt-get update -qq

# Install Python and pip
echo "[*] Installing Python and pip..."
apt-get install -y -qq python3 python3-pip python3-dev

# Install system dependencies
echo "[*] Installing system dependencies..."
apt-get install -y -qq \
    hping3 \
    nmap \
    hydra \
    tshark \
    dsniff \
    ettercap-text-only \
    aircrack-ng \
    reaver \
    bully \
    sslstrip \
    slowhttptest \
    metasploit-framework \
    net-tools \
    iproute2 \
    macchanger \
    curl \
    wget \
    git \
    make \
    gcc \
    libssl-dev \
    libffi-dev \
    build-essential \
    arping \
    scapy \
    hostapd \
    dnsmasq \
    isc-dhcp-server \
    beef-xss \
    responder \
    socat \
    nikto \
    sqlmap \
    openvpn \
    wireshark-qt \
    proxychains4 \
    tor \
    macof \
    tcpreplay \
    netcat \
    cryptsetup

# Install Python packages
echo "[*] Installing Python packages..."
pip3 install --quiet --upgrade pip
pip3 install --quiet \
    scapy \
    cryptography \
    ipaddress \
    concurrent-log-handler \
    requests \
    paramiko \
    beautifulsoup4 \
    lxml \
    pycryptodome \
    pyopenssl \
    netifaces \
    psutil \
    colorama \
    pyfiglet \
    terminaltables \
    pyinstaller \
    flask \
    dnspython \
    pynacl

# Install additional tools from GitHub
echo "[*] Installing additional tools from GitHub..."
git clone --quiet https://github.com/trustedsec/social-engineer-toolkit /opt/setoolkit
cd /opt/setoolkit && pip3 install -r requirements.txt >/dev/null 2>&1

git clone --quiet https://github.com/byt3bl33d3r/MITMf /opt/MITMf
cd /opt/MITMf && pip3 install -r requirements.txt >/dev/null 2>&1

git clone --quiet https://github.com/rapid7/metasploit-framework /opt/metasploit
cd /opt/metasploit && bundle install >/dev/null 2>&1

git clone --quiet https://github.com/Screetsec/TheFatRat /opt/TheFatRat
cd /opt/TheFatRat && chmod +x setup.sh && ./setup.sh >/dev/null 2>&1

# Install packit (packet injection tool)
echo "[*] Installing packit..."
git clone --quiet https://github.com/eribertomota/packit /opt/packit
cd /opt/packit && ./configure >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1

# Create wordlist directory
echo "[*] Setting up wordlists..."
mkdir -p /usr/share/wordlists
cd /usr/share/wordlists
wget -q https://github.com/danielmiessler/SecLists/archive/master.zip
unzip -q master.zip && rm master.zip
ln -s SecLists-master/Passwords/Common-Credentials/10k-most-common.txt passwords.txt
ln -s SecLists-master/Usernames/top-usernames-shortlist.txt users.txt
ln -s SecLists-master/Passwords/rockyou.txt rockyou.txt

# Setup configuration files
echo "[*] Creating configuration files..."
cat > /etc/hosts.zeta << 'EOL'
127.0.0.1 localhost
::1 localhost
# Zeta Warfare Engine DNS Poisoning Entries
192.168.1.1 www.bank.com
192.168.1.1 online.payment.site
EOL

# Clean up
echo "[*] Cleaning up..."
apt-get autoremove -y -qq
apt-get clean -qq

# Final setup
echo "[*] Final setup..."
msfdb init >/dev/null 2>&1
systemctl enable postgresql >/dev/null 2>&1
systemctl start postgresql >/dev/null 2>&1

echo -e "\n[+] Installation complete. ALL dependencies for ZetaWarfareEngine have been installed."
echo "[!] LEGAL WARNING: These tools are for authorized penetration testing and research ONLY."
echo "[*] Additional manual configuration may be required for:"
echo "    - Wireless card monitor mode"
echo "    - Metasploit database"
echo "    - Beef-XSS hook URL"
echo "    - MITMf configurations"
