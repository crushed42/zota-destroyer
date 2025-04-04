#!/bin/bash

# Zeta Warfare Engine - Optimized Installation Script
# Uses apt for system packages whenever possible

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Update package lists
echo "[*] Updating package lists..."
apt-get update -qq

# Install Python and pip
echo "[*] Installing Python environment..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    python3-scapy \
    python3-cryptography \
    python3-ipaddress \
    python3-requests \
    python3-paramiko \
    python3-lxml \
    python3-openssl \
    python3-netifaces \
    python3-psutil \
    python3-colorama \
    python3-flask \
    python3-dnspython

# Install system tools
echo "[*] Installing security tools..."
apt-get install -y -qq \
    hping3 \
    nmap \
    hydra \
    tshark \
    dsniff \
    ettercap-text-only \
    aircrack-ng \
    reaver \
    sslstrip \
    slowhttptest \
    metasploit-framework \
    net-tools \
    iproute2 \
    macchanger \
    arping \
    hostapd \
    dnsmasq \
    responder \
    sqlmap \
    wireshark-qt \
    netcat

# Install remaining Python packages via pip
echo "[*] Installing additional Python packages via pip..."
pip3 install --quiet --upgrade pip
pip3 install --quiet \
    concurrent-log-handler \
    pycryptodome \
    pyfiglet \
    terminaltables \
    pynacl

# Install wordlists
echo "[*] Setting up wordlists..."
apt-get install -y -qq seclists
ln -s /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt /usr/share/wordlists/passwords.txt 2>/dev/null || true
ln -s /usr/share/seclists/Usernames/top-usernames-shortlist.txt /usr/share/wordlists/users.txt 2>/dev/null || true

# Clean up
echo "[*] Cleaning up..."
apt-get autoremove -y -qq
apt-get clean -qq

echo -e "\n[+] Installation complete. Core dependencies installed via apt."
echo "[!] Note: Some advanced features may require manual setup of:"
echo "    - Metasploit database (run 'msfdb init')"
echo "    - Wireless card monitor mode"
