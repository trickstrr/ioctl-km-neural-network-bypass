import os
import subprocess
import sys

def install_dependencies():
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "flask_socketio", "cryptography", "psutil"])

def setup_firewall():
    print("Setting up firewall rules...")
    # Inbound rule
    subprocess.call(["sudo", "ufw", "allow", "443/tcp"])
    # Outbound rule
    subprocess.call(["sudo", "ufw", "allow", "out", "443/tcp"])
    subprocess.call(["sudo", "ufw", "enable"])

def create_systemd_service():
    print("Creating systemd service...")
    service_content = '''
[Unit]
Description=C2 Server Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/c2server/c2_server.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
    '''
    
    with open("/etc/systemd/system/c2server.service", "w") as f:
        f.write(service_content)
    
    subprocess.call(["sudo", "systemctl", "daemon-reload"])
    subprocess.call(["sudo", "systemctl", "enable", "c2server.service"])

def setup_c2_server():
    print("Setting up C2 server...")
    os.makedirs("/opt/c2server", exist_ok=True)
    # Here you would copy your actual c2_server.py file to /opt/c2server/
    # For this example, we'll create a dummy file
    with open("/opt/c2server/c2_server.py", "w") as f:
        f.write("# Your C2 server code goes here")

def main():
    print("Starting C2 Server installation for Linux...")
    install_dependencies()
    setup_firewall()
    setup_c2_server()
    create_systemd_service()
    print("Installation complete. You can start the service using 'sudo systemctl start c2server'")

if __name__ == "__main__":
    main()