import os
import subprocess
import sys

def install_dependencies():
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "flask_socketio", "cryptography", "psutil"])

def setup_firewall():
    print("Setting up firewall rules...")
    # Inbound rule
    subprocess.call(["netsh", "advfirewall", "firewall", "add", "rule", "name=C2Server_Inbound", "dir=in", "action=allow", "protocol=TCP", "localport=443"])
    # Outbound rule
    subprocess.call(["netsh", "advfirewall", "firewall", "add", "rule", "name=C2Server_Outbound", "dir=out", "action=allow", "protocol=TCP", "remoteport=443"])

def create_service():
    print("Creating Windows service...")
    service_script = '''
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os

class C2ServerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "C2ServerService"
    _svc_display_name_ = "C2 Server Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from c2_server import run_server
        run_server()

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(C2ServerService)
    '''
    
    with open("c2_server_service.py", "w") as f:
        f.write(service_script)
    
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32"])
    subprocess.call([sys.executable, "c2_server_service.py", "install"])

def main():
    print("Starting C2 Server installation for Windows...")
    install_dependencies()
    setup_firewall()
    create_service()
    print("Installation complete. You can start the service using 'net start C2ServerService'")

if __name__ == "__main__":
    main()