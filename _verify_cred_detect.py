import http.server
import subprocess
import sys
import threading
import time

sys.path.insert(0, r"C:\Users\gbran\OneDrive\Documents\server-guard")

from collectors.packet_capture import PacketCaptureCollector

IFACE = "vEthernet (WSL (Hyper-V firewall))"
PORT = 18080
HOST_IP = "172.17.144.1"


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass


def run_server():
    srv = http.server.HTTPServer((HOST_IP, PORT), QuietHandler)
    srv.timeout = 15
    srv.handle_request()


server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()

print(f"Starting PacketCaptureCollector on iface={IFACE!r}")
collector = PacketCaptureCollector(iface=IFACE)
time.sleep(2)  # let the sniffer thread actually attach before traffic flows

url = f"http://{HOST_IP}:{PORT}/"
print(f"Sending one real WSL->Windows request with Basic Auth to {url}")
result = subprocess.run(
    ["wsl.exe", "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
     "-u", "testuser:testpass", url],
    capture_output=True, text=True, timeout=15,
)
print("curl exit:", result.returncode, "stdout:", result.stdout, "stderr:", result.stderr[:300])

time.sleep(1.5)
values = collector.collect()
print("collector.collect() ->", values)

collector.close()
server_thread.join(timeout=2)

hits = values.get("plaintext_credential_hits", 0)
if hits >= 1:
    print("RESULT: PASS - real cleartext credential detection fired on live WSL->Windows traffic")
else:
    print("RESULT: FAIL - no plaintext_credential_hits recorded")
