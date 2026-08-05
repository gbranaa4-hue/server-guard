import subprocess
import sys
import time

sys.path.insert(0, r"C:\Users\gbran\OneDrive\Documents\server-guard")

from collectors.packet_capture import PacketCaptureCollector

IFACE = "vEthernet (WSL (Hyper-V firewall))"
PORT = 18082
HOST_IP = "172.17.144.1"

print(f"Starting PacketCaptureCollector on iface={IFACE!r}")
collector = PacketCaptureCollector(iface=IFACE)
time.sleep(2)

# scapy TCP flags: "" = NULL (no flags), "F" = FIN only, "FPU" = FIN+PSH+URG (XMAS)
scans = [("null_scan", ""), ("fin_scan", "F"), ("xmas_scan", "FPU")]

for name, flags in scans:
    code = (
        "from scapy.all import IP, TCP, send; "
        f"send(IP(dst='{HOST_IP}')/TCP(dport={PORT}, flags='{flags}'), verbose=0)"
    )
    print(f"Sending {name} (flags={flags!r}) ...")
    result = subprocess.run(
        ["wsl.exe", "--", "python3", "-c", code],
        capture_output=True, text=True, timeout=15,
    )
    print(f"  exit={result.returncode} stdout={result.stdout.strip()!r} stderr={result.stderr.strip()[:300]!r}")
    time.sleep(0.5)

time.sleep(1.5)
values = collector.collect()
print("collector.collect() ->", values)
collector.close()

hits = values.get("stealth_scan_hits", 0)
if hits >= 3:
    print(f"RESULT: PASS - all 3 stealth scan types detected ({hits} total hits)")
elif hits > 0:
    print(f"RESULT: PARTIAL - only {hits}/3 stealth scan hits recorded")
else:
    print("RESULT: FAIL - no stealth_scan_hits recorded")
