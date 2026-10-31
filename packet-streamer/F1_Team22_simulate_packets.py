#!/usr/bin/env python3
"""
Simulate network packets sent to Node/Express backend at http://localhost:3000/api/packets
"""

import time
import random
import json
import urllib.request

URL = "http://localhost:3000/api/packets"

PROTOCOLS = [
    ("TCP", 80, "HTTP GET /index.html"),
    ("TCP", 443, "TLS Client Hello"),
    ("TCP", 22, "SSH Key Exchange"),
    ("DNS", 53, "DNS Query google.com (A)"),
    ("UDP", 123, "NTP Time Sync"),
    ("ICMP", None, "Echo Request (ping)"),
    ("TCP", 8080, "API Request POST /v1/telemetry"),
    ("UDP", 5353, "mDNS Multicast Query")
]

HOSTS = [
    ("192.168.1.102", "142.250.190.46"),
    ("192.168.1.102", "1.1.1.1"),
    ("192.168.1.102", "8.8.8.8"),
    ("10.0.0.15", "10.0.0.1"),
    ("172.16.0.4", "172.217.16.206"),
    ("192.168.1.55", "192.168.1.1")
]

def generate_packet():
    src, dst = random.choice(HOSTS)
    proto, port, info = random.choice(PROTOCOLS)
    length = random.randint(48, 1480)
    sport = random.randint(1024, 65530) if proto != "ICMP" else None
    
    return {
        "srcIp": src,
        "dstIp": dst,
        "protocol": proto,
        "length": length,
        "srcPort": sport,
        "dstPort": port,
        "macSrc": "00:1a:2b:3c:4d:5e",
        "macDst": "00:50:56:c0:00:08",
        "info": info
    }

def main():
    print(f"[*] Starting packet simulator -> {URL}")
    print("[*] Press Ctrl+C to stop.")
    count = 0
    try:
        while True:
            pkt = generate_packet()
            data = json.dumps(pkt).encode("utf-8")
            req = urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=1) as resp:
                    count += 1
                    print(f"[{count}] Sent {pkt['protocol']} {pkt['srcIp']} -> {pkt['dstIp']} ({pkt['length']} bytes) [Status: {resp.status}]")
            except Exception as e:
                print(f"[-] Failed to send packet: {e}")
            time.sleep(random.uniform(0.15, 0.75))
    except KeyboardInterrupt:
        print("\n[!] Simulation stopped.")

if __name__ == "__main__":
    main()
