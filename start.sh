#!/usr/bin/env bash
set -e

echo "===================================================="
echo " Starting NetPulse Services"
echo "===================================================="

# Ensure binaries are built
if [[ ! -f /home/kali/sniffer || ! -f /home/kali/sniffer_http || ! -f /home/kali/dns_server ]]; then
    echo "[*] Building C++ sniffer and DNS binaries..."
    make -C /home/kali
fi

# Start systemd services
echo "[*] Starting packet-streamer (Node.js backend)..."
sudo systemctl start packet-streamer.service

echo "[*] Starting packet-dns (C++ UDP DNS server)..."
sudo systemctl start packet-dns.service

echo "[*] Starting packet-sniffer (libpcap HTTP streamer)..."
sudo systemctl start packet-sniffer.service

echo ""
echo "===================================================="
echo " All services started successfully!"
echo " Web Dashboard: http://localhost:3000"
echo " Backend API:   http://localhost:3000/api/packets"
echo " DNS Endpoint:  http://localhost:3000/api/dns"
echo " DNS Server:    UDP 0.0.0.0:53"
echo "===================================================="
