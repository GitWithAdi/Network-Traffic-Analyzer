#!/usr/bin/env bash
# NetPulse Services Startup Script (F1 Team 22)
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR/.run"

echo "===================================================="
echo " Starting NetPulse Services (F1 Team 22)"
echo "===================================================="

# 1. Ensure binaries are built
if [[ ! -f "$DIR/F1_Team22_sniffer" || ! -f "$DIR/F1_Team22_sniffer_http" || ! -f "$DIR/F1_Team22_dns_server" ]]; then
    if [[ ! -f "$DIR/sniffer" || ! -f "$DIR/sniffer_http" || ! -f "$DIR/dns_server" ]]; then
        echo "[*] Building C++ sniffer and DNS binaries..."
        make -C "$DIR" -f F1_Team22_Makefile
    fi
fi

# 2. Check if systemd services are installed and active
USE_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files F1_Team22_packet-streamer.service 2>/dev/null | grep -q "F1_Team22_packet-streamer"; then
    USE_SYSTEMD=true
elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files packet-streamer.service 2>/dev/null | grep -q "packet-streamer"; then
    USE_SYSTEMD=true
fi

if [ "$USE_SYSTEMD" = true ]; then
    echo "[*] Starting services via systemd..."
    SVC_STREAMER="F1_Team22_packet-streamer.service"
    SVC_DNS="F1_Team22_packet-dns.service"
    SVC_SNIFFER="F1_Team22_packet-sniffer.service"

    if ! systemctl list-unit-files "$SVC_STREAMER" 2>/dev/null | grep -q "$SVC_STREAMER"; then
        SVC_STREAMER="packet-streamer.service"
        SVC_DNS="packet-dns.service"
        SVC_SNIFFER="packet-sniffer.service"
    fi

    sudo systemctl start "$SVC_STREAMER"
    sudo systemctl start "$SVC_DNS"
    sudo systemctl start "$SVC_SNIFFER"
else
    echo "[*] Systemd service units not installed. Launching direct background processes..."
    
    # Start Node.js backend
    if [ ! -f "$DIR/.run/streamer.pid" ] || ! kill -0 "$(cat "$DIR/.run/streamer.pid" 2>/dev/null)" 2>/dev/null; then
        echo "[*] Starting packet-streamer backend (port 3000)..."
        (cd "$DIR/packet-streamer" && [ -d node_modules ] || npm install)
        nohup node "$DIR/packet-streamer/F1_Team22_server.js" > "$DIR/.run/streamer.log" 2>&1 &
        echo $! > "$DIR/.run/streamer.pid"
    fi

    # Start DNS server
    DNS_BIN="$DIR/F1_Team22_dns_server"
    [ -f "$DNS_BIN" ] || DNS_BIN="$DIR/dns_server"
    if [ ! -f "$DIR/.run/dns.pid" ] || ! kill -0 "$(cat "$DIR/.run/dns.pid" 2>/dev/null)" 2>/dev/null; then
        echo "[*] Starting DNS server (UDP port 53)..."
        nohup sudo "$DNS_BIN" -p 53 -u 8.8.8.8 --backend-host 127.0.0.1 --backend-port 3000 > "$DIR/.run/dns.log" 2>&1 &
        echo $! > "$DIR/.run/dns.pid"
    fi

    # Start packet sniffer HTTP streamer
    SNIFFER_BIN="$DIR/F1_Team22_sniffer_http"
    [ -f "$SNIFFER_BIN" ] || SNIFFER_BIN="$DIR/sniffer_http"
    if [ ! -f "$DIR/.run/sniffer.pid" ] || ! kill -0 "$(cat "$DIR/.run/sniffer.pid" 2>/dev/null)" 2>/dev/null; then
        echo "[*] Starting packet sniffer HTTP streamer (interface: any)..."
        nohup sudo "$SNIFFER_BIN" -i any -p 3000 > "$DIR/.run/sniffer.log" 2>&1 &
        echo $! > "$DIR/.run/sniffer.pid"
    fi
fi

echo ""
echo "===================================================="
echo " All NetPulse services started successfully!"
echo " Web Dashboard: http://localhost:3000"
echo " Backend API:   http://localhost:3000/api/packets"
echo " DNS Endpoint:  http://localhost:3000/api/dns"
echo " DNS Server:    UDP 0.0.0.0:53"
echo "===================================================="
