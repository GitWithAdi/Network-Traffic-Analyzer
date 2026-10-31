#!/usr/bin/env bash
# NetPulse Services Stop Script (F1 Team 22)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "===================================================="
echo " Stopping NetPulse Services (F1 Team 22)"
echo "===================================================="

# 1. Stop systemd services if present
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl stop F1_Team22_packet-sniffer.service 2>/dev/null || true
    sudo systemctl stop F1_Team22_packet-dns.service 2>/dev/null || true
    sudo systemctl stop F1_Team22_packet-streamer.service 2>/dev/null || true
    sudo systemctl stop packet-sniffer.service 2>/dev/null || true
    sudo systemctl stop packet-dns.service 2>/dev/null || true
    sudo systemctl stop packet-streamer.service 2>/dev/null || true
fi

# 2. Stop standalone background PIDs if present
for pidfile in "$DIR/.run"/*.pid; do
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "[*] Stopping process $PID ($(basename "$pidfile" .pid))..."
            sudo kill "$PID" 2>/dev/null || kill "$PID" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    fi
done

echo "[*] NetPulse services stopped cleanly."
