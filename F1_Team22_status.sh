#!/usr/bin/env bash
# NetPulse Services Status Script (F1 Team 22)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================== NetPulse Status (F1 Team 22) ==================="

# Check systemd status if available
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files F1_Team22_packet-streamer.service 2>/dev/null | grep -q "F1_Team22_packet-streamer"; then
    echo "--- Systemd Services ---"
    sudo systemctl status F1_Team22_packet-streamer.service --no-pager 2>/dev/null || true
    echo ""
    sudo systemctl status F1_Team22_packet-dns.service --no-pager 2>/dev/null || true
    echo ""
    sudo systemctl status F1_Team22_packet-sniffer.service --no-pager 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files packet-streamer.service 2>/dev/null | grep -q "packet-streamer"; then
    echo "--- Systemd Services ---"
    sudo systemctl status packet-streamer.service --no-pager 2>/dev/null || true
    echo ""
    sudo systemctl status packet-dns.service --no-pager 2>/dev/null || true
    echo ""
    sudo systemctl status packet-sniffer.service --no-pager 2>/dev/null || true
fi

# Check PID-based processes
if [ -d "$DIR/.run" ]; then
    echo "--- Local Process PIDs ---"
    for pidfile in "$DIR/.run"/*.pid; do
        if [ -f "$pidfile" ]; then
            name="$(basename "$pidfile" .pid)"
            pid="$(cat "$pidfile" 2>/dev/null)"
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                echo "  [+] $name is running (PID: $pid)"
            else
                echo "  [-] $name is NOT running (stale PID: $pid)"
            fi
        fi
    done
fi

echo ""
echo "[*] Live Telemetry & Stats:"
curl -s http://localhost:3000/api/stats | python3 -m json.tool 2>/dev/null || echo "Backend unreachable (server not running on port 3000)"
echo "======================================================================"
