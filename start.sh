#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "===================================================="
echo " Starting NetPulse Services"
echo "===================================================="

# Ensure binaries are built
if [[ ! -f "$SCRIPT_DIR/sniffer" || ! -f "$SCRIPT_DIR/sniffer_http" ]]; then
    echo "[*] Building C++ sniffer binaries..."
    make -C "$SCRIPT_DIR"
fi

# Check if systemd services are installed and active
if systemctl list-unit-files packet-streamer.service &>/dev/null; then
    echo "[*] Starting packet-streamer via systemd..."
    sudo systemctl start packet-streamer.service
    echo "[*] Starting packet-sniffer via systemd..."
    sudo systemctl start packet-sniffer.service
else
    echo "[*] Systemd service not installed. You can run manually:"
    echo "    Terminal 1: cd $SCRIPT_DIR/packet-streamer && npm start"
    echo "    Terminal 2: $SCRIPT_DIR/sniffer_http -i any -p 3000"
fi

echo ""
echo "===================================================="
echo " NetPulse is ready!"
echo " Web Dashboard: http://localhost:3000"
echo " Backend API:   http://localhost:3000/api/packets"
echo "===================================================="
