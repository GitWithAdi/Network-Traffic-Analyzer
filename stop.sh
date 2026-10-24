#!/usr/bin/env bash

echo "===================================================="
echo " Stopping NetPulse Services"
echo "===================================================="

sudo systemctl stop packet-sniffer.service 2>/dev/null || true
sudo systemctl stop packet-streamer.service 2>/dev/null || true

echo "[*] NetPulse services stopped."
