#!/usr/bin/env bash

echo "=================== NetPulse Status ==================="
sudo systemctl status packet-streamer.service --no-pager
echo ""
sudo systemctl status packet-sniffer.service --no-pager
echo ""
echo "[*] Live Stats:"
curl -s http://localhost:3000/api/stats | python3 -m json.tool 2>/dev/null || echo "Backend unreachable"
echo "======================================================="
