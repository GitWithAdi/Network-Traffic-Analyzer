#!/usr/bin/env bash
# NetPulse Systemd Service Installer (F1 Team 22)
# Configures and registers systemd units dynamically for the current user and directory
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run this installer as root: sudo ./F1_Team22_install_services.sh"
    exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-$USER}"
NODE_BIN="$(which node || echo "/usr/bin/node")"

echo "===================================================="
echo " Installing NetPulse Services (F1 Team 22)"
echo "===================================================="
echo "[*] Project Directory: $DIR"
echo "[*] Service User:      $TARGET_USER"
echo "[*] Node Binary:       $NODE_BIN"

# 1. packet-streamer backend unit
cat <<EOF > /etc/systemd/system/F1_Team22_packet-streamer.service
[Unit]
Description=NetPulse Packet Streamer Backend (F1 Team 22)
After=network.target

[Service]
Type=simple
User=$TARGET_USER
WorkingDirectory=$DIR/packet-streamer
ExecStart=$NODE_BIN $DIR/packet-streamer/F1_Team22_server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production PORT=3000

[Install]
WantedBy=multi-user.target
EOF

# 2. packet-dns service unit
cat <<EOF > /etc/systemd/system/F1_Team22_packet-dns.service
[Unit]
Description=NetPulse C++ DNS Forwarding Server (F1 Team 22)
After=network.target F1_Team22_packet-streamer.service
Wants=F1_Team22_packet-streamer.service

[Service]
Type=simple
User=$TARGET_USER
WorkingDirectory=$DIR
ExecStart=$DIR/F1_Team22_dns_server -p 53 -u 8.8.8.8 --backend-host 127.0.0.1 --backend-port 3000
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# 3. packet-sniffer service unit
cat <<EOF > /etc/systemd/system/F1_Team22_packet-sniffer.service
[Unit]
Description=NetPulse Packet Sniffer HTTP Streamer (F1 Team 22)
After=network.target F1_Team22_packet-streamer.service
Wants=F1_Team22_packet-streamer.service

[Service]
Type=simple
User=$TARGET_USER
WorkingDirectory=$DIR
ExecStart=$DIR/F1_Team22_sniffer_http -i any -p 3000
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[+] Successfully installed and registered systemd services!"
echo "[+] You can now control them using ./F1_Team22_start.sh, ./F1_Team22_status.sh, and ./F1_Team22_stop.sh"
echo "===================================================="
