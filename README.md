# NetPulse: Real-Time Network Packet Sniffer & Live Streaming Dashboard

A full-stack network packet capture and streaming system built with **C++ (libpcap)**, **Node.js / Express**, **Socket.io**, and a real-time web dashboard.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |            Browser Web Dashboard            |
                                      |          http://localhost:3000              |
                                      +---------------------------------------------+
                                                             ▲
                                                             | WebSocket (Socket.io)
                                                             ▼
                                      +---------------------------------------------+
                                      |          Node.js & Express Backend          |
                                      |          (port 3000, Morgan logging)        |
                                      +---------------------------------------------+
                                                             ▲
                                                             | HTTP POST /api/packets
                                                             |
+------------------------------+      +---------------------------------------------+
|        sniffer (CLI)         |      |             sniffer_http (CLI)              |
| Terminal packet analyzer     |      | Real-time HTTP streamer                     |
| libpcap promiscuous capture  |      | libpcap promiscuous capture                 |
+------------------------------+      +---------------------------------------------+
              ▲                                              ▲
              +----------------------+-----------------------+
                                     |
                       Raw Network Interfaces
                       (eth0, wlan0, lo, any)
```

---

## What Was Completed & Fixed

1. **IPv6 Hop-by-Hop / "Proto 0" Bug Resolution**:
   - **Problem**: Capturing IPv6 packets caused many packets to be misidentified as `Proto 0` / `Protocol 0`. In IPv6, Protocol 0 is `IPPROTO_HOPOPTS` (Hop-by-Hop Options), which prefixes Multicast Listener Discovery (MLD), Router Alert, and Neighbor Discovery traffic.
   - **Solution**: Built an IPv6 extension header traversal engine that walks through Hop-by-Hop (0), Routing (43), Fragment (44), Destination Options (60), Authentication Headers (51), and Mobility (135) to accurately reveal the underlying transport/payload protocol (e.g., `ICMPv6 (MLDv2 Report)`, `ICMPv6 (Neighbor Solicitation)`, `TCP`, `UDP`) and parses TCP/UDP ports.

2. **Multi-Link-Layer (DLT) Support for Linux Cooked Capture (`any`)**:
   - Added native support for `DLT_EN10MB` (standard Ethernet on `eth0`), `DLT_LINUX_SLL` (Linux cooked capture v1 on interface `any`), `DLT_LINUX_SLL2`, and `DLT_NULL`/`DLT_LOOP` (loopback).
   - Both `sniffer` and `sniffer_http` now run on any interface (`eth0`, `any`, `lo`, `wlan0`).

3. **Self-Capture Loop Prevention**:
   - Automatically installs a kernel-level BPF filter (`not (tcp port 3000)`) and enforces user-space port checks in `sniffer_http` so sending HTTP POST requests to port 3000 never triggers recursive self-capture storms.

4. **Permission & Capability Configuration**:
   - Enabled passwordless sudo in `/etc/sudoers.d/kali-nopasswd`.
   - Applied Linux capabilities `cap_net_raw,cap_net_admin=eip` to `sniffer` and `sniffer_http`. Both binaries can now be run directly by regular users without `sudo`!

5. **Enhanced Protocol & Transport Decoders**:
   - Decodes IPv4 and IPv6 packets.
   - TCP: Decodes source/destination ports, TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), and service names.
   - UDP: Decodes ports and known services (`DNS`, `DHCP`, `NTP`, `mDNS`, etc.).
   - ICMP / ICMPv6: Decodes message types (Echo Request/Reply, MLD, Neighbor Solicitations, etc.).
   - ARP: Decodes ARP Requests and Replies with sender/target IPs and MACs.

---

## Quick Start

### 1. Build the C++ Sniffers
```bash
make clean && make
```
*This compiles `sniffer` and `sniffer_http` and applies `cap_net_raw,cap_net_admin` capabilities.*

### 2. Start the Web Dashboard Backend
```bash
cd /home/kali/packet-streamer
npm start
```
*Open http://localhost:3000 in your browser to view the live dashboard.*

### 3. Stream Live Packets to Dashboard
In another terminal:
```bash
# Stream traffic from eth0:
./sniffer_http -i eth0

# Or stream traffic across all interfaces:
./sniffer_http -i any
```

### 4. Standalone CLI Packet Sniffing (Without Web Dashboard)
```bash
# Capture on eth0:
./sniffer -i eth0

# Capture with BPF filter (e.g. TCP only):
./sniffer -i eth0 -f "tcp"

# Capture 20 packets with verbose payload hex dump:
./sniffer -i eth0 -c 20 -v
```

---

## Project Structure

- `sniffer.cpp`: Standalone terminal packet sniffer with statistics, BPF filters, and verbose hex dump.
- `sniffer_http.cpp`: Real-time packet streamer that delivers captured packets via HTTP POST to the backend.
- `Makefile`: Build automation for C++ binaries with capability configuration.
- `packet-streamer/`:
  - `server.js`: Node.js Express server with Morgan logging, REST API (`/api/packets`, `/api/stats`), and Socket.io server.
  - `public/index.html`: Real-time responsive HTML dashboard with sticky header, live scrolling packet list, filters, inspect pane, and KPI metrics.
  - `test_socket.js`: Automated Socket.io integration test script.
  - `simulate_packets.py`: Packet generator for offline testing and demonstration.
