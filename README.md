# NetPulse: Real-Time Network Packet Sniffer & Live Streaming Dashboard

A full-stack network packet capture, DNS monitoring, and streaming system built with **C++ (libpcap & POSIX sockets)**, **Node.js / Express**, **Socket.io**, and a real-time web dashboard.

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
                                      |    Endpoints: /api/packets, /api/dns        |
                                      +---------------------------------------------+
                                                ▲                        ▲
                         HTTP POST /api/packets |                        | HTTP POST /api/dns
                                                |                        |
+------------------------------+  +--------------------------+  +--------------------------+
|        sniffer (CLI)         |  |    sniffer_http (CLI)    |  |     dns_server (UDP)     |
| Terminal packet analyzer     |  | Real-time HTTP streamer  |  | UDP Port 53 Forwarder    |
| libpcap promiscuous capture  |  | libpcap promiscuous      |  | Forwards to 8.8.8.8      |
+------------------------------+  +--------------------------+  +--------------------------+
              ▲                               ▲                                ▲
              +---------------+---------------+                                |
                              |                                                |
                 Raw Network Interfaces                               UDP DNS Queries
                 (eth0, wlan0, lo, any)                               (Port 53 Client)
```

---

## Features & Implementation Details

1. **IPv6 Hop-by-Hop / "Proto 0" Bug Resolution**:
   - **Problem**: Capturing IPv6 packets caused many packets to be misidentified as `Proto 0` / `Protocol 0`. In IPv6, Protocol 0 is `IPPROTO_HOPOPTS` (Hop-by-Hop Options), which prefixes Multicast Listener Discovery (MLD), Router Alert, and Neighbor Discovery traffic.
   - **Solution**: Built an IPv6 extension header traversal engine that walks through Hop-by-Hop (0), Routing (43), Fragment (44), Destination Options (60), Authentication Headers (51), and Mobility (135) to accurately reveal the underlying transport/payload protocol (e.g., `ICMPv6 (MLDv2 Report)`, `ICMPv6 (Neighbor Solicitation)`, `TCP`, `UDP`) and parses TCP/UDP ports.

2. **Multi-Link-Layer (DLT) Support for Linux Cooked Capture (`any`)**:
   - Added native support for `DLT_EN10MB` (standard Ethernet on `eth0`), `DLT_LINUX_SLL` (Linux cooked capture v1 on interface `any`), `DLT_LINUX_SLL2`, and `DLT_NULL`/`DLT_LOOP` (loopback).
   - Both `sniffer` and `sniffer_http` now run on any interface (`eth0`, `any`, `lo`, `wlan0`).

3. **C++ UDP DNS Forwarding Server (`dns_server`)**:
   - Binds to UDP port 53 using standard POSIX sockets (`cap_net_bind_service`).
   - Parses RFC 1035 wire-format DNS queries, extracts requested domain names, forwards queries to upstream resolvers (`8.8.8.8:53`), and relays responses back to clients.
   - Asynchronously transmits query metadata via HTTP POST to `/api/dns` for live dashboard analytics.

4. **Self-Capture Loop Prevention**:
   - Automatically installs a kernel-level BPF filter (`not (tcp port 3000)`) and enforces user-space port checks in `sniffer_http` so sending HTTP POST requests to port 3000 never triggers recursive self-capture storms.

5. **Permission & Capability Configuration**:
   - Applied Linux capabilities `cap_net_raw,cap_net_admin=eip` to `sniffer` and `sniffer_http`, and `cap_net_bind_service=+ep` to `dns_server`.
   - All binaries can run securely without full root privileges.

6. **Enhanced Protocol & Transport Decoders**:
   - Decodes IPv4 and IPv6 packets.
   - **TCP**: Decodes source/destination ports, TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), sequence numbers, and service names.
   - **UDP**: Decodes ports and known services (`DNS`, `DHCP`, `NTP`, `mDNS`, etc.).
   - **ICMP / ICMPv6**: Decodes message types (Echo Request/Reply, MLD, Neighbor Solicitations, etc.).
   - **ARP**: Decodes ARP Requests and Replies with sender/target IPs and MACs.

7. **Real-Time Web Dashboard**:
   - Responsive UI with sticky navigation header, live scrolling packet inspection table, protocol distribution charts, packet search/filtering, and real-time DNS queries monitor.

---

## Quick Start

### 1. Build the C++ Binaries
```bash
make clean && make
```
*This compiles `sniffer`, `sniffer_http`, and `dns_server`, and assigns Linux capabilities (`cap_net_raw`, `cap_net_admin`, `cap_net_bind_service`).*

### 2. Run All Services (Recommended)
You can manage the complete stack with the provided service scripts:
```bash
# Start backend, sniffer, and DNS server
./start.sh

# Check status and live stats
./status.sh

# Stop all services
./stop.sh
```
*Open http://localhost:3000 in your browser to view the live dashboard.*

---

### Manual / CLI Execution

#### Start the Web Dashboard Backend
```bash
cd packet-streamer
npm start
```

#### Stream Live Packets to Dashboard
In another terminal:
```bash
# Stream traffic across all interfaces:
./sniffer_http -i any -p 3000

# Or listen specifically on eth0:
./sniffer_http -i eth0 -p 3000
```

#### Run the DNS Forwarding Server
```bash
./dns_server -p 53 -u 8.8.8.8 --backend-host 127.0.0.1 --backend-port 3000
```

#### Standalone CLI Packet Sniffing (Without Web Dashboard)
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

- `dns_server.cpp`: UDP DNS forwarder listening on port 53, parsing domain names and streaming queries to Express backend.
- `sniffer.cpp`: Standalone terminal packet sniffer with statistics, BPF filters, and verbose hex dump.
- `sniffer_http.cpp`: Real-time packet streamer that delivers captured packets via HTTP POST to the backend.
- `Makefile`: Build automation for C++ binaries with Linux capability configuration.
- `start.sh`, `stop.sh`, `status.sh`: Lifecycle scripts for orchestrating all services.
- `systemd/`:
  - `packet-streamer.service`: Systemd unit file for Node.js backend.
  - `packet-sniffer.service`: Systemd unit file for libpcap HTTP streamer.
  - `packet-dns.service`: Systemd unit file for C++ UDP DNS server.
- `packet-streamer/`:
  - `server.js`: Node.js Express server with Morgan logging, REST APIs (`/api/packets`, `/api/dns`, `/api/stats`), and Socket.io.
  - `public/index.html`: Real-time responsive HTML dashboard with sticky header, live scrolling packet list, DNS query tab, filters, inspect pane, and KPI metrics.
  - `test_socket.js`: Automated Socket.io integration test script.
  - `simulate_packets.py`: Packet generator for offline testing and demonstration.
