#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <csignal>
#include <cstring>
#include <pcap.h>
#include <pcap/sll.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

// Global settings
pcap_t* g_pcap_handle = nullptr;
int g_link_type = DLT_EN10MB;
std::string g_backend_host = "127.0.0.1";
int g_backend_port = 3000;
bool g_send_http = true;
bool g_verbose = false;
uint64_t g_backend_fail_count = 0;

// Statistics
struct HttpStats {
    uint64_t total_captured = 0;
    uint64_t streamed_to_backend = 0;
    uint64_t filtered_self_traffic = 0;
    uint64_t http_errors = 0;
} g_stats;

// Signal handler
void handle_signal(int signum) {
    (void)signum;
    if (g_pcap_handle != nullptr) {
        std::cout << "\n[!] Signal received. Stopping packet capture and streaming...\n";
        pcap_breakloop(g_pcap_handle);
    }
}

// Convert MAC address to human-readable string (XX:XX:XX:XX:XX:XX)
std::string format_mac(const uint8_t* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Map common ports to service names
std::string port_service(int port) {
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:   return "DHCP-Server";
        case 68:   return "DHCP-Client";
        case 80:   return "HTTP";
        case 123:  return "NTP";
        case 443:  return "HTTPS";
        case 3000: return "Dev/Web";
        case 5353: return "mDNS";
        case 8080: return "HTTP-Alt";
        default:   return "";
    }
}

// Helper to convert IP protocol numbers to readable names
std::string protocol_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:    return "TCP";
        case IPPROTO_UDP:    return "UDP";
        case IPPROTO_ICMP:   return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_IGMP:   return "IGMP";
        case 0:              return "HOPOPT";
        case IPPROTO_ESP:    return "ESP";
        case IPPROTO_AH:     return "AH";
        case 89:             return "OSPF";
        case 132:            return "SCTP";
        default:             return "Proto " + std::to_string(proto);
    }
}

std::string icmpv6_type_name(uint8_t type) {
    switch (type) {
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 128: return "Echo Request (ping6)";
        case 129: return "Echo Reply (ping6)";
        case 130: return "MLD Query";
        case 131: return "MLD Report";
        case 132: return "MLD Done";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 143: return "MLDv2 Report";
        default:  return "Type " + std::to_string(type);
    }
}

std::string icmp_type_name(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply (ping)";
        case 3:  return "Destination Unreachable";
        case 8:  return "Echo Request (ping)";
        case 11: return "Time Exceeded";
        default: return "Type " + std::to_string(type);
    }
}

// Escape JSON strings
std::string escape_json(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 32) {
            char buf[7];
            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<int>(c));
            out += buf;
        } else {
            out += c;
        }
    }
    return out;
}

// Send HTTP POST request to Node backend using native POSIX sockets
void post_packet_to_backend(const std::string& src_ip,
                            const std::string& dst_ip,
                            const std::string& proto,
                            uint32_t length,
                            int src_port,
                            int dst_port,
                            const std::string& mac_src,
                            const std::string& mac_dst,
                            const std::string& info) {
    if (!g_send_http) return;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        g_stats.http_errors++;
        return;
    }

    // Set 250ms send and receive timeout so sniffer loop never stalls
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_backend_port);
    if (inet_pton(AF_INET, g_backend_host.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sock);
        g_stats.http_errors++;
        return;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        g_stats.http_errors++;
        g_backend_fail_count++;
        if (g_backend_fail_count == 1) {
            std::cerr << "[-] Notice: Backend http://" << g_backend_host << ":" << g_backend_port
                      << " is currently unreachable. Packets will continue capturing in terminal.\n";
        }
        return;
    }

    g_backend_fail_count = 0;

    // Build JSON payload
    std::string json = "{";
    json += "\"srcIp\":\"" + escape_json(src_ip) + "\",";
    json += "\"dstIp\":\"" + escape_json(dst_ip) + "\",";
    json += "\"protocol\":\"" + escape_json(proto) + "\",";
    json += "\"length\":" + std::to_string(length) + ",";
    if (src_port >= 0) json += "\"srcPort\":" + std::to_string(src_port) + ",";
    if (dst_port >= 0) json += "\"dstPort\":" + std::to_string(dst_port) + ",";
    if (!mac_src.empty()) json += "\"macSrc\":\"" + escape_json(mac_src) + "\",";
    if (!mac_dst.empty()) json += "\"macDst\":\"" + escape_json(mac_dst) + "\",";
    json += "\"info\":\"" + escape_json(info) + "\"";
    json += "}";

    std::string request = "POST /api/packets HTTP/1.1\r\n"
                          "Host: " + g_backend_host + ":" + std::to_string(g_backend_port) + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(json.length()) + "\r\n"
                          "Connection: close\r\n\r\n" + json;

    ssize_t sent = send(sock, request.c_str(), request.length(), 0);
    close(sock);

    if (sent > 0) {
        g_stats.streamed_to_backend++;
    } else {
        g_stats.http_errors++;
    }
}

// Link-layer header decoding supporting Ethernet and Linux cooked modes
struct LinkLayerInfo {
    bool valid = false;
    uint16_t ether_type = 0;
    size_t l3_offset = 0;
    std::string src_mac;
    std::string dst_mac;
};

LinkLayerInfo parse_link_layer(const u_char* packet, uint32_t caplen, int link_type) {
    LinkLayerInfo info;

    if (link_type == DLT_EN10MB) { // Ethernet
        if (caplen < sizeof(struct ether_header)) return info;
        const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
        info.ether_type = ntohs(eth->ether_type);
        info.src_mac = format_mac(eth->ether_shost);
        info.dst_mac = format_mac(eth->ether_dhost);
        info.l3_offset = sizeof(struct ether_header);

        // VLAN support
        if (info.ether_type == ETHERTYPE_VLAN && caplen >= info.l3_offset + 4) {
            info.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(packet + info.l3_offset + 2));
            info.l3_offset += 4;
        }
        info.valid = true;
    }
    else if (link_type == DLT_LINUX_SLL) { // Linux cooked v1 ('any')
        if (caplen < SLL_HDR_LEN) return info;
        const struct sll_header* sll = reinterpret_cast<const struct sll_header*>(packet);
        info.ether_type = ntohs(sll->sll_protocol);
        info.src_mac = (sll->sll_halen == 6) ? format_mac(sll->sll_addr) : "cooked";
        info.dst_mac = (sll->sll_pkttype == LINUX_SLL_BROADCAST) ? "ff:ff:ff:ff:ff:ff" : "cooked";
        info.l3_offset = SLL_HDR_LEN;
        info.valid = true;
    }
    else if (link_type == DLT_LINUX_SLL2) { // Linux cooked v2
        if (caplen < SLL2_HDR_LEN) return info;
        const struct sll2_header* sll2 = reinterpret_cast<const struct sll2_header*>(packet);
        info.ether_type = ntohs(sll2->sll2_protocol);
        info.src_mac = (sll2->sll2_halen == 6) ? format_mac(sll2->sll2_addr) : "cooked";
        info.dst_mac = (sll2->sll2_pkttype == LINUX_SLL_BROADCAST) ? "ff:ff:ff:ff:ff:ff" : "cooked";
        info.l3_offset = SLL2_HDR_LEN;
        info.valid = true;
    }
    else if (link_type == DLT_NULL || link_type == DLT_LOOP) { // Loopback
        if (caplen < 4) return info;
        uint32_t family = *reinterpret_cast<const uint32_t*>(packet);
        if (family == 2) info.ether_type = ETHERTYPE_IP;
        else if (family == 10 || family == 24 || family == 28) info.ether_type = ETHERTYPE_IPV6;
        info.src_mac = "loopback";
        info.dst_mac = "loopback";
        info.l3_offset = 4;
        info.valid = true;
    }

    return info;
}

// Callback invoked by libpcap
void packet_callback(u_char* user_args, const struct pcap_pkthdr* header, const u_char* packet) {
    (void)user_args;
    g_stats.total_captured++;

    LinkLayerInfo link = parse_link_layer(packet, header->caplen, g_link_type);
    if (!link.valid) return;

    size_t l3_offset = link.l3_offset;

    // ==========================================
    // 1. IPv4 Packet Processing
    // ==========================================
    if (link.ether_type == ETHERTYPE_IP) {
        if (header->caplen < l3_offset + sizeof(struct ip)) return;
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + l3_offset);
        size_t ip_hl = ip_hdr->ip_hl * 4;
        if (ip_hl < sizeof(struct ip) || header->caplen < l3_offset + ip_hl) return;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, sizeof(src_ip)) ||
            !inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, sizeof(dst_ip))) {
            return;
        }

        uint8_t proto_num = ip_hdr->ip_p;
        std::string proto = protocol_name(proto_num);
        int src_port = -1;
        int dst_port = -1;
        size_t l4_offset = l3_offset + ip_hl;
        std::string extra_desc = "";

        if (proto_num == IPPROTO_TCP && header->caplen >= l4_offset + sizeof(struct tcphdr)) {
            const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + l4_offset);
            src_port = ntohs(tcp_hdr->th_sport);
            dst_port = ntohs(tcp_hdr->th_dport);

            std::string svc = port_service(dst_port);
            if (svc.empty()) svc = port_service(src_port);
            if (!svc.empty()) extra_desc = " (" + svc + ")";
        } else if (proto_num == IPPROTO_UDP && header->caplen >= l4_offset + sizeof(struct udphdr)) {
            const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + l4_offset);
            src_port = ntohs(udp_hdr->uh_sport);
            dst_port = ntohs(udp_hdr->uh_dport);

            std::string svc = port_service(dst_port);
            if (svc.empty()) svc = port_service(src_port);
            if (!svc.empty()) extra_desc = " (" + svc + ")";
        } else if (proto_num == IPPROTO_ICMP && header->caplen >= l4_offset + 2) {
            extra_desc = " (" + icmp_type_name(packet[l4_offset]) + ")";
        }

        // CRITICAL FILTER: Prevent feedback loop if capturing port 3000 HTTP POSTs
        if (src_port == g_backend_port || dst_port == g_backend_port) {
            g_stats.filtered_self_traffic++;
            return;
        }

        std::cout << "[#" << g_stats.total_captured << "] IPv4 (" << proto << extra_desc << ") "
                  << src_ip << (src_port >= 0 ? ":" + std::to_string(src_port) : "")
                  << " -> "
                  << dst_ip << (dst_port >= 0 ? ":" + std::to_string(dst_port) : "")
                  << " [" << header->len << "B]\n";

        std::string info = proto + extra_desc + " " + src_ip;
        if (src_port >= 0) info += ":" + std::to_string(src_port);
        info += " -> " + std::string(dst_ip);
        if (dst_port >= 0) info += ":" + std::to_string(dst_port);

        post_packet_to_backend(src_ip, dst_ip, proto, header->len, src_port, dst_port,
                               link.src_mac, link.dst_mac, info);
    }

    // ==========================================
    // 2. IPv6 Packet Processing (with Extension Header Resolution)
    // ==========================================
    else if (link.ether_type == ETHERTYPE_IPV6) {
        if (header->caplen < l3_offset + sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(packet + l3_offset);
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        if (!inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, sizeof(src_ip)) ||
            !inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, sizeof(dst_ip))) {
            return;
        }

        // Traverse extension headers to find real upper layer protocol (Resolves "Proto 0" issue)
        uint8_t next_proto = ip6->ip6_nxt;
        size_t cur_offset = l3_offset + sizeof(struct ip6_hdr);
        bool has_hopopt = false;

        while (cur_offset <= header->caplen) {
            if (next_proto == IPPROTO_HOPOPTS) {
                has_hopopt = true;
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == IPPROTO_ROUTING || next_proto == IPPROTO_DSTOPTS || next_proto == 135) {
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == IPPROTO_FRAGMENT) {
                if (header->caplen < cur_offset + 8) break;
                uint8_t nxt = packet[cur_offset];
                next_proto = nxt;
                cur_offset += 8;
            } else if (next_proto == IPPROTO_AH) {
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 2) * 4;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else {
                break;
            }
        }

        std::string proto = protocol_name(next_proto);
        int src_port = -1;
        int dst_port = -1;
        std::string extra_desc = "";

        if (next_proto == IPPROTO_TCP && header->caplen >= cur_offset + sizeof(struct tcphdr)) {
            const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + cur_offset);
            src_port = ntohs(tcp_hdr->th_sport);
            dst_port = ntohs(tcp_hdr->th_dport);
            std::string svc = port_service(dst_port);
            if (svc.empty()) svc = port_service(src_port);
            if (!svc.empty()) extra_desc = " (" + svc + ")";
        } else if (next_proto == IPPROTO_UDP && header->caplen >= cur_offset + sizeof(struct udphdr)) {
            const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + cur_offset);
            src_port = ntohs(udp_hdr->uh_sport);
            dst_port = ntohs(udp_hdr->uh_dport);
            std::string svc = port_service(dst_port);
            if (svc.empty()) svc = port_service(src_port);
            if (!svc.empty()) extra_desc = " (" + svc + ")";
        } else if (next_proto == IPPROTO_ICMPV6 && header->caplen >= cur_offset + 2) {
            extra_desc = " (" + icmpv6_type_name(packet[cur_offset]) + ")";
        }

        if (has_hopopt && extra_desc.empty()) {
            extra_desc = " [Hop-by-Hop Opts]";
        }

        // Loopback self-filtering
        if (src_port == g_backend_port || dst_port == g_backend_port) {
            g_stats.filtered_self_traffic++;
            return;
        }

        std::cout << "[#" << g_stats.total_captured << "] IPv6 (" << proto << extra_desc << ") "
                  << src_ip << (src_port >= 0 ? ":" + std::to_string(src_port) : "")
                  << " -> "
                  << dst_ip << (dst_port >= 0 ? ":" + std::to_string(dst_port) : "")
                  << " [" << header->len << "B]\n";

        std::string info = "IPv6 " + proto + extra_desc + " " + src_ip;
        if (src_port >= 0) info += ":" + std::to_string(src_port);
        info += " -> " + std::string(dst_ip);
        if (dst_port >= 0) info += ":" + std::to_string(dst_port);

        post_packet_to_backend(src_ip, dst_ip, proto, header->len, src_port, dst_port,
                               link.src_mac, link.dst_mac, info);
    }

    // ==========================================
    // 3. ARP Packet Processing
    // ==========================================
    else if (link.ether_type == ETHERTYPE_ARP) {
        if (header->caplen < l3_offset + sizeof(struct ether_arp)) return;
        const struct ether_arp* arp = reinterpret_cast<const struct ether_arp*>(packet + l3_offset);
        if (ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER && ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, arp->arp_tpa, dst_ip, sizeof(dst_ip));

            uint16_t op = ntohs(arp->ea_hdr.ar_op);
            std::string op_name = (op == ARPOP_REQUEST) ? "ARP Request" :
                                  (op == ARPOP_REPLY) ? "ARP Reply" : "ARP";

            std::cout << "[#" << g_stats.total_captured << "] " << op_name << " "
                      << src_ip << " -> " << dst_ip << " [" << header->len << "B]\n";

            std::string info = op_name + " for " + dst_ip;
            post_packet_to_backend(src_ip, dst_ip, "ARP", header->len, -1, -1,
                                   format_mac(arp->arp_sha), format_mac(arp->arp_tha), info);
        }
    }
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Real-time network packet sniffer that streams captured packets via HTTP POST to Node.js backend.\n\n"
              << "Options:\n"
              << "  -i, --interface <dev>    Network device to listen on (e.g. eth0, any, lo). Default: eth0\n"
              << "  -p, --port <port>        Node/Express backend port (default: 3000)\n"
              << "  -h, --host <host>        Node/Express backend host (default: 127.0.0.1)\n"
              << "  -f, --filter <bpf>       Additional BPF filter expression (e.g. \"tcp or udp\")\n"
              << "      --no-http            Capture and print only; disable streaming HTTP POST\n"
              << "      --help               Display this help message\n\n"
              << "Examples:\n"
              << "  " << prog << " -i eth0\n"
              << "  " << prog << " -i any -p 3000\n"
              << "  " << prog << " -i eth0 -f \"icmp or port 80\"\n";
}

int main(int argc, char* argv[]) {
    std::string interface_name = "eth0";
    std::string custom_filter = "";

    // Parse CLI arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            interface_name = argv[++i];
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            g_backend_port = std::stoi(argv[++i]);
        } else if ((arg == "-h" || arg == "--host") && i + 1 < argc) {
            g_backend_host = argv[++i];
        } else if ((arg == "-f" || arg == "--filter") && i + 1 < argc) {
            custom_filter = argv[++i];
        } else if (arg == "--no-http") {
            g_send_http = false;
        } else if (arg[0] != '-') {
            // Positional interface argument for backwards compatibility
            interface_name = arg;
        } else {
            std::cerr << "[-] Unknown option: " << arg << "\n";
            print_help(argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    g_pcap_handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (g_pcap_handle == nullptr) {
        std::cerr << "[-] Error opening device '" << interface_name << "': " << errbuf << "\n";
        std::cerr << "    Tip: Run with sudo or set capability: sudo setcap cap_net_raw,cap_net_admin=eip " << argv[0] << "\n";
        return 1;
    }

    g_link_type = pcap_datalink(g_pcap_handle);
    const char* dlt_name = pcap_datalink_val_to_name(g_link_type);
    const char* dlt_desc = pcap_datalink_val_to_description(g_link_type);

    // Build filter that excludes our backend port to eliminate self-capture loops
    std::string final_filter = "not (tcp port " + std::to_string(g_backend_port) + ")";
    if (!custom_filter.empty()) {
        final_filter = "(" + custom_filter + ") and (" + final_filter + ")";
    }

    struct bpf_program fp;
    if (pcap_compile(g_pcap_handle, &fp, final_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != -1) {
        pcap_setfilter(g_pcap_handle, &fp);
        pcap_freecode(&fp);
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "============================================================\n"
              << "[*] Sniffer HTTP Streamer Started\n"
              << "    Interface:     " << interface_name << " (" << (dlt_name ? dlt_name : "DLT") << " - " << (dlt_desc ? dlt_desc : "") << ")\n"
              << "    Backend URL:   http://" << g_backend_host << ":" << g_backend_port << "/api/packets\n"
              << "    Streaming:     " << (g_send_http ? "ENABLED" : "DISABLED (--no-http)") << "\n"
              << "    BPF Filter:    " << final_filter << "\n"
              << "[*] Press Ctrl+C to terminate.\n"
              << "============================================================\n";

    pcap_loop(g_pcap_handle, 0, packet_callback, nullptr);

    std::cout << "\n=================== Streamer Summary ===================\n"
              << "Total Captured:       " << g_stats.total_captured << "\n"
              << "Streamed to Backend:  " << g_stats.streamed_to_backend << "\n"
              << "Self-traffic Filtered:" << g_stats.filtered_self_traffic << "\n"
              << "HTTP Errors/Drops:    " << g_stats.http_errors << "\n"
              << "========================================================\n";

    pcap_close(g_pcap_handle);
    g_pcap_handle = nullptr;
    std::cout << "[*] Capture terminated cleanly.\n";
    return 0;
}
