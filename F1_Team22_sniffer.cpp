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

// Global state
pcap_t* g_pcap_handle = nullptr;
int g_link_type = DLT_EN10MB;
bool g_verbose = false;
uint64_t g_max_packets = 0; // 0 = unlimited

// Statistics tracking
struct PacketStats {
    uint64_t total = 0;
    uint64_t ipv4 = 0;
    uint64_t ipv6 = 0;
    uint64_t arp = 0;
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t icmpv6 = 0;
    uint64_t other = 0;
} g_stats;

// Graceful signal handler
void handle_signal(int signum) {
    (void)signum;
    if (g_pcap_handle != nullptr) {
        std::cout << "\n[!] Signal received. Stopping packet capture...\n";
        pcap_breakloop(g_pcap_handle);
    }
}

// Format MAC address as XX:XX:XX:XX:XX:XX
std::string format_mac(const uint8_t* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Convert common ports to service names
std::string port_service(int port) {
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:   return "DHCP-Server";
        case 68:   return "DHCP-Client";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 123:  return "NTP";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 3000: return "Dev/Web";
        case 5353: return "mDNS";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        default:   return "";
    }
}

std::string format_port(int port) {
    if (port < 0) return "N/A";
    std::string svc = port_service(port);
    if (!svc.empty()) {
        return std::to_string(port) + " (" + svc + ")";
    }
    return std::to_string(port);
}

// Protocol number to human readable name
std::string protocol_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:    return "TCP";
        case IPPROTO_UDP:    return "UDP";
        case IPPROTO_ICMP:   return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_IGMP:   return "IGMP";
        case 0:              return "HOPOPT (IPv6 Hop-by-Hop)";
        case IPPROTO_ESP:    return "ESP";
        case IPPROTO_AH:     return "AH";
        case 89:             return "OSPF";
        case 132:            return "SCTP";
        default:             return "Protocol " + std::to_string(proto);
    }
}

// ICMPv6 message type names
std::string icmpv6_type_name(uint8_t type) {
    switch (type) {
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";
        case 128: return "Echo Request (ping6)";
        case 129: return "Echo Reply (ping6)";
        case 130: return "Multicast Listener Query (MLD)";
        case 131: return "Multicast Listener Report (MLD)";
        case 132: return "Multicast Listener Done (MLD)";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 137: return "Redirect Message";
        case 143: return "MLDv2 Report";
        default:  return "Type " + std::to_string(type);
    }
}

// ICMPv4 message type names
std::string icmp_type_name(uint8_t type, uint8_t code) {
    (void)code;
    switch (type) {
        case 0:  return "Echo Reply (ping)";
        case 3:  return "Destination Unreachable";
        case 5:  return "Redirect";
        case 8:  return "Echo Request (ping)";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        default: return "Type " + std::to_string(type);
    }
}

// Hex & ASCII dump for verbose mode
void print_hex_dump(const u_char* data, size_t len) {
    const size_t max_dump = 128; // Limit dump to 128 bytes
    size_t dump_len = std::min(len, max_dump);
    std::cout << "  Payload Preview (" << dump_len << " of " << len << " bytes):\n";

    for (size_t i = 0; i < dump_len; i += 16) {
        std::cout << "    " << std::hex << std::setw(4) << std::setfill('0') << i << ": ";

        // Hex bytes
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < dump_len) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(data[i + j]) << " ";
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }

        // ASCII representation
        std::cout << " |";
        for (size_t j = 0; j < 16 && (i + j) < dump_len; ++j) {
            char c = static_cast<char>(data[i + j]);
            std::cout << ((c >= 32 && c <= 126) ? c : '.');
        }
        std::cout << "|\n";
    }
    std::cout << std::dec;
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

    if (link_type == DLT_EN10MB) { // Standard Ethernet
        if (caplen < sizeof(struct ether_header)) return info;
        const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
        info.ether_type = ntohs(eth->ether_type);
        info.src_mac = format_mac(eth->ether_shost);
        info.dst_mac = format_mac(eth->ether_dhost);
        info.l3_offset = sizeof(struct ether_header);

        // Handle 802.1Q VLAN tagging
        if (info.ether_type == ETHERTYPE_VLAN && caplen >= info.l3_offset + 4) {
            info.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(packet + info.l3_offset + 2));
            info.l3_offset += 4;
        }
        info.valid = true;
    }
    else if (link_type == DLT_LINUX_SLL) { // Linux cooked capture v1 (e.g. interface 'any')
        if (caplen < SLL_HDR_LEN) return info;
        const struct sll_header* sll = reinterpret_cast<const struct sll_header*>(packet);
        info.ether_type = ntohs(sll->sll_protocol);
        info.src_mac = (sll->sll_halen == 6) ? format_mac(sll->sll_addr) : "cooked-mode";
        info.dst_mac = (sll->sll_pkttype == LINUX_SLL_BROADCAST) ? "ff:ff:ff:ff:ff:ff" : "cooked-mode";
        info.l3_offset = SLL_HDR_LEN;
        info.valid = true;
    }
    else if (link_type == DLT_LINUX_SLL2) { // Linux cooked capture v2
        if (caplen < SLL2_HDR_LEN) return info;
        const struct sll2_header* sll2 = reinterpret_cast<const struct sll2_header*>(packet);
        info.ether_type = ntohs(sll2->sll2_protocol);
        info.src_mac = (sll2->sll2_halen == 6) ? format_mac(sll2->sll2_addr) : "cooked-mode";
        info.dst_mac = (sll2->sll2_pkttype == LINUX_SLL_BROADCAST) ? "ff:ff:ff:ff:ff:ff" : "cooked-mode";
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

// Packet callback handler invoked by libpcap
void packet_callback(u_char* user_args, const struct pcap_pkthdr* header, const u_char* packet) {
    (void)user_args;
    g_stats.total++;

    LinkLayerInfo link = parse_link_layer(packet, header->caplen, g_link_type);
    if (!link.valid) return;

    size_t l3_offset = link.l3_offset;

    // ==========================================
    // 1. IPv4 Packet Processing
    // ==========================================
    if (link.ether_type == ETHERTYPE_IP) {
        g_stats.ipv4++;
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
        std::string proto_str = protocol_name(proto_num);
        size_t l4_offset = l3_offset + ip_hl;
        int src_port = -1;
        int dst_port = -1;
        std::string extra_info = "";

        if (proto_num == IPPROTO_TCP) {
            g_stats.tcp++;
            if (header->caplen >= l4_offset + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + l4_offset);
                src_port = ntohs(tcp->th_sport);
                dst_port = ntohs(tcp->th_dport);

                std::vector<std::string> flags;
                if (tcp->th_flags & TH_SYN) flags.push_back("SYN");
                if (tcp->th_flags & TH_ACK) flags.push_back("ACK");
                if (tcp->th_flags & TH_FIN) flags.push_back("FIN");
                if (tcp->th_flags & TH_RST) flags.push_back("RST");
                if (tcp->th_flags & TH_PUSH) flags.push_back("PSH");
                if (tcp->th_flags & TH_URG) flags.push_back("URG");

                if (!flags.empty()) {
                    extra_info += " [Flags: ";
                    for (size_t i = 0; i < flags.size(); ++i) {
                        extra_info += (i > 0 ? "," : "") + flags[i];
                    }
                    extra_info += "]";
                }
            }
        } else if (proto_num == IPPROTO_UDP) {
            g_stats.udp++;
            if (header->caplen >= l4_offset + sizeof(struct udphdr)) {
                const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + l4_offset);
                src_port = ntohs(udp->uh_sport);
                dst_port = ntohs(udp->uh_dport);
            }
        } else if (proto_num == IPPROTO_ICMP) {
            g_stats.icmp++;
            if (header->caplen >= l4_offset + 2) {
                uint8_t icmp_type = packet[l4_offset];
                uint8_t icmp_code = packet[l4_offset + 1];
                extra_info += " (" + icmp_type_name(icmp_type, icmp_code) + ")";
            }
        } else {
            g_stats.other++;
        }

        std::cout << "[Packet #" << g_stats.total << "] IPv4 (" << proto_str << extra_info << ")\n"
                  << "  Ethernet:       " << link.src_mac << " -> " << link.dst_mac << "\n"
                  << "  Source:         " << src_ip << (src_port >= 0 ? " : " + format_port(src_port) : "") << "\n"
                  << "  Destination:    " << dst_ip << (dst_port >= 0 ? " : " + format_port(dst_port) : "") << "\n"
                  << "  Packet Length:  " << header->len << " bytes (captured: " << header->caplen << " bytes)\n";

        if (g_verbose) {
            print_hex_dump(packet, header->caplen);
        }
        std::cout << "------------------------------------------------------------\n";
    }

    // ==========================================
    // 2. IPv6 Packet Processing (with Extension Header Resolution)
    // ==========================================
    else if (link.ether_type == ETHERTYPE_IPV6) {
        g_stats.ipv6++;
        if (header->caplen < l3_offset + sizeof(struct ip6_hdr)) return;

        const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(packet + l3_offset);
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, sizeof(src_ip)) ||
            !inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, sizeof(dst_ip))) {
            return;
        }

        // Traverse IPv6 extension headers to resolve actual upper-layer protocol
        // (Fixes "Proto 0" caused by Hop-by-Hop options IPPROTO_HOPOPTS)
        uint8_t next_proto = ip6->ip6_nxt;
        size_t cur_offset = l3_offset + sizeof(struct ip6_hdr);
        std::vector<std::string> ext_headers;

        while (cur_offset <= header->caplen) {
            if (next_proto == IPPROTO_HOPOPTS) { // 0
                ext_headers.push_back("Hop-by-Hop");
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == IPPROTO_ROUTING) { // 43
                ext_headers.push_back("Routing");
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == IPPROTO_FRAGMENT) { // 44
                ext_headers.push_back("Fragment");
                if (header->caplen < cur_offset + 8) break;
                uint8_t nxt = packet[cur_offset];
                next_proto = nxt;
                cur_offset += 8;
            } else if (next_proto == IPPROTO_DSTOPTS) { // 60
                ext_headers.push_back("DestOpts");
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == IPPROTO_AH) { // 51
                ext_headers.push_back("AH");
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 2) * 4;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else if (next_proto == 135) { // Mobility
                ext_headers.push_back("Mobility");
                if (header->caplen < cur_offset + 2) break;
                uint8_t nxt = packet[cur_offset];
                uint8_t len = packet[cur_offset + 1];
                size_t hlen = (static_cast<size_t>(len) + 1) * 8;
                if (header->caplen < cur_offset + hlen) break;
                next_proto = nxt;
                cur_offset += hlen;
            } else {
                break; // Reached upper-layer protocol (TCP, UDP, ICMPv6, etc.)
            }
        }

        std::string proto_str = protocol_name(next_proto);
        int src_port = -1;
        int dst_port = -1;
        std::string extra_info = "";

        if (next_proto == IPPROTO_TCP) {
            g_stats.tcp++;
            if (header->caplen >= cur_offset + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + cur_offset);
                src_port = ntohs(tcp->th_sport);
                dst_port = ntohs(tcp->th_dport);

                std::vector<std::string> flags;
                if (tcp->th_flags & TH_SYN) flags.push_back("SYN");
                if (tcp->th_flags & TH_ACK) flags.push_back("ACK");
                if (tcp->th_flags & TH_FIN) flags.push_back("FIN");
                if (tcp->th_flags & TH_RST) flags.push_back("RST");
                if (tcp->th_flags & TH_PUSH) flags.push_back("PSH");
                if (tcp->th_flags & TH_URG) flags.push_back("URG");

                if (!flags.empty()) {
                    extra_info += " [Flags: ";
                    for (size_t i = 0; i < flags.size(); ++i) {
                        extra_info += (i > 0 ? "," : "") + flags[i];
                    }
                    extra_info += "]";
                }
            }
        } else if (next_proto == IPPROTO_UDP) {
            g_stats.udp++;
            if (header->caplen >= cur_offset + sizeof(struct udphdr)) {
                const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + cur_offset);
                src_port = ntohs(udp->uh_sport);
                dst_port = ntohs(udp->uh_dport);
            }
        } else if (next_proto == IPPROTO_ICMPV6) {
            g_stats.icmpv6++;
            if (header->caplen >= cur_offset + 2) {
                uint8_t icmp_type = packet[cur_offset];
                extra_info += " (" + icmpv6_type_name(icmp_type) + ")";
            }
        } else {
            g_stats.other++;
        }

        if (!ext_headers.empty()) {
            extra_info += " [Ext: ";
            for (size_t i = 0; i < ext_headers.size(); ++i) {
                extra_info += (i > 0 ? "," : "") + ext_headers[i];
            }
            extra_info += "]";
        }

        std::cout << "[Packet #" << g_stats.total << "] IPv6 (" << proto_str << extra_info << ")\n"
                  << "  Ethernet:       " << link.src_mac << " -> " << link.dst_mac << "\n"
                  << "  Source:         " << src_ip << (src_port >= 0 ? " : " + format_port(src_port) : "") << "\n"
                  << "  Destination:    " << dst_ip << (dst_port >= 0 ? " : " + format_port(dst_port) : "") << "\n"
                  << "  Packet Length:  " << header->len << " bytes (captured: " << header->caplen << " bytes)\n";

        if (g_verbose) {
            print_hex_dump(packet, header->caplen);
        }
        std::cout << "------------------------------------------------------------\n";
    }

    // ==========================================
    // 3. ARP Packet Processing
    // ==========================================
    else if (link.ether_type == ETHERTYPE_ARP) {
        g_stats.arp++;
        if (header->caplen < l3_offset + sizeof(struct ether_arp)) return;

        const struct ether_arp* arp = reinterpret_cast<const struct ether_arp*>(packet + l3_offset);
        if (ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER && ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, arp->arp_tpa, dst_ip, sizeof(dst_ip));

            uint16_t op = ntohs(arp->ea_hdr.ar_op);
            std::string op_str = (op == ARPOP_REQUEST) ? "ARP Request" :
                                 (op == ARPOP_REPLY) ? "ARP Reply" : "ARP Op " + std::to_string(op);

            std::cout << "[Packet #" << g_stats.total << "] ARP (" << op_str << ")\n"
                      << "  Ethernet:       " << link.src_mac << " -> " << link.dst_mac << "\n"
                      << "  Sender IP:      " << src_ip << " (" << format_mac(arp->arp_sha) << ")\n"
                      << "  Target IP:      " << dst_ip << " (" << format_mac(arp->arp_tha) << ")\n"
                      << "  Packet Length:  " << header->len << " bytes\n";
            std::cout << "------------------------------------------------------------\n";
        }
    }

    if (g_max_packets > 0 && g_stats.total >= g_max_packets) {
        pcap_breakloop(g_pcap_handle);
    }
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -i, --interface <dev>    Network interface to listen on (e.g., eth0, lo, any). Default: eth0\n"
              << "  -f, --filter <bpf>       BPF filter expression (e.g., \"tcp\", \"port 80\", \"icmp or udp\")\n"
              << "  -c, --count <num>        Number of packets to capture before exiting (default: unlimited)\n"
              << "  -v, --verbose            Show hex and ASCII payload preview\n"
              << "  -h, --help               Display this help message\n\n"
              << "Examples:\n"
              << "  " << prog << " -i eth0\n"
              << "  " << prog << " -i any -f \"tcp port 80\"\n"
              << "  " << prog << " -i eth0 -c 20 -v\n";
}

int main(int argc, char* argv[]) {
    std::string interface_name = "eth0";
    std::string bpf_filter = "";

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            interface_name = argv[++i];
        } else if ((arg == "-f" || arg == "--filter") && i + 1 < argc) {
            bpf_filter = argv[++i];
        } else if ((arg == "-c" || arg == "--count") && i + 1 < argc) {
            g_max_packets = std::stoull(argv[++i]);
        } else if (arg == "-v" || arg == "--verbose") {
            g_verbose = true;
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

    // Open live packet capture
    g_pcap_handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (g_pcap_handle == nullptr) {
        std::cerr << "[-] Error opening device '" << interface_name << "': " << errbuf << "\n";
        std::cerr << "    Tip: Run with sudo or set capability: sudo setcap cap_net_raw,cap_net_admin=eip " << argv[0] << "\n";
        return 1;
    }

    // Inspect data link type
    g_link_type = pcap_datalink(g_pcap_handle);
    const char* dlt_name = pcap_datalink_val_to_name(g_link_type);
    const char* dlt_desc = pcap_datalink_val_to_description(g_link_type);

    if (g_link_type != DLT_EN10MB && g_link_type != DLT_LINUX_SLL &&
        g_link_type != DLT_LINUX_SLL2 && g_link_type != DLT_NULL && g_link_type != DLT_LOOP) {
        std::cerr << "[-] Warning: Unsupported datalink type " << g_link_type
                  << " (" << (dlt_name ? dlt_name : "unknown") << "). Parsing may be inaccurate.\n";
    }

    // Apply BPF filter if specified
    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(g_pcap_handle, &fp, bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[-] Error compiling BPF filter '" << bpf_filter << "': "
                      << pcap_geterr(g_pcap_handle) << "\n";
            pcap_close(g_pcap_handle);
            return 1;
        }
        if (pcap_setfilter(g_pcap_handle, &fp) == -1) {
            std::cerr << "[-] Error setting BPF filter: " << pcap_geterr(g_pcap_handle) << "\n";
            pcap_freecode(&fp);
            pcap_close(g_pcap_handle);
            return 1;
        }
        pcap_freecode(&fp);
    }

    // Register signal handlers
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "============================================================\n"
              << "[*] C++ Packet Sniffer Started\n"
              << "    Interface:     " << interface_name << " (DLT: " << (dlt_name ? dlt_name : "unknown")
              << " - " << (dlt_desc ? dlt_desc : "") << ")\n";
    if (!bpf_filter.empty()) {
        std::cout << "    BPF Filter:    " << bpf_filter << "\n";
    }
    if (g_max_packets > 0) {
        std::cout << "    Packet Limit:  " << g_max_packets << "\n";
    }
    std::cout << "    Verbose Mode:  " << (g_verbose ? "ON" : "OFF") << "\n"
              << "[*] Press Ctrl+C to stop.\n"
              << "============================================================\n";

    // Main capture loop
    pcap_loop(g_pcap_handle, 0, packet_callback, nullptr);

    // Final statistics
    std::cout << "\n=================== Capture Summary ===================\n"
              << "Total Packets:   " << g_stats.total << "\n"
              << "  - IPv4:        " << g_stats.ipv4 << "\n"
              << "  - IPv6:        " << g_stats.ipv6 << "\n"
              << "  - ARP:         " << g_stats.arp << "\n"
              << "Protocols:\n"
              << "  - TCP:         " << g_stats.tcp << "\n"
              << "  - UDP:         " << g_stats.udp << "\n"
              << "  - ICMP:        " << g_stats.icmp << "\n"
              << "  - ICMPv6:      " << g_stats.icmpv6 << "\n"
              << "  - Other:       " << g_stats.other << "\n";

    struct pcap_stat ps;
    if (pcap_stats(g_pcap_handle, &ps) == 0) {
        std::cout << "Kernel Stats:\n"
                  << "  - Received:    " << ps.ps_recv << "\n"
                  << "  - Dropped:     " << ps.ps_drop << "\n";
    }
    std::cout << "=======================================================\n";

    pcap_close(g_pcap_handle);
    g_pcap_handle = nullptr;
    std::cout << "[*] Capture closed cleanly.\n";
    return 0;
}
