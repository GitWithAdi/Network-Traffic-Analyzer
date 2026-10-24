#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Global server socket handle for graceful shutdown
int g_server_fd = -1;
std::atomic<bool> g_running(true);
std::string g_upstream_dns = "8.8.8.8";
int g_upstream_port = 53;
std::string g_backend_host = "127.0.0.1";
int g_backend_port = 3000;
int g_listen_port = 53;

// Signal handler for Ctrl+C (SIGINT) and SIGTERM
void handle_signal(int signum) {
    (void)signum;
    std::cout << "\n[!] Signal received. Shutting down DNS server...\n";
    g_running = false;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

// Map DNS Query Type ID to human-readable string
std::string qtype_to_string(uint16_t qtype) {
    switch (qtype) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 255: return "ANY";
        default:  return "TYPE" + std::to_string(qtype);
    }
}

// Structure representing parsed DNS question
struct DnsQuestion {
    std::string domain;
    uint16_t qtype = 0;
    std::string qtype_name = "A";
    bool valid = false;
};

// Parse domain name from RFC 1035 binary DNS query payload
DnsQuestion parse_dns_query(const uint8_t* buffer, size_t length) {
    DnsQuestion result;

    // Standard DNS Header is 12 bytes
    if (length < 12) return result;

    // Check Question Count (QDCOUNT at offset 4-5)
    uint16_t qdcount = (static_cast<uint16_t>(buffer[4]) << 8) | buffer[5];
    if (qdcount == 0) return result;

    // Question section begins right after 12-byte header
    size_t offset = 12;
    std::string domain = "";

    while (offset < length) {
        uint8_t label_len = buffer[offset++];
        if (label_len == 0) {
            // Null byte terminates QNAME
            break;
        }

        // Check for DNS pointer compression (top 2 bits set)
        if ((label_len & 0xC0) == 0xC0) {
            if (offset >= length) return result;
            offset++; // Skip second byte of pointer
            break;
        }

        // Validate label length against remaining buffer
        if (offset + label_len > length) {
            return result; // Malformed packet
        }

        if (!domain.empty()) {
            domain += ".";
        }

        for (size_t i = 0; i < label_len; ++i) {
            domain += static_cast<char>(buffer[offset + i]);
        }
        offset += label_len;
    }

    // Extract QTYPE (2 bytes) following QNAME
    if (offset + 2 <= length) {
        result.qtype = (static_cast<uint16_t>(buffer[offset]) << 8) | buffer[offset + 1];
        result.qtype_name = qtype_to_string(result.qtype);
    }

    result.domain = domain;
    result.valid = !domain.empty();
    return result;
}

// Escape JSON characters
std::string escape_json(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

// Send HTTP POST request to Express backend at http://127.0.0.1:3000/api/dns
void post_dns_to_backend(const std::string& domain,
                         const std::string& client_ip,
                         const std::string& query_type) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    // 500ms timeout so DNS forwarding never stalls if web backend is busy
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_backend_port);
    if (inet_pton(AF_INET, g_backend_host.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return;
    }

    std::string json = "{"
                       "\"domain\":\"" + escape_json(domain) + "\","
                       "\"clientIp\":\"" + escape_json(client_ip) + "\","
                       "\"queryType\":\"" + escape_json(query_type) + "\""
                       "}";

    std::string request = "POST /api/dns HTTP/1.1\r\n"
                          "Host: " + g_backend_host + ":" + std::to_string(g_backend_port) + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(json.length()) + "\r\n"
                          "Connection: close\r\n\r\n" + json;

    send(sock, request.c_str(), request.length(), 0);
    close(sock);
}

// Handle an incoming DNS query asynchronously
void process_query(int server_fd,
                   struct sockaddr_in client_addr,
                   socklen_t client_len,
                   std::vector<uint8_t> query_payload) {
    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    // 1. Parse domain name from the binary query
    DnsQuestion q = parse_dns_query(query_payload.data(), query_payload.size());

    if (q.valid) {
        std::cout << "[+] DNS Query from " << client_ip << ":" << client_port
                  << " -> " << q.domain << " (" << q.qtype_name << ")\n";

        // 2. Notify Express backend via HTTP POST
        post_dns_to_backend(q.domain, client_ip, q.qtype_name);
    } else {
        std::cout << "[?] Incoming DNS packet from " << client_ip << ":" << client_port
                  << " (" << query_payload.size() << " bytes)\n";
    }

    // 3. Forward request to upstream Google DNS (8.8.8.8:53)
    int forward_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (forward_sock < 0) {
        std::cerr << "[-] Error creating forward socket\n";
        return;
    }

    // Set 3-second timeout for upstream response
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(forward_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in upstream_addr;
    std::memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(g_upstream_port);
    inet_pton(AF_INET, g_upstream_dns.c_str(), &upstream_addr.sin_addr);

    ssize_t sent_bytes = sendto(forward_sock, query_payload.data(), query_payload.size(), 0,
                                (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));

    if (sent_bytes <= 0) {
        std::cerr << "[-] Failed to forward query to " << g_upstream_dns << "\n";
        close(forward_sock);
        return;
    }

    // 4. Receive answer from Google DNS
    uint8_t resp_buffer[4096];
    struct sockaddr_in resp_addr;
    socklen_t resp_len = sizeof(resp_addr);

    ssize_t resp_bytes = recvfrom(forward_sock, resp_buffer, sizeof(resp_buffer), 0,
                                  (struct sockaddr*)&resp_addr, &resp_len);

    if (resp_bytes > 0) {
        // 5. Forward response back to the original client
        sendto(server_fd, resp_buffer, resp_bytes, 0,
               (struct sockaddr*)&client_addr, client_len);

        if (q.valid) {
            std::cout << "    [<-] Relayed response (" << resp_bytes << " bytes) for '"
                      << q.domain << "' back to " << client_ip << ":" << client_port << "\n";
        }
    } else {
        std::cerr << "[-] No response from " << g_upstream_dns << " for " << q.domain << "\n";
    }

    close(forward_sock);
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "C++ UDP DNS Forwarding Server\n"
              << "Binds to port 53, extracts requested domain names, forwards to 8.8.8.8,\n"
              << "relays response to client, and reports queries to Express backend via HTTP POST.\n\n"
              << "Options:\n"
              << "  -p, --port <port>         Local UDP port to bind (default: 53)\n"
              << "  -u, --upstream <ip>       Upstream DNS server IP (default: 8.8.8.8)\n"
              << "      --upstream-port <p>   Upstream DNS port (default: 53)\n"
              << "      --backend-host <host> Express backend host (default: 127.0.0.1)\n"
              << "      --backend-port <port> Express backend port (default: 3000)\n"
              << "  -h, --help                Show this help message\n\n"
              << "Note: Binding to port 53 requires root privileges or CAP_NET_BIND_SERVICE capability.\n";
}

int main(int argc, char* argv[]) {
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            g_listen_port = std::stoi(argv[++i]);
        } else if ((arg == "-u" || arg == "--upstream") && i + 1 < argc) {
            g_upstream_dns = argv[++i];
        } else if (arg == "--upstream-port" && i + 1 < argc) {
            g_upstream_port = std::stoi(argv[++i]);
        } else if (arg == "--backend-host" && i + 1 < argc) {
            g_backend_host = argv[++i];
        } else if (arg == "--backend-port" && i + 1 < argc) {
            g_backend_port = std::stoi(argv[++i]);
        } else {
            std::cerr << "[-] Unknown option: " << arg << "\n";
            print_help(argv[0]);
            return 1;
        }
    }

    // Set up signal handlers for graceful exit
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // Create UDP socket
    g_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_server_fd < 0) {
        std::cerr << "[-] Failed to create UDP socket: " << std::strerror(errno) << "\n";
        return 1;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    // Bind to 0.0.0.0:g_listen_port
    struct sockaddr_in bind_addr;
    std::memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(g_listen_port);

    if (bind(g_server_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        std::cerr << "[-] Error binding UDP socket to port " << g_listen_port << ": "
                  << std::strerror(errno) << "\n";
        if (errno == EACCES) {
            std::cerr << "    Tip: Binding to port " << g_listen_port
                      << " requires root (sudo) or capability:\n"
                      << "    sudo setcap cap_net_bind_service=+ep " << argv[0] << "\n";
        }
        close(g_server_fd);
        return 1;
    }

    std::cout << "============================================================\n"
              << "[*] C++ UDP DNS Server Running\n"
              << "    Listen Address: 0.0.0.0:" << g_listen_port << "\n"
              << "    Upstream DNS:   " << g_upstream_dns << ":" << g_upstream_port << "\n"
              << "    HTTP Reporting: http://" << g_backend_host << ":" << g_backend_port << "/api/dns\n"
              << "[*] Press Ctrl+C to terminate.\n"
              << "============================================================\n";

    // Packet reception loop
    uint8_t buffer[4096];
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        ssize_t bytes = recvfrom(g_server_fd, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&client_addr, &client_len);

        if (bytes < 0) {
            if (!g_running) break;
            if (errno == EINTR) continue;
            std::cerr << "[-] recvfrom error: " << std::strerror(errno) << "\n";
            continue;
        }

        // Spawn a detached worker thread to handle forwarding and HTTP POST asynchronously
        std::vector<uint8_t> payload(buffer, buffer + bytes);
        std::thread(process_query, g_server_fd, client_addr, client_len, payload).detach();
    }

    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }

    std::cout << "[*] DNS server terminated cleanly.\n";
    return 0;
}
