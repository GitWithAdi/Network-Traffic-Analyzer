CXX ?= g++
CXXFLAGS ?= -Wall -Wextra -O2 -std=c++17 -pthread
LDFLAGS ?= -lpcap

TARGET = sniffer
HTTP_TARGET = sniffer_http
DNS_TARGET = dns_server

SRCS = sniffer.cpp
HTTP_SRCS = sniffer_http.cpp
DNS_SRCS = dns_server.cpp

all: $(TARGET) $(HTTP_TARGET) $(DNS_TARGET) setcap

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

$(HTTP_TARGET): $(HTTP_SRCS)
	$(CXX) $(CXXFLAGS) -o $(HTTP_TARGET) $(HTTP_SRCS) $(LDFLAGS)

$(DNS_TARGET): $(DNS_SRCS)
	$(CXX) $(CXXFLAGS) -o $(DNS_TARGET) $(DNS_SRCS)

setcap: $(TARGET) $(HTTP_TARGET) $(DNS_TARGET)
	@echo "[*] Applying network capabilities..."
	@sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET) 2>/dev/null || true
	@sudo setcap cap_net_raw,cap_net_admin=eip $(HTTP_TARGET) 2>/dev/null || true
	@sudo setcap cap_net_bind_service=+ep $(DNS_TARGET) 2>/dev/null || true

clean:
	rm -f $(TARGET) $(HTTP_TARGET) $(DNS_TARGET) a.out

test: all
	@echo "[*] Testing $(TARGET) help..."
	./$(TARGET) --help
	@echo "[*] Testing $(HTTP_TARGET) help..."
	./$(HTTP_TARGET) --help
	@echo "[*] Testing $(DNS_TARGET) help..."
	./$(DNS_TARGET) --help

.PHONY: all clean setcap test
