#!/usr/bin/env python3
"""Derive the measurement builds from the repository's sniffer_http.cpp.

  sniffer_prop     proposed build (unchanged behaviour) + a pcap_stats printout at exit
  sniffer_base     baseline: BASELINE_NO_EH (no IPv6 extension-header walk) and
                   BASELINE_NO_GUARD (no BPF self-capture filter, no port check)
  sniffer_ethonly  proposed build forced to assume Ethernet framing (link-layer check)

Usage: python3 build_variants.py [path/to/sniffer_http.cpp]   (default: ../sniffer_http.cpp)
"""
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
srcpath = sys.argv[1] if len(sys.argv) > 1 else (
    os.path.join(HERE, "..", "F1_Team22_sniffer_http.cpp")
    if os.path.exists(os.path.join(HERE, "..", "F1_Team22_sniffer_http.cpp"))
    else os.path.join(HERE, "..", "sniffer_http.cpp")
)
src = open(srcpath).read()

hdr = "#ifndef BASELINE_NO_EH\n#define BASELINE_NO_EH 0\n#endif\n#ifndef BASELINE_NO_GUARD\n#define BASELINE_NO_GUARD 0\n#endif\n"
assert "#include <iostream>" in src
src = src.replace("#include <iostream>", hdr + "#include <iostream>", 1)

loop = "while (cur_offset <= header->caplen) {"
assert src.count(loop) == 1
src = src.replace(loop, "while (!BASELINE_NO_EH && cur_offset <= header->caplen) {")

chk = "if (src_port == g_backend_port || dst_port == g_backend_port) {"
assert src.count(chk) == 2
src = src.replace(chk, "if (!BASELINE_NO_GUARD && (src_port == g_backend_port || dst_port == g_backend_port)) {")

old = 'std::string final_filter = "not (tcp port " + std::to_string(g_backend_port) + ")";'
assert old in src
src = src.replace(old, 'std::string final_filter = BASELINE_NO_GUARD ? std::string("") : ("not (tcp port " + std::to_string(g_backend_port) + ")");')

old = "    pcap_close(g_pcap_handle);\n    g_pcap_handle = nullptr;\n    std::cout << \"[*] Capture terminated cleanly.\\n\";"
assert old in src
src = src.replace(old, '    { struct pcap_stat ps; if (pcap_stats(g_pcap_handle, &ps) == 0)\n        std::cout << "Kernel Received: " << ps.ps_recv << "\\nKernel Dropped: " << ps.ps_drop << "\\n"; }\n' + old)

measure = os.path.join(HERE, "sniffer_http_measure.cpp")
open(measure, "w").write(src)

dl = "g_link_type = pcap_datalink(g_pcap_handle);"
assert src.count(dl) == 1
open(os.path.join(HERE, "sniffer_http_ethonly.cpp"), "w").write(src.replace(dl, dl + "\n    g_link_type = DLT_EN10MB; /* force Ethernet assumption */"))

flags = ["-O2", "-std=c++17", "-Wall", "-Wextra"]
def build(out, cpp, *defs):
    subprocess.check_call(["g++", *flags, *defs, "-o", os.path.join(HERE, out), os.path.join(HERE, cpp), "-lpcap"])
build("sniffer_prop", "sniffer_http_measure.cpp")
build("sniffer_base", "sniffer_http_measure.cpp", "-DBASELINE_NO_EH=1", "-DBASELINE_NO_GUARD=1")
build("sniffer_ethonly", "sniffer_http_ethonly.cpp")
print("built sniffer_prop, sniffer_base, sniffer_ethonly")
