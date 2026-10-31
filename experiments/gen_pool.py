#!/usr/bin/env python3
"""Build the mixed-traffic test pool (pool.pcap) and its ground truth (meta.json).

Every packet has a unique source address (IPv6 fd00::<id>, IPv4 10.77.x.y, ARP 10.78.x.y), so each
line printed by a sniffer can be matched to the packet that caused it. Ground truth is known by
construction and cross-checked against tcpdump's independent 'ip6 protochain' filters.

Usage: python3 gen_pool.py [N=2000]
"""
import json, os, random, subprocess, sys
from collections import Counter
from scapy.all import (Ether, IP, IPv6, TCP, UDP, ICMP, ARP, ICMPv6EchoRequest, ICMPv6MLReport2,
                       IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting, IPv6ExtHdrFragment,
                       RouterAlert, wrpcap, rdpcap)

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(7)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
E = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")
v6 = lambda i: IPv6(src="fd00::%x" % i, dst="::1")
v4 = lambda i: IP(src="10.77.%d.%d" % (i >> 8, i & 255), dst="127.0.0.1")
HBH = lambda: IPv6ExtHdrHopByHop(options=[RouterAlert()])

# (name, builder, expected protocol as printed by sniffer_http, destination port or None)
EH = [  # IPv6 packets that START with an extension header
 ("hbh_mld",   lambda i, sp: E/v6(i)/HBH()/ICMPv6MLReport2(), "ICMPv6", None),
 ("hbh_echo",  lambda i, sp: E/v6(i)/HBH()/ICMPv6EchoRequest(), "ICMPv6", None),
 ("hbh_tcp",   lambda i, sp: E/v6(i)/HBH()/TCP(sport=sp, dport=80, flags="S"), "TCP", 80),
 ("hbh_udp",   lambda i, sp: E/v6(i)/HBH()/UDP(sport=sp, dport=53)/(b"x"*8), "UDP", 53),
 ("dst_udp",   lambda i, sp: E/v6(i)/IPv6ExtHdrDestOpt()/UDP(sport=sp, dport=123)/(b"x"*8), "UDP", 123),
 ("dst_tcp",   lambda i, sp: E/v6(i)/IPv6ExtHdrDestOpt()/TCP(sport=sp, dport=443, flags="S"), "TCP", 443),
 ("rt_udp",    lambda i, sp: E/v6(i)/IPv6ExtHdrRouting()/UDP(sport=sp, dport=53)/(b"x"*8), "UDP", 53),
 ("frag1_udp", lambda i, sp: E/v6(i)/IPv6ExtHdrFragment(offset=0, m=1, id=i)/UDP(sport=sp, dport=5353)/(b"x"*8), "UDP", 5353),
 ("chain_tcp", lambda i, sp: E/v6(i)/HBH()/IPv6ExtHdrDestOpt()/TCP(sport=sp, dport=22, flags="S"), "TCP", 22),
]
PLAIN6 = [
 ("v6_tcp",  lambda i, sp: E/v6(i)/TCP(sport=sp, dport=80, flags="S"), "TCP", 80),
 ("v6_udp",  lambda i, sp: E/v6(i)/UDP(sport=sp, dport=53)/(b"x"*8), "UDP", 53),
 ("v6_echo", lambda i, sp: E/v6(i)/ICMPv6EchoRequest(), "ICMPv6", None),
]
V4 = [
 ("v4_tcp",  lambda i, sp: E/v4(i)/TCP(sport=sp, dport=443, flags="S"), "TCP", 443),
 ("v4_udp",  lambda i, sp: E/v4(i)/UDP(sport=sp, dport=123)/(b"x"*8), "UDP", 123),
 ("v4_icmp", lambda i, sp: E/v4(i)/ICMP(), "ICMP", None),
]
pkts, meta = [], {}
for i in range(1, N + 1):
    r, sp = i % 20, 20000 + (i % 20000)      # 40% IPv6+EH, 20% plain IPv6, 35% IPv4, 5% ARP
    if r < 8:    name, f, proto, dp = EH[(i // 20 * 8 + r) % len(EH)]; fam, eh = "v6", True
    elif r < 12: name, f, proto, dp = PLAIN6[i % 3]; fam, eh = "v6", False
    elif r < 19: name, f, proto, dp = V4[i % 3]; fam, eh = "v4", False
    else:
        pkts.append(Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc="10.78.%d.%d" % (i >> 8, i & 255), pdst="10.78.0.1"))
        meta[i] = dict(name="arp", fam="arp", proto="ARP", sport=None, dport=None, eh=False); continue
    pkts.append(f(i, sp))
    meta[i] = dict(name=name, fam=fam, proto=proto, sport=sp if dp else None, dport=dp, eh=eh)
pool = os.path.join(HERE, "pool.pcap")
wrpcap(pool, pkts)
json.dump(meta, open(os.path.join(HERE, "meta.json"), "w"))
print("pool.pcap: %d packets, %d IPv6 packets with extension headers" % (len(pkts), sum(1 for m in meta.values() if m["eh"])))

# ---- ground-truth cross-check with tcpdump (independent of this script) ----
expected = Counter(m["proto"] for m in meta.values() if m["fam"] == "v6")
chain = {"TCP": 6, "UDP": 17, "ICMPv6": 58}
check = {"expected_from_metadata": dict(expected), "tcpdump_protochain": {}}
try:
    for name, num in chain.items():
        tmp = os.path.join(HERE, "_tc.pcap")
        subprocess.run(["tcpdump", "-nn", "-r", pool, "-w", tmp, "ip6 protochain %d" % num], capture_output=True, check=True)
        check["tcpdump_protochain"][name] = len(rdpcap(tmp)); os.remove(tmp)
    check["match"] = all(check["tcpdump_protochain"][k] == expected[k] for k in chain)
except Exception as e:
    check["error"] = str(e)
os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
json.dump(check, open(os.path.join(HERE, "results", "ground_truth_check.json"), "w"), indent=1)
print("ground truth check:", check)
