#!/usr/bin/env python3
"""Demo helper: send three IPv6 packets that each start with an extension header onto the loopback interface.

  1. Hop-by-Hop header + MLDv2 report
  2. Hop-by-Hop header + TCP SYN to port 80
  3. Destination Options header + UDP datagram to port 53

Run a sniffer on 'lo' first (needs root), e.g.
    sudo ./sniffer_base -i lo --no-http     # baseline: prints HOPOPT, HOPOPT, Proto 60
    sudo ./sniffer_prop -i lo --no-http     # proposed: ICMPv6 (MLDv2 Report), TCP (HTTP), UDP (DNS) with ports
then run:  sudo python3 send_v6_demo.py
"""
from scapy.all import *
E = Ether()
pk = [
    E/IPv6(src="fd00::5", dst="::1")/IPv6ExtHdrHopByHop(options=[RouterAlert()])/ICMPv6MLReport2(),
    E/IPv6(src="fd00::6", dst="::1")/IPv6ExtHdrHopByHop(options=[RouterAlert()])/TCP(sport=40001, dport=80, flags="S"),
    E/IPv6(src="fd00::7", dst="::1")/IPv6ExtHdrDestOpt()/UDP(sport=40002, dport=53)/Raw(b"x" * 8),
]
sendp(pk, iface="lo", verbose=0)
print("sent", len(pk), "IPv6 packets with extension headers")
