#!/usr/bin/env python3
"""Two supplementary checks (HTTP streaming disabled, only the decoder is exercised).

 1. Link layer: capture on the 'any' interface (Linux cooked frames) with an Ethernet-only parser
    versus the datalink-aware decoder.
 2. Known weakness: 200 non-first IPv6 fragments - the decoder reports false ports.

Usage: python3 run_aux.py [results_dir] [repeats=5] [duration_s=10]
"""
import json, os, random, re, signal, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_exp import parse
from scapy.all import Ether, IPv6, IPv6ExtHdrFragment, Raw, wrpcap

rdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results")
reps = int(sys.argv[2]) if len(sys.argv) > 2 else 5
dur = int(sys.argv[3]) if len(sys.argv) > 3 else 10
os.makedirs(rdir, exist_ok=True)
OUT = os.path.join(HERE, "aux_out.txt")

def replay(pcap, pps, limit, loops=1):
    r = subprocess.run(["tcpreplay", "-i", "lo", f"--pps={pps}", f"--loop={loops}", f"--limit={limit}", pcap], capture_output=True, text=True)
    m = re.search(r"Successful packets:\s+(\d+)", r.stdout + r.stderr); return int(m.group(1)) if m else 0

def run(binary, iface, pps, seconds):
    with open(OUT, "w") as fo:
        sn = subprocess.Popen([os.path.join(HERE, binary), "-i", iface, "--no-http"], stdout=fo, stderr=subprocess.STDOUT); time.sleep(1.2)
        n = replay(os.path.join(HERE, "pool.pcap"), pps, pps * seconds, 100000); time.sleep(1.5)
        sn.send_signal(signal.SIGINT); sn.wait(timeout=15)
    res = parse(OUT); res["offered"] = n; os.remove(OUT); return res

rows = []
for rep in range(1, reps + 1):
    for name, b in (("ethernet_only", "sniffer_ethonly"), ("datalink_aware", "sniffer_prop")):
        r = run(b, "any", 100, dur); r.update(test="link_any", variant=name, rep=rep)
        rows.append(r); print(json.dumps(r), flush=True)

random.seed(3)
E = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")
frags = [E/IPv6(src="fd00::%x" % (0xf000 + i), dst="::1")/IPv6ExtHdrFragment(nh=17, offset=185, m=0, id=i)/Raw(bytes(random.randrange(256) for _ in range(16))) for i in range(200)]
fp = os.path.join(HERE, "frag.pcap"); wrpcap(fp, frags)
with open(OUT, "w") as fo:
    sn = subprocess.Popen([os.path.join(HERE, "sniffer_prop"), "-i", "lo", "--no-http"], stdout=fo, stderr=subprocess.STDOUT); time.sleep(1.2)
    n = replay(fp, 100, 200); time.sleep(1.5); sn.send_signal(signal.SIGINT); sn.wait(timeout=15)
lines = [l for l in open(OUT) if "IPv6 (" in l]
with_ports = sum(1 for l in lines if re.search(r"fd00::f[0-9a-f]{3}:\d+ ->", l))
r = dict(test="nonfirst_fragments", offered=n, reported=len(lines), reported_with_ports=with_ports, sample=lines[:2])
rows.append(r); print(json.dumps(r)); os.remove(OUT)
json.dump(rows, open(os.path.join(rdir, "aux_results.json"), "w"), indent=1)
