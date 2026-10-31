#!/usr/bin/env python3
"""Run baseline-vs-proposed trials (needs root or CAP_NET_RAW, tcpreplay, node).

Usage: python3 run_exp.py [out.jsonl] [duration_s] [repeats] [scenarios]
       defaults: results/results.jsonl 20 5 S1,S2,S3

For each repeat and scenario the baseline and the proposed build run one after the other, each with a
freshly started backend. tcpreplay injects pool.pcap onto the loopback interface at the scenario's rate.
"""
import json, os, re, signal, subprocess, sys, time, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.environ.get("BACKEND_DIR", os.path.join(HERE, "..", "packet-streamer"))
RATES = {"S1": 50, "S2": 1000, "S3": 10000}          # packets per second
META = {int(k): v for k, v in json.load(open(os.path.join(HERE, "meta.json"))).items()}
LINE = re.compile(r"^\[#(\d+)\] IPv6 \((\S+?)[ )].*? (\S+) -> (\S+) \[(\d+)B\]$")
SRC = re.compile(r"^fd00::([0-9a-f]+)(?::(\d+))?$")

def wait_health(timeout=8):
    t = time.time()
    while time.time() - t < timeout:
        try:
            urllib.request.urlopen("http://127.0.0.1:3000/health", timeout=0.5).read(); return True
        except Exception:
            time.sleep(0.2)
    return False

def parse(path):
    """Score every IPv6 line that belongs to the pool, and read the counters printed at exit."""
    s = dict(v6_lines=0, v6_ok=0, eh_lines=0, eh_ok=0, plain_lines=0, plain_ok=0)
    counters = {}
    with open(path, errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            m = LINE.match(ln)
            if m:
                proto, src = m.group(2), m.group(3)
                sm = SRC.match(src)
                if not sm: continue
                meta = META.get(int(sm.group(1), 16)); sp = sm.group(2)
                if not meta or meta["fam"] != "v6": continue
                ok = (proto == meta["proto"]) and (meta["sport"] is None or (sp is not None and int(sp) == meta["sport"]))
                s["v6_lines"] += 1; s["v6_ok"] += ok
                k = "eh" if meta["eh"] else "plain"
                s[k + "_lines"] += 1; s[k + "_ok"] += ok
                continue
            for key, pat in (("captured", r"Total Captured:\s+(\d+)"), ("streamed", r"Streamed to Backend:\s+(\d+)"),
                             ("self_filtered", r"Self-traffic Filtered:\s*(\d+)"), ("http_errors", r"HTTP Errors/Drops:\s+(\d+)"),
                             ("k_recv", r"Kernel Received:\s+(\d+)"), ("k_drop", r"Kernel Dropped:\s+(\d+)")):
                mm = re.match(pat, ln)
                if mm: counters[key] = int(mm.group(1))
    s.update(counters); return s

def trial(variant, scen, dur, rep, outdir):
    binary = os.path.join(HERE, "sniffer_base" if variant == "baseline" else "sniffer_prop")
    pps = RATES[scen]
    server_file = "F1_Team22_server.js" if os.path.exists(os.path.join(BACKEND, "F1_Team22_server.js")) else "server.js"
    node = subprocess.Popen(["node", server_file], cwd=BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_health(): raise RuntimeError("backend did not start (npm install in packet-streamer first)")
        outf = os.path.join(outdir, f"{variant}_{scen}_{rep}.txt")
        with open(outf, "w") as fo:
            sn = subprocess.Popen([binary, "-i", "lo"], stdout=fo, stderr=subprocess.STDOUT)
            time.sleep(1.2)
            t0 = time.time()
            r = subprocess.run(["tcpreplay", "-i", "lo", f"--pps={pps}", "--loop=100000", f"--limit={pps*dur}",
                                os.path.join(HERE, "pool.pcap")], capture_output=True, text=True)
            elapsed = time.time() - t0
            m = re.search(r"Successful packets:\s+(\d+)", r.stdout + r.stderr)
            offered = int(m.group(1)) if m else 0
            time.sleep(2.0)                                  # drain
            sn.send_signal(signal.SIGINT)
            try: sn.wait(timeout=20); clean = True
            except subprocess.TimeoutExpired: sn.kill(); sn.wait(); clean = False
        res = parse(outf)
        res.update(variant=variant, scenario=scen, rep=rep, offered=offered, replay_s=round(elapsed, 2), clean_exit=clean, pps_target=pps)
        os.remove(outf)
        return res
    finally:
        node.terminate()
        try: node.wait(timeout=5)
        except subprocess.TimeoutExpired: node.kill()
        time.sleep(0.5)

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results", "results.jsonl")
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    reps = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    scens = sys.argv[4].split(",") if len(sys.argv) > 4 else ["S1", "S2", "S3"]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    tmp = os.path.join(HERE, "tmp_out"); os.makedirs(tmp, exist_ok=True)
    for rep in range(1, reps + 1):
        for sc in scens:
            for v in ("baseline", "proposed"):
                r = trial(v, sc, dur, rep, tmp)
                with open(out, "a") as f: f.write(json.dumps(r) + "\n")
                print(json.dumps(r), flush=True)
