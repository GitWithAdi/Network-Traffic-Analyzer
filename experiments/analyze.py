#!/usr/bin/env python3
"""Aggregate results.jsonl into mean +- SD, draw the charts and write RESULTS.md.

Usage: python3 analyze.py [results_dir]      (default: results/)
Reads  results_dir/results.jsonl (+ aux_results.json, ground_truth_check.json if present)
Writes results_dir/summary.json, results_raw.csv, fig4_metrics.png, fig5_coverage.png, RESULTS.md
"""
import csv, datetime, json, os, platform, shutil, statistics as st, subprocess, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
HERE = os.path.dirname(os.path.abspath(__file__))
RD = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results")
plt.rcParams["font.family"] = ["Liberation Serif", "DejaVu Serif"]
rows = [json.loads(l) for l in open(os.path.join(RD, "results.jsonl"))]
VAR = ["baseline", "proposed"]
SC = [s for s in ("S1", "S2", "S3") if any(r["scenario"] == s for r in rows)]   # works for partial runs too
LABEL = {"M1": "M1 IPv6 extension-header identification accuracy (%)", "M2": "M2 Backend amplification factor (streamed / offered)",
         "M3": "M3 Kernel drop rate (%)", "M4": "M4 Delivery ratio (%)", "M5": "M5 Traffic coverage (%)"}
DEC = {"M1": 1, "M2": 2, "M3": 2, "M4": 2, "M5": 1}

def metrics(r):
    return dict(
        M1=100.0 * r["eh_ok"] / r["eh_lines"] if r["eh_lines"] else float("nan"),
        M2=r["streamed"] / r["offered"] if r["offered"] else float("nan"),
        M3=100.0 * r["k_drop"] / r["k_recv"] if r.get("k_recv") else float("nan"),
        M4=100.0 * r["streamed"] / max(1, r["captured"] - r["self_filtered"]),
        M5=100.0 * r["v6_lines"] / (0.6 * r["offered"]) if r["offered"] else float("nan"),   # 60% of the pool is IPv6
        rate=r["offered"] / r["replay_s"])
D = {(v, s): [] for v in VAR for s in SC}
for r in rows: D[(r["variant"], r["scenario"])].append((r["rep"], metrics(r)))
def ms(v, s, k):
    xs = [m[k] for _, m in sorted(D[(v, s)], key=lambda t: t[0])]
    return (st.mean(xs), st.stdev(xs) if len(xs) > 1 else 0.0, xs)
out = {f"{v}|{s}|{k}": ms(v, s, k) for s in SC for v in VAR for k in ("M1", "M2", "M3", "M4", "M5", "rate")}
json.dump({k: dict(mean=a, sd=b, runs=c) for k, (a, b, c) in out.items()}, open(os.path.join(RD, "summary.json"), "w"), indent=1)

with open(os.path.join(RD, "results_raw.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["variant", "scenario", "rep", "offered", "captured", "streamed", "self_filtered", "http_errors", "kernel_recv", "kernel_drop", "ipv6_lines", "ipv6_correct", "eh_lines", "eh_correct"])
    for r in rows: w.writerow([r["variant"], r["scenario"], r["rep"], r["offered"], r["captured"], r["streamed"], r["self_filtered"], r["http_errors"], r.get("k_recv", ""), r.get("k_drop", ""), r["v6_lines"], r["v6_ok"], r["eh_lines"], r["eh_ok"]])

# ---- charts
C = {"baseline": "#D1495B", "proposed": "#0E8A94"}
fig, axs = plt.subplots(1, 3, figsize=(6.6, 2.7))
titles = {"M1": "M1: extension-header\nidentification (%)", "M2": "M2: backend amplification\n(streamed / offered)", "M3": "M3: kernel drop rate (%)"}
for ax, k in zip(axs, ("M1", "M2", "M3")):
    w = 0.38
    for j, v in enumerate(VAR):
        xs = [i + (j - 0.5) * w for i in range(len(SC))]
        ax.bar(xs, [out[f"{v}|{s}|{k}"][0] for s in SC], w, yerr=[out[f"{v}|{s}|{k}"][1] for s in SC], capsize=2.5,
               color=C[v], label=v.capitalize(), edgecolor="#333333", linewidth=0.6, error_kw=dict(lw=0.8))
    ax.set_xticks(range(len(SC))); ax.set_xticklabels(SC, fontsize=9); ax.set_title(titles[k], fontsize=9)
    ax.tick_params(axis="y", labelsize=8); ax.grid(axis="y", lw=0.3, alpha=0.6); ax.set_axisbelow(True)
    if k == "M2": ax.set_yscale("log")
axs[0].set_ylim(0, 105); axs[0].legend(fontsize=8, frameon=False, loc="center left")
fig.tight_layout(); fig.savefig(os.path.join(RD, "fig4_metrics.png"), dpi=220); plt.close(fig)
fig, ax = plt.subplots(figsize=(4.6, 2.9))
for v in VAR:
    ax.errorbar([out[f"{v}|{s}|rate"][0] for s in SC], [out[f"{v}|{s}|M5"][0] for s in SC], yerr=[out[f"{v}|{s}|M5"][1] for s in SC],
                marker="o", capsize=3, color=C[v], label=v.capitalize(), lw=1.4, ms=5)
ax.set_xscale("log"); ax.set_xlabel("Achieved offered load (packets/s, log scale)", fontsize=9)
ax.set_ylabel("M5: offered IPv6 traffic analysed (%)", fontsize=9); ax.set_ylim(0, 105); ax.grid(lw=0.3, alpha=0.6)
ax.tick_params(labelsize=8); ax.legend(fontsize=8, frameon=False, loc="center right")
fig.tight_layout(); fig.savefig(os.path.join(RD, "fig5_coverage.png"), dpi=220); plt.close(fig)

# ---- RESULTS.md
def run(cmd):
    try: return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
    except Exception: return ""
def first(txt, n=0): 
    ls = [l.strip() for l in txt.splitlines() if l.strip()]; return ls[n] if len(ls) > n else "n/a"
cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "n/a") if os.path.exists("/proc/cpuinfo") else "n/a"
mem = next((int(l.split()[1]) // 1024 for l in open("/proc/meminfo") if l.startswith("MemTotal")), 0) if os.path.exists("/proc/meminfo") else 0
try:
    import scapy; scv = scapy.__version__
except Exception: scv = "n/a"
env = [("OS / kernel", f"{platform.platform()}"), ("CPU", f"{cpu}, {os.cpu_count()} vCPU(s)"), ("RAM", f"{mem} MB"),
       ("Compiler", first(run(["g++", "--version"]))), ("libpcap / tcpdump", first(run(["tcpdump", "--version"]), 1) + " | " + first(run(["tcpdump", "--version"]))),
       ("Node.js", first(run(["node", "-v"]))), ("Scapy", scv), ("tcpreplay", first(run(["tcpreplay", "--version"])))]
def cellfmt(k, v): d = DEC[k]; return f"{v[0]:.{d}f} ± {v[1]:.{d}f}"
def improvement(k, b, p):
    if k in ("M1", "M5"): return f"+{p - b:.1f} pp"
    if k == "M4": return "n/a"
    if b == 0: return "n/a"
    red = (b - p) / b * 100
    return "none (both at ceiling)" if abs(red) < 1 else f"{red:.1f} % lower"
SCN = {"S1": "S1 (50 pkt/s)", "S2": "S2 (1,000 pkt/s)", "S3": "S3 (10,000 pkt/s)"}
n = {s: len(D[("baseline", s)]) for s in SC}
md = ["# NetPulse experiment results", "",
      f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} by `analyze.py` from `results.jsonl` ({len(rows)} trials).", "",
      "## Environment", "", "| Item | Value |", "|---|---|"] + [f"| {a} | {b} |" for a, b in env] + [
      "", "Absolute throughput depends on the host; the baseline-versus-proposed comparison is what matters. Everything ran on the loopback interface with the sniffer, backend and replay tool sharing the same CPU(s).", "",
      "## Method", "",
      "- **Traffic:** a 2,000-packet pool built with Scapy (`gen_pool.py`), replayed on `lo` with `tcpreplay --pps=N`: 40 % IPv6 with extension headers, 20 % plain IPv6, 35 % IPv4, 5 % ARP. Every packet has a unique source address so each output line can be scored.",
      "- **Ground truth:** known by construction from `meta.json` and cross-checked with tcpdump (`ip6 protochain`)" + (": " + ("matches" if json.load(open(os.path.join(RD, 'ground_truth_check.json'))).get('match') else "MISMATCH, check the file") if os.path.exists(os.path.join(RD, "ground_truth_check.json")) else "."),
      "- **Builds:** `sniffer_prop` is the repository's `sniffer_http` plus a `pcap_stats` printout; `sniffer_base` is the same code with the IPv6 extension-header walk and the self-capture guard disabled (`build_variants.py`).",
      f"- **Scenarios:** S1 50, S2 1,000, S3 10,000 packets/s; 20 s of replay + 2 s drain per run; {n['S1']} runs per cell (baseline and proposed alternate within each repeat; a fresh backend per run).", "",
      "## Results (mean ± SD)", "", "| Scenario | Metric | Baseline | Proposed | Improvement |", "|---|---|---|---|---|"]
for s in SC:
    for k in ("M1", "M2", "M3", "M4", "M5"):
        b, p = out[f"baseline|{s}|{k}"], out[f"proposed|{s}|{k}"]
        md.append(f"| {SCN[s]} | {LABEL[k]} | {cellfmt(k, b)} | {cellfmt(k, p)} | {improvement(k, b[0], p[0])} |")
md += ["", "Improvement is the gain in percentage points (pp) for M1 and M5 and the relative reduction for M2 and M3. Achieved offered load (packets/s): " +
       ", ".join(f"{SCN[s].split(' ')[0]} {out[f'baseline|{s}|rate'][0]:.0f}" for s in SC) + ".", "",
       "![metrics](fig4_metrics.png)", "", "![coverage](fig5_coverage.png)", "",
       "Raw per-run counters: `results_raw.csv`. Aggregates: `summary.json`.", ""]
ap = os.path.join(RD, "aux_results.json")
if os.path.exists(ap):
    aux = json.load(open(ap))
    link = {}
    for r in aux:
        if r.get("test") == "link_any": link.setdefault(r["variant"], []).append(r)
    md += ["## Supplementary checks", "", "| Check | Decoder | Result |", "|---|---|---|"]
    for name, lab in (("ethernet_only", "Ethernet-only parser"), ("datalink_aware", "Datalink-aware (proposed)")):
        rr = link.get(name, [])
        if rr:
            md.append(f"| Capture on `any` (Linux cooked frames), IPv6 packets decoded correctly per run | {lab} | " + ", ".join(f"{r['v6_ok']} of {int(0.6*r['offered'])}" for r in rr) + " (one value per run) |")
    for r in aux:
        if r.get("test") == "nonfirst_fragments":
            md.append(f"| Non-first IPv6 fragments on `lo` ({r['offered']} sent) | Proposed | {r['reported_with_ports']} of {r['offered']} reported with ports taken from fragment data (false ports) |")
    md.append("")
md += ["## Notes", "",
       "- M1 is measured only on the packets that carry IPv6 extension headers; on plain IPv6 both builds were correct.",
       "- M3: on loopback the kernel counts each frame twice, which does not change the ratio.",
       "- M5 is the share of offered IPv6 packets that were captured and decoded; it makes the builds comparable when both are saturated.",
       "- The baseline storm keeps the capture thread busy with its own traffic until it hits the processing ceiling, so M2 for the baseline depends on how fast the host is.", ""]
open(os.path.join(RD, "RESULTS.md"), "w").write("\n".join(md))
print("wrote summary.json, results_raw.csv, charts and RESULTS.md in", RD)
