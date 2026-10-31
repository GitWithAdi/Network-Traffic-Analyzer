# NetPulse experiments: baseline vs proposed

Scripts, raw data and results used to evaluate NetPulse against a naive baseline sniffer.
Put this folder in the repository root, next to `F1_Team22_sniffer_http.cpp` and `packet-streamer/`.

| What | Detail |
|---|---|
| Question | Does the IPv6 extension-header walk and the self-capture guard make a measurable difference? |
| Baseline | `F1_Team22_sniffer_http.cpp` with the extension-header loop and the BPF / port self-capture guard disabled |
| Proposed | `F1_Team22_sniffer_http.cpp` as in the repository (plus a `pcap_stats` printout at exit) |
| Scenarios | S1 50, S2 1,000, S3 10,000 packets/s; 20 s per run; 5 runs per cell |
| Metrics | M1 extension-header identification accuracy, M2 backend amplification, M3 kernel drop rate, M4 delivery ratio, M5 traffic coverage |

Latest results: [`results/RESULTS.md`](results/RESULTS.md).

## Files

| File | Role |
|---|---|
| `gen_pool.py` | Builds `pool.pcap` (2,000 mixed packets) and `meta.json` (ground truth); cross-checks it with tcpdump |
| `build_variants.py` | Derives `sniffer_prop`, `sniffer_base` and `sniffer_ethonly` from `../sniffer_http.cpp` |
| `run_exp.py` | Runs the trials: backend + sniffer + `tcpreplay` on `lo`, scores the output |
| `run_aux.py` | Link-layer check on the `any` interface and the non-first IPv6 fragment check |
| `analyze.py` | Mean and SD, charts, `RESULTS.md` |
| `F1_Team22_run_all.sh` | Runs everything in order (about 15 minutes) |
| `send_v6_demo.py` | Demo helper: three IPv6 packets with extension headers, for a live baseline-vs-proposed comparison |
| `results/` | Raw per-run data (`results.jsonl`, `results_raw.csv`), aggregates, charts and `RESULTS.md` |

## Run it

Needs Linux, root (or `CAP_NET_RAW`), a C++ compiler with libpcap headers, Node.js, tcpdump, tcpreplay, Python 3.

```bash
sudo apt install g++ libpcap-dev tcpdump tcpreplay nodejs npm python3-pip
pip install scapy matplotlib
cd experiments
sudo ./F1_Team22_run_all.sh          # runs all steps in sequence
```

To use a different backend folder: `BACKEND_DIR=/path/to/packet-streamer python3 run_exp.py ...`.
A quick check of the setup: `python3 run_exp.py /tmp/quick/results.jsonl 4 1 S1` then `python3 analyze.py /tmp/quick`.

## Live demo of the main result

```bash
sudo ./sniffer_base -i lo --no-http        # baseline: prints HOPOPT, HOPOPT, Proto 60
sudo python3 send_v6_demo.py               # in a second terminal
sudo ./sniffer_prop -i lo --no-http        # proposed: ICMPv6 (MLDv2 Report), TCP (HTTP), UDP (DNS) with ports
```

## Notes

- M1 is measured only on packets that carry IPv6 extension headers (40 % of the pool). On plain IPv6 both builds are correct.
- Results depend on the host. The committed results come from a 1 vCPU Ubuntu 24.04 machine over loopback, where the sniffer, backend and replay tool share one CPU; see `results/RESULTS.md` for the environment. Re-run on your own machine and commit the new `results/` to replace them.
- The generated files (`pool.pcap`, `meta.json`, binaries, `tmp_out/`) are listed in `.gitignore`.
