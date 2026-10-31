# NetPulse experiment results

Generated 2026-10-31 05:35 by `analyze.py` from `results.jsonl` (30 trials).

## Environment

| Item | Value |
|---|---|
| OS / kernel | Linux-6.18.44-fc-v185-x86_64-with-glibc2.39 |
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, 1 vCPU(s) |
| RAM | 3995 MB |
| Compiler | g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 |
| libpcap / tcpdump | libpcap version 1.10.4 (with TPACKET_V3) | tcpdump version 4.99.4 |
| Node.js | v22.22.2 |
| Scapy | 2.8.0 |
| tcpreplay | tcpreplay version: 4.4.4 (build git:v4.4.4) (debug) |

Absolute throughput depends on the host; the baseline-versus-proposed comparison is what matters. Everything ran on the loopback interface with the sniffer, backend and replay tool sharing the same CPU(s).

## Method

- **Traffic:** a 2,000-packet pool built with Scapy (`gen_pool.py`), replayed on `lo` with `tcpreplay --pps=N`: 40 % IPv6 with extension headers, 20 % plain IPv6, 35 % IPv4, 5 % ARP. Every packet has a unique source address so each output line can be scored.
- **Ground truth:** known by construction from `meta.json` and cross-checked with tcpdump (`ip6 protochain`): matches
- **Builds:** `sniffer_prop` is the repository's `sniffer_http` plus a `pcap_stats` printout; `sniffer_base` is the same code with the IPv6 extension-header walk and the self-capture guard disabled (`build_variants.py`).
- **Scenarios:** S1 50, S2 1,000, S3 10,000 packets/s; 20 s of replay + 2 s drain per run; 5 runs per cell (baseline and proposed alternate within each repeat; a fresh backend per run).

## Results (mean ± SD)

| Scenario | Metric | Baseline | Proposed | Improvement |
|---|---|---|---|---|
| S1 (50 pkt/s) | M1 IPv6 extension-header identification accuracy (%) | 0.0 ± 0.0 | 100.0 ± 0.0 | +100.0 pp |
| S1 (50 pkt/s) | M2 Backend amplification factor (streamed / offered) | 36.80 ± 0.70 | 1.00 ± 0.00 | 97.3 % lower |
| S1 (50 pkt/s) | M3 Kernel drop rate (%) | 87.25 ± 0.04 | 0.00 ± 0.00 | 100.0 % lower |
| S1 (50 pkt/s) | M4 Delivery ratio (%) | 99.80 ± 0.00 | 100.00 ± 0.00 | n/a |
| S1 (50 pkt/s) | M5 Traffic coverage (%) | 13.7 ± 0.7 | 100.0 ± 0.0 | +86.3 pp |
| S2 (1,000 pkt/s) | M1 IPv6 extension-header identification accuracy (%) | 0.0 ± 0.0 | 100.0 ± 0.0 | +100.0 pp |
| S2 (1,000 pkt/s) | M2 Backend amplification factor (streamed / offered) | 1.95 ± 0.02 | 1.00 ± 0.00 | 48.8 % lower |
| S2 (1,000 pkt/s) | M3 Kernel drop rate (%) | 87.98 ± 0.09 | 0.00 ± 0.00 | 100.0 % lower |
| S2 (1,000 pkt/s) | M4 Delivery ratio (%) | 99.80 ± 0.00 | 99.87 ± 0.00 | n/a |
| S2 (1,000 pkt/s) | M5 Traffic coverage (%) | 8.1 ± 0.1 | 100.0 ± 0.0 | +91.9 pp |
| S3 (10,000 pkt/s) | M1 IPv6 extension-header identification accuracy (%) | 0.0 ± 0.0 | 100.0 ± 0.0 | +100.0 pp |
| S3 (10,000 pkt/s) | M2 Backend amplification factor (streamed / offered) | 0.20 ± 0.00 | 0.20 ± 0.00 | none (both at ceiling) |
| S3 (10,000 pkt/s) | M3 Kernel drop rate (%) | 91.98 ± 0.05 | 78.98 ± 0.32 | 14.1 % lower |
| S3 (10,000 pkt/s) | M4 Delivery ratio (%) | 99.80 ± 0.00 | 99.80 ± 0.00 | n/a |
| S3 (10,000 pkt/s) | M5 Traffic coverage (%) | 3.1 ± 0.2 | 19.8 ± 0.5 | +16.8 pp |

Improvement is the gain in percentage points (pp) for M1 and M5 and the relative reduction for M2 and M3. Achieved offered load (packets/s): S1 50, S2 998, S3 9983.

![metrics](fig4_metrics.png)

![coverage](fig5_coverage.png)

Raw per-run counters: `results_raw.csv`. Aggregates: `summary.json`.

## Supplementary checks

| Check | Decoder | Result |
|---|---|---|
| Capture on `any` (Linux cooked frames), IPv6 packets decoded correctly per run | Ethernet-only parser | 0 of 600, 0 of 600, 0 of 600, 0 of 600, 0 of 600 (one value per run) |
| Capture on `any` (Linux cooked frames), IPv6 packets decoded correctly per run | Datalink-aware (proposed) | 600 of 600, 600 of 600, 600 of 600, 600 of 600, 600 of 600 (one value per run) |
| Non-first IPv6 fragments on `lo` (200 sent) | Proposed | 200 of 200 reported with ports taken from fragment data (false ports) |

## Notes

- M1 is measured only on the packets that carry IPv6 extension headers; on plain IPv6 both builds were correct.
- M3: on loopback the kernel counts each frame twice, which does not change the ratio.
- M5 is the share of offered IPv6 packets that were captured and decoded; it makes the builds comparable when both are saturated.
- The baseline storm keeps the capture thread busy with its own traffic until it hits the processing ceiling, so M2 for the baseline depends on how fast the host is.
