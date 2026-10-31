# NetPulse Empirical Experiment Results (F1 Team 22)

This document provides the complete empirical performance and accuracy evaluation of NetPulse compared against a naive baseline sniffer. It details how the project results and performance metrics were calculated, measured, and verified.

> **Reproducibility**: All experiment harness scripts, raw benchmark data, and plotting code are located in the [`experiments/`](experiments/) directory. You can reproduce the full evaluation suite by following the [Reproduction Guide](#how-to-reproduce-the-results) below.

---

## 1. Evaluation Environment

All experiments were executed on an isolated Linux benchmarking instance over the loopback interface (`lo`), sharing CPU resources between packet replay (`tcpreplay`), packet streamer, and Node.js backend.

| Item | Specification / Value |
|---|---|
| **OS / Kernel** | Linux-6.18.44-fc-v185-x86_64-with-glibc2.39 |
| **CPU** | Intel(R) Xeon(R) Processor @ 2.10GHz (1 vCPU) |
| **RAM** | 3995 MB |
| **Compiler** | g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 |
| **libpcap / tcpdump** | libpcap version 1.10.4 (with TPACKET_V3) \| tcpdump version 4.99.4 |
| **Node.js** | v22.22.2 |
| **Scapy** | 2.8.0 |
| **tcpreplay** | tcpreplay version 4.4.4 |

---

## 2. Methodology & Benchmark Setup

- **Synthetic Workload Pool (`gen_pool.py`)**:
  - A 2,000-packet PCAP dataset was procedurally generated using Scapy (`pool.pcap`).
  - **Distribution**: 40% IPv6 with extension headers, 20% plain IPv6, 35% IPv4, 5% ARP.
  - Every packet carries a deterministic source IP (`fd00::...`) and unique sequence ID, cross-validated against `tcpdump -v ip6 protochain` (`ground_truth_check.json`).
- **Compared Builds (`build_variants.py`)**:
  - **Proposed (`sniffer_prop`)**: Full NetPulse pipeline featuring IPv6 extension-header traversal engine and BPF / port-level self-capture loop protection (`F1_Team22_sniffer_http.cpp`).
  - **Baseline (`sniffer_base`)**: A naive sniffer build with IPv6 extension-header traversal disabled and self-capture guard disabled (mirroring standard naive implementations).
  - **Ethernet-only (`sniffer_ethonly`)**: A baseline variant assuming static `DLT_EN10MB` framing without multi-link-layer header offset adaptation.
- **Test Scenarios**:
  - **S1 (Low Load)**: 50 packets/s (20 s replay + 2 s drain; 5 runs per cell).
  - **S2 (Medium Load)**: 1,000 packets/s (20 s replay + 2 s drain; 5 runs per cell).
  - **S3 (High Load / Saturation)**: 10,000 packets/s (20 s replay + 2 s drain; 5 runs per cell).
  - Total: 30 independent trials alternating between baseline and proposed with a fresh backend process per run.

---

## 3. Evaluated Metrics

1. **M1 — IPv6 Extension-Header Identification Accuracy (%)**:
   Fraction of offered IPv6 packets with extension headers correctly decoded down to the true transport protocol and port (versus misidentifying as `HOPOPT` / Protocol 0).
2. **M2 — Backend Amplification Factor (streamed / offered)**:
   Ratio of packets forwarded to the web dashboard backend over actual offered traffic. A ratio > 1.0 indicates a self-capture amplification loop.
3. **M3 — Kernel Drop Rate (%)**:
   Percentage of frames dropped by libpcap buffer / kernel buffer (`ps_drop / (ps_recv + ps_drop)`).
4. **M4 — Delivery Ratio (%)**:
   Reliability of packet streaming over HTTP POST to backend under load.
5. **M5 — Traffic Coverage (%)**:
   Fraction of total offered IPv6 traffic successfully captured and analyzed before saturation drop.

---

## 4. Experimental Results (Mean ± SD)

| Scenario | Metric | Baseline (`sniffer_base`) | Proposed (`sniffer_prop`) | Improvement |
|---|---|---|---|---|
| **S1 (50 pkt/s)** | M1: IPv6 Ext-Header Accuracy (%) | 0.0 ± 0.0 | **100.0 ± 0.0** | **+100.0 pp** |
| S1 (50 pkt/s) | M2: Backend Amplification Factor | 36.80 ± 0.70 | **1.00 ± 0.00** | **97.3% lower (Loop eliminated)** |
| S1 (50 pkt/s) | M3: Kernel Drop Rate (%) | 87.25 ± 0.04 | **0.00 ± 0.00** | **100.0% lower** |
| S1 (50 pkt/s) | M4: Delivery Ratio (%) | 99.80 ± 0.00 | **100.00 ± 0.00** | n/a |
| S1 (50 pkt/s) | M5: Traffic Coverage (%) | 13.7 ± 0.7 | **100.0 ± 0.0** | **+86.3 pp** |
| **S2 (1,000 pkt/s)** | M1: IPv6 Ext-Header Accuracy (%) | 0.0 ± 0.0 | **100.0 ± 0.0** | **+100.0 pp** |
| S2 (1,000 pkt/s) | M2: Backend Amplification Factor | 1.95 ± 0.02 | **1.00 ± 0.00** | **48.8% lower** |
| S2 (1,000 pkt/s) | M3: Kernel Drop Rate (%) | 87.98 ± 0.09 | **0.00 ± 0.00** | **100.0% lower** |
| S2 (1,000 pkt/s) | M4: Delivery Ratio (%) | 99.80 ± 0.00 | **99.87 ± 0.00** | n/a |
| S2 (1,000 pkt/s) | M5: Traffic Coverage (%) | 8.1 ± 0.1 | **100.0 ± 0.0** | **+91.9 pp** |
| **S3 (10,000 pkt/s)** | M1: IPv6 Ext-Header Accuracy (%) | 0.0 ± 0.0 | **100.0 ± 0.0** | **+100.0 pp** |
| S3 (10,000 pkt/s) | M2: Backend Amplification Factor | 0.20 ± 0.00 | **0.20 ± 0.00** | Equal (CPU saturated) |
| S3 (10,000 pkt/s) | M3: Kernel Drop Rate (%) | 91.98 ± 0.05 | **78.98 ± 0.32** | **14.1% lower** |
| S3 (10,000 pkt/s) | M4: Delivery Ratio (%) | 99.80 ± 0.00 | **99.80 ± 0.00** | n/a |
| S3 (10,000 pkt/s) | M5: Traffic Coverage (%) | 3.1 ± 0.2 | **19.8 ± 0.5** | **+16.8 pp** |

*Note: Improvement represents gain in percentage points (pp) for M1 & M5, or relative reduction in error/overhead for M2 & M3. Realized offered rates were S1 = 50 pkt/s, S2 = 998 pkt/s, S3 = 9983 pkt/s.*

---

## 5. Visual Performance Charts

### Figure 4: Extension Header Accuracy, Amplification Factor & Kernel Drop Rate
![metrics](experiments/results/fig4_metrics.png)

### Figure 5: Traffic Coverage Under Escalating Offered Load
![coverage](experiments/results/fig5_coverage.png)

---

## 6. Supplementary Verification Checks

| Verification Test | Decoder Configuration | Results (Observed / Expected) | Analysis |
|---|---|---|---|
| **Capture on `any` (Linux cooked SLL frames)** | Static Ethernet-only Parser | **0 / 600** correct per run (all 5 runs) | Static 14-byte offset fails on 16-byte Linux Cooked SLL header, causing complete decode failure. |
| **Capture on `any` (Linux cooked SLL frames)** | DLT-Aware Engine (Proposed) | **600 / 600** correct per run (all 5 runs) | Dynamic DLT offset detection accurately decodes all frames across heterogeneous interfaces. |
| **Non-first IPv6 fragments (200 sent)** | Proposed Engine | **200 / 200** identified as fragments | Non-first fragments omit transport headers; false port decoding documented and flagged in project report. |

---

## 7. Raw Artifacts & Datasets

All raw measurement files and summary tables can be inspected in [`experiments/results/`](experiments/results/):
- **Raw CSV Data**: [`experiments/results/results_raw.csv`](experiments/results/results_raw.csv)
- **JSONL Trial Runs**: [`experiments/results/results.jsonl`](experiments/results/results.jsonl)
- **Aggregated Summary**: [`experiments/results/summary.json`](experiments/results/summary.json)
- **Auxiliary Checks**: [`experiments/results/aux_results.json`](experiments/results/aux_results.json)
- **Ground Truth Verification**: [`experiments/results/ground_truth_check.json`](experiments/results/ground_truth_check.json)

---

## 8. How to Reproduce the Results

### Prerequisites
On Ubuntu / Debian / Kali Linux:
```bash
sudo apt update
sudo apt install -y g++ libpcap-dev tcpdump tcpreplay nodejs npm python3-pip
pip3 install scapy matplotlib
```

### Execution
Run the automated experiment pipeline:
```bash
cd experiments
sudo ./F1_Team22_run_all.sh
```

The script will:
1. Generate the packet pool (`pool.pcap`) and ground-truth metadata (`meta.json`).
2. Build measurement variants (`sniffer_prop`, `sniffer_base`, `sniffer_ethonly`) from `F1_Team22_sniffer_http.cpp`.
3. Execute the 30 scenario runs on loopback using `tcpreplay`.
4. Perform auxiliary link-layer tests on interface `any`.
5. Compute statistics, render charts (`fig4_metrics.png`, `fig5_coverage.png`), and generate summary reports.
