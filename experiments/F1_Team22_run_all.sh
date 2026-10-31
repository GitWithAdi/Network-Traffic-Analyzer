#!/usr/bin/env bash
# Full pipeline (about 15 minutes). Run from this folder as root, e.g.:  sudo ./F1_Team22_run_all.sh
set -e
cd "$(dirname "$0")"
(cd ../packet-streamer && [ -d node_modules ] || npm install)
python3 gen_pool.py 2000
python3 build_variants.py
python3 run_exp.py results/results.jsonl 20 5 S1,S2,S3
python3 run_aux.py results
python3 analyze.py results
echo "Done. See results/RESULTS.md and ../F1_Team22_results.md"
