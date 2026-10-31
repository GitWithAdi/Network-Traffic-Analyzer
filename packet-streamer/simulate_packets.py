#!/usr/bin/env python3
"""
Wrapper for packet simulator, forwarding to F1_Team22_simulate_packets.py
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import F1_Team22_simulate_packets

if __name__ == "__main__":
    F1_Team22_simulate_packets.main()
