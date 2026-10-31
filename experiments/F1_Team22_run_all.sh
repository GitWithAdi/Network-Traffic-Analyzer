#!/usr/bin/env bash
# NetPulse Experiments Runner (F1 Team 22)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_all.sh" "$@"
