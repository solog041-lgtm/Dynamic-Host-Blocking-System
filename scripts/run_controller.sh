#!/usr/bin/env bash
# Start POX with persistent blocklist and event logging.
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO/results"
cd "$HOME/pox"
./pox.py log.level --INFO host_blocker \
    --config="$REPO/config/config.json" \
    --event_log="$REPO/results/events.csv" \
    --state_file="$REPO/results/blocklist.json"
