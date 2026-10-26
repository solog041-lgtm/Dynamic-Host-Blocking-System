#!/usr/bin/env bash
# Terminal 1: start the POX controller with the host-blocking component.
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HOME/pox"
./pox.py log.level --INFO host_blocker \
    --config="$REPO/config/config.json" \
    --event_log="$REPO/results/events.csv"
