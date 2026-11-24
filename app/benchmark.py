#!/usr/bin/env python3
"""Measure ICMP latency and TCP throughput from a Mininet host.

Start an iperf3 server on the destination first:
    h1 iperf3 -s -D -p 5201
Then run this from a client host:
    h2 python3 app/benchmark.py 10.0.0.1 --label baseline
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("server")
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--duration", type=int, default=5)
    p.add_argument("--port", type=int, default=5201)
    p.add_argument("--label", default="measurement")
    p.add_argument("--output", default="results/performance.csv")
    a = p.parse_args()

    ping = run(["ping", "-c", str(a.count), "-W", "2", a.server])
    ping_text = ping.stdout + ping.stderr
    match = re.search(r"rtt [^=]+ = [^/]+/([0-9.]+)/", ping_text)
    latency = float(match.group(1)) if match else None

    iperf = run(["iperf3", "-c", a.server, "-p", str(a.port),
                 "-t", str(a.duration), "-J"])
    throughput = None
    try:
        report = json.loads(iperf.stdout)
        throughput = report["end"]["sum_received"]["bits_per_second"] / 1_000_000
    except (ValueError, KeyError, TypeError):
        pass

    os.makedirs(os.path.dirname(os.path.abspath(a.output)), exist_ok=True)
    new_file = not os.path.exists(a.output)
    with open(a.output, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["timestamp", "label", "destination",
                        "avg_latency_ms", "tcp_throughput_mbps"])
        w.writerow([time.time(), a.label, a.server, latency, throughput])

    print(f"LABEL={a.label}")
    print(f"AVERAGE_LATENCY_MS={latency if latency is not None else 'unavailable'}")
    print(f"TCP_THROUGHPUT_MBPS={throughput if throughput is not None else 'unavailable'}")
    if latency is None or throughput is None:
        print("MEASUREMENTS_INCOMPLETE; check ping/iperf3 output and server status")
        return 1
    print("MEASUREMENTS_OK")
    return 0

if __name__ == "__main__":
    sys.exit(main())
