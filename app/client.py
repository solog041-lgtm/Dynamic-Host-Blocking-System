#!/usr/bin/env python3
"""
Legitimate TCP client.

    h2 python3 app/client.py 10.0.0.1 --user alice --password alice123
    h2 python3 app/client.py 10.0.0.1 --user bob --password bob123 -i   # interactive

Non-interactive mode logs in, runs ECHO/TIME/STATS, measures round-trip
time and exits with code 0 on success, 1 on failure (handy for tests).
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import LineReader, send_msg  # noqa: E402


def call(sock, reader, msg):
    send_msg(sock, msg)
    return reader.read_msg()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--user", default="alice")
    ap.add_argument("--password", default="alice123")
    ap.add_argument("--count", type=int, default=3, help="ECHO round trips")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("-i", "--interactive", action="store_true")
    a = ap.parse_args()

    try:
        sock = socket.create_connection((a.server, a.port), timeout=a.timeout)
    except OSError as e:
        print(f"[client] CONNECT FAILED: {e}")
        return 1
    reader = LineReader(sock)
    try:
        print("[client]", reader.read_msg())
        r = call(sock, reader, {"type": "AUTH", "user": a.user,
                                "password": a.password})
        print("[client] AUTH ->", r)
        if not r or r["status"] != "OK":
            return 1

        if a.interactive:
            print("commands: echo <text> | time | stats | quit")
            while True:
                line = input("> ").strip()
                if not line:
                    continue
                cmd, _, rest = line.partition(" ")
                r = call(sock, reader, {"type": cmd.upper(), "data": rest})
                print(r)
                if cmd.lower() == "quit":
                    break
            return 0

        rtts = []
        for i in range(a.count):
            t0 = time.perf_counter()
            r = call(sock, reader, {"type": "ECHO", "data": f"hello-{i}"})
            rtts.append((time.perf_counter() - t0) * 1000)
            assert r["status"] == "OK" and r["data"] == f"hello-{i}"
        print("[client] TIME ->", call(sock, reader, {"type": "TIME"}))
        print("[client] STATS ->", call(sock, reader, {"type": "STATS"}))
        call(sock, reader, {"type": "QUIT"})
        print(f"[client] SUCCESS  echo RTT avg={sum(rtts)/len(rtts):.2f} ms "
              f"min={min(rtts):.2f} max={max(rtts):.2f}")
        return 0
    except (OSError, AssertionError, TypeError) as e:
        print(f"[client] FAILED: {e!r}")
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
