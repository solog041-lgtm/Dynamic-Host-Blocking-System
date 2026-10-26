#!/usr/bin/env python3
"""
Malicious host simulator (for testing only, inside Mininet).

    h4 python3 app/attacker.py 10.0.0.1 --mode bruteforce
    h4 python3 app/attacker.py 10.0.0.1 --mode flood --rate 50

bruteforce : tries passwords from a small list until cut off
flood      : opens many short TCP connections per second

The script prints a timeline so you can see the moment the SDN
controller blocks this host (connects start timing out).
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import LineReader, send_msg  # noqa: E402

PASSWORDS = ["123456", "password", "admin", "qwerty", "letmein",
             "alice", "welcome", "monkey", "dragon", "iloveyou"]


def bruteforce(a):
    t_start = time.time()
    for i in range(a.attempts):
        pw = PASSWORDS[i % len(PASSWORDS)]
        t = time.time() - t_start
        try:
            with socket.create_connection((a.server, a.port),
                                          timeout=a.timeout) as s:
                r = LineReader(s)
                r.read_msg()
                send_msg(s, {"type": "AUTH", "user": "alice", "password": pw})
                reply = r.read_msg()
                print(f"[attacker t={t:5.1f}s] try {i+1:2d} pw={pw!r:12} -> "
                      f"{reply['status'] if reply else 'CLOSED'}")
        except OSError as e:
            print(f"[attacker t={t:5.1f}s] try {i+1:2d} -> BLOCKED/UNREACHABLE ({e})")
        time.sleep(a.delay)


def flood(a):
    t_start = time.time()
    ok = fail = 0
    end = t_start + a.duration
    while time.time() < end:
        try:
            s = socket.create_connection((a.server, a.port), timeout=a.timeout)
            s.close()
            ok += 1
        except OSError:
            fail += 1
        if (ok + fail) % 10 == 0:
            print(f"[attacker t={time.time()-t_start:5.1f}s] "
                  f"connections ok={ok} failed={fail}")
        time.sleep(1.0 / a.rate)
    print(f"[attacker] done ok={ok} failed={fail}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--mode", choices=["bruteforce", "flood"],
                    default="bruteforce")
    ap.add_argument("--attempts", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--rate", type=float, default=50, help="flood conns/sec")
    ap.add_argument("--duration", type=float, default=5)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()
    bruteforce(a) if a.mode == "bruteforce" else flood(a)


if __name__ == "__main__":
    main()
