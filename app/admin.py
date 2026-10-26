#!/usr/bin/env python3
"""
Admin CLI for the controller's control socket.

    python3 app/admin.py list
    python3 app/admin.py block 10.0.0.5 --duration 120 --reason manual
    python3 app/admin.py unblock 10.0.0.5

Run from the root namespace (controller at 127.0.0.1) or from a Mininet
host (controller at 10.0.0.254, use --host).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import request  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["list", "block", "unblock"])
    ap.add_argument("ip", nargs="?")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--duration", type=int, default=60, help="0 = permanent")
    ap.add_argument("--reason", default="manual block by admin")
    ap.add_argument("--config", default=os.path.join(HERE, "..", "config",
                                                     "config.json"))
    a = ap.parse_args()
    with open(a.config) as f:
        token = json.load(f)["controller"]["auth_token"]

    msg = {"type": a.cmd.upper(), "token": token}
    if a.cmd != "list":
        if not a.ip:
            ap.error("ip required")
        msg["ip"] = a.ip
    if a.cmd == "block":
        msg.update(duration=a.duration, reason=a.reason)
    print(json.dumps(request(a.host, a.port, msg), indent=2))


if __name__ == "__main__":
    main()
