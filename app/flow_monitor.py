#!/usr/bin/env python3
"""Print OpenFlow 1.0 flow tables for the project's Mininet switches."""
import argparse
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser(description="Inspect OVS flow tables")
    parser.add_argument("--switches", nargs="+", default=["s1", "s2", "s3"])
    args = parser.parse_args()
    failed = False
    for switch in args.switches:
        print(f"\n===== {switch}: OpenFlow flow table =====")
        result = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow10", "dump-flows", switch],
            text=True, capture_output=True
        )
        if result.returncode:
            failed = True
            print(result.stderr.strip() or f"Unable to inspect {switch}")
        else:
            print(result.stdout.strip() or "(empty flow table)")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
