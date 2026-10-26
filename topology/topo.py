#!/usr/bin/env python3
r"""
Mininet topology for the Dynamic Host Blocking System.

                       c0 (POX, 127.0.0.1:6633)
                               |
          root-ns (10.0.0.254) |  <- path from hosts to controller's
                 \             |     control socket (port 6000)
     h1 (server) - s1 ------------------
                  /  \
                s2    s3
               / \    / \
             h2  h3  h4  h5
       (alice)(bob) (attacker)(carol)

  h1 10.0.0.1  application server
  h2 10.0.0.2  client (alice)
  h3 10.0.0.3  client (bob)
  h4 10.0.0.4  attacker
  h5 10.0.0.5  client (carol)

Run:
    sudo python3 topology/topo.py            # interactive CLI
    sudo python3 topology/topo.py --test     # automated D1 test run
"""
import argparse
import os
import sys
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))


class BlockingTopo(Topo):
    def build(self, bw=10, delay="2ms"):
        s1 = self.addSwitch("s1", protocols="OpenFlow10")
        s2 = self.addSwitch("s2", protocols="OpenFlow10")
        s3 = self.addSwitch("s3", protocols="OpenFlow10")
        hosts = {}
        for i in range(1, 6):
            hosts[i] = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24",
                                    mac=f"00:00:00:00:00:0{i}")
        link = dict(bw=bw, delay=delay)
        self.addLink(hosts[1], s1, **link)
        self.addLink(s1, s2, **link)
        self.addLink(s1, s3, **link)
        self.addLink(hosts[2], s2, **link)
        self.addLink(hosts[3], s2, **link)
        self.addLink(hosts[4], s3, **link)
        self.addLink(hosts[5], s3, **link)


def connect_root_ns(net, switch="s1", ip="10.0.0.254/24"):
    """Give the root namespace (where POX runs) an interface on the data
    network so h1's server can reach the controller's control socket."""
    root = Node("root", inNamespace=False)
    sw = net[switch]
    link = net.addLink(root, sw)
    root.setIP(ip, intf=link.intf1)
    return root  # must be called before net.start()


def run_tests(net):
    h1, h2, h3, h4, h5 = (net[f"h{i}"] for i in range(1, 6))
    py = f"cd {ROOT} && python3"
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok))
        info(f"\n*** [{'PASS' if ok else 'FAIL'}] {name} {detail}\n")

    info("\n*** T1: pingall (basic connectivity through the controller)\n")
    loss = net.pingAll(timeout=1)
    check("T1 pingall", loss == 0, f"loss={loss}%")

    info("*** T2: h1 can reach controller control socket at 10.0.0.254:6000\n")
    out = h1.cmd(f"{py} app/admin.py list --host 10.0.0.254")
    check("T2 server->controller channel", '"status": "OK"' in out, out.strip())

    info("*** starting server on h1\n")
    h1.cmd(f"{py} app/server.py --log /tmp/dhbs_server.log "
           f"> /tmp/dhbs_server.out 2>&1 &")
    time.sleep(1.5)

    info("*** T3: concurrent legitimate clients h2, h3, h5\n")
    for h, u in ((h2, "alice"), (h3, "bob"), (h5, "carol")):
        h.cmd(f"{py} app/client.py 10.0.0.1 --user {u} --password {u}123 "
              f"--count 5 > /tmp/dhbs_{h.name}.out 2>&1 &")
    time.sleep(3)
    def output_has_success(host):
        path = f"/tmp/dhbs_{host.name}.out"
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return "SUCCESS" in f.read()
        except OSError:
            return False

    ok = all(output_has_success(h) for h in (h2, h3, h5))
    check("T3 concurrent clients", ok)

    info("*** T4: attacker h4 brute-forces -> server reports -> SDN blocks\n")
    print(h4.cmd(f"{py} app/attacker.py 10.0.0.1 --mode bruteforce "
                 f"--attempts 6 --delay 0.3"))
    out = h1.cmd(f"{py} app/admin.py list --host 10.0.0.254")
    check("T4a h4 in controller blocklist", "10.0.0.4" in out)
    r = h4.cmd("ping -c 2 -W 1 10.0.0.1")
    check("T4b h4 cannot ping h1", " 0% packet loss" not in r)
    r = h4.cmd("ping -c 2 -W 1 10.0.0.5")
    check("T4c h4 isolated network-wide (h5 on same switch)",
          " 0% packet loss" not in r)
    for sw in ("s1", "s2", "s3"):
        flows = net[sw].cmd(f"ovs-ofctl dump-flows {sw}")
        check(f"T4d drop rule present on {sw}",
              "nw_src=10.0.0.4" in flows and "priority=65000" in flows)

    info("*** T5: legitimate client still works while h4 is blocked\n")
    out = h2.cmd(f"{py} app/client.py 10.0.0.1 --user alice --password alice123")
    check("T5 h2 unaffected", "SUCCESS" in out)

    info("*** T6: admin unblock restores h4\n")
    h1.cmd(f"{py} app/admin.py unblock 10.0.0.4 --host 10.0.0.254")
    time.sleep(0.5)
    r = h4.cmd("ping -c 2 -W 1 10.0.0.1")
    check("T6 h4 reachable after unblock", " 0% packet loss" in r)

    h1.cmd("pkill -f app/server.py")
    passed = sum(ok for _, ok in results)
    info(f"\n*** SUMMARY: {passed}/{len(results)} checks passed\n")
    for name, ok in results:
        info(f"    {'PASS' if ok else 'FAIL'}  {name}\n")
    return all(ok for _, ok in results)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6633)
    ap.add_argument("--test", action="store_true")
    a = ap.parse_args()

    setLogLevel("info")
    net = Mininet(topo=BlockingTopo(), switch=OVSSwitch, link=TCLink,
                  controller=None, autoSetMacs=False)
    net.addController("c0", controller=RemoteController,
                      ip=a.controller_ip, port=a.controller_port)
    root = connect_root_ns(net)
    net.start()
    info("*** root namespace reachable from hosts at 10.0.0.254\n")
    try:
        if a.test:
            time.sleep(2)  # let switches connect
            tests_passed = run_tests(net)
        else:
            CLI(net)
            tests_passed = True
    finally:
        root.cmd("ip link del root-eth0 2>/dev/null")
        net.stop()
    if a.test and not tests_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
