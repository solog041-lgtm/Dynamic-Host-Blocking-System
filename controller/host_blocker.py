"""
POX component: Dynamic Host Blocking controller.

Responsibilities
  1. L2 learning switch on every connected OpenFlow switch
     (flows installed at priority 100 with idle timeouts).
  2. A network-wide blocklist. Blocking an IP pushes high-priority
     (65000) DROP rules for its IPv4 *and* ARP traffic to ALL switches,
     with a hard timeout so blocks expire automatically.
  3. A TCP control socket (default 0.0.0.0:6000) speaking the same
     newline-JSON protocol as the app, so the application server (or an
     admin) can BLOCK / UNBLOCK / LIST hosts at runtime. This is where
     application events turn into SDN actions.

Run (from the POX directory):
    ./pox.py log.level --INFO host_blocker --config=/path/to/config.json

Copy or symlink this file into pox/ext/ first (see README).
"""
import json
import os
import socket
import threading
import time

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str

log = core.getLogger()

DROP_PRIORITY = 65000
FWD_PRIORITY = 100
FWD_IDLE_TIMEOUT = 30


def _drop_matches(ip):
    """IPv4 traffic and ARP traffic sourced from `ip`."""
    m_ip = of.ofp_match(dl_type=0x0800, nw_src=IPAddr(ip))
    m_arp = of.ofp_match(dl_type=0x0806, nw_src=IPAddr(ip))
    return [m_ip, m_arp]


class HostBlocker(object):
    def __init__(self, cfg, event_log):
        self.token = cfg["auth_token"]
        self.blocked = {}            # ip -> {reason, since, until, by}
        self.mac_to_port = {}        # dpid -> {mac: port}
        self.event_log = event_log
        core.openflow.addListeners(self)
        for ip in cfg.get("static_blocklist", []):
            self.block(ip, "static blocklist", 0, "config")

    # ------------------------------------------------------------------
    # event log (CSV) - used for testing now and performance eval in D2
    # ------------------------------------------------------------------
    def _record(self, event, ip, detail=""):
        line = f"{time.time():.6f},{event},{ip},{detail}\n"
        try:
            with open(self.event_log, "a") as f:
                f.write(line)
        except OSError as e:
            log.error("cannot write event log: %s", e)

    # ------------------------------------------------------------------
    # blocklist management (must run on the POX thread)
    # ------------------------------------------------------------------
    def _push_drop(self, conn, ip, hard_timeout):
        for m in _drop_matches(ip):
            fm = of.ofp_flow_mod(match=m, priority=DROP_PRIORITY,
                                 hard_timeout=hard_timeout)
            # no actions => drop
            conn.send(fm)

    def block(self, ip, reason, duration, by):
        IPAddr(ip)  # validates, raises on garbage
        now = time.time()
        until = now + duration if duration > 0 else None
        self.blocked[ip] = {"reason": reason, "since": now,
                            "until": until, "by": by}
        n = 0
        for conn in core.openflow.connections:
            self._push_drop(conn, ip, duration)
            n += 1
        log.warning("BLOCK %s for %s on %d switch(es) - %s (by %s)",
                    ip, f"{duration}s" if duration > 0 else "permanent",
                    n, reason, by)
        self._record("BLOCK", ip, f"{reason} | by={by} | switches={n}")
        if duration > 0:
            # keep our table in sync with the switches' hard timeout
            core.callDelayed(duration, self._expire, ip, now)
        return n

    def _expire(self, ip, since):
        entry = self.blocked.get(ip)
        if entry and entry["since"] == since:
            del self.blocked[ip]
            log.info("block on %s expired", ip)
            self._record("EXPIRE", ip)

    def unblock(self, ip):
        IPAddr(ip)
        existed = self.blocked.pop(ip, None) is not None
        for conn in core.openflow.connections:
            for m in _drop_matches(ip):
                conn.send(of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT,
                                          match=m, priority=DROP_PRIORITY))
        log.warning("UNBLOCK %s (was blocked: %s)", ip, existed)
        self._record("UNBLOCK", ip)
        return existed

    # ------------------------------------------------------------------
    # OpenFlow events
    # ------------------------------------------------------------------
    def _handle_ConnectionUp(self, event):
        log.info("switch %s connected", dpid_to_str(event.dpid))
        self.mac_to_port[event.dpid] = {}
        # re-apply active blocks to a (re)connecting switch
        now = time.time()
        for ip, e in self.blocked.items():
            left = 0 if e["until"] is None else max(1, int(e["until"] - now))
            self._push_drop(event.connection, ip, left)

    def _handle_ConnectionDown(self, event):
        log.info("switch %s disconnected", dpid_to_str(event.dpid))
        self.mac_to_port.pop(event.dpid, None)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        dpid = event.dpid
        table = self.mac_to_port.setdefault(dpid, {})

        # Safety net: a blocked host's packet reached us (e.g. race with
        # flow install). Drop it and re-push the rule.
        ip_pkt = packet.find("ipv4")
        arp_pkt = packet.find("arp")
        src_ip = None
        if ip_pkt is not None:
            src_ip = str(ip_pkt.srcip)
        elif arp_pkt is not None:
            src_ip = str(arp_pkt.protosrc)
        if src_ip in self.blocked:
            e = self.blocked[src_ip]
            left = 0 if e["until"] is None else max(1, int(e["until"] - time.time()))
            self._push_drop(event.connection, src_ip, left)
            self._record("DROP_PACKETIN", src_ip, dpid_to_str(dpid))
            return

        # --- L2 learning switch ---
        table[packet.src] = event.port
        if packet.dst.is_multicast or packet.dst not in table:
            msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            return

        out_port = table[packet.dst]
        if out_port == event.port:
            return  # would loop back, drop
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match(dl_dst=packet.dst, in_port=event.port)
        fm.priority = FWD_PRIORITY
        fm.idle_timeout = FWD_IDLE_TIMEOUT
        fm.actions.append(of.ofp_action_output(port=out_port))
        fm.data = event.ofp  # forward the triggering packet too
        event.connection.send(fm)

    # ------------------------------------------------------------------
    # Control-channel request handling (called on the POX thread)
    # ------------------------------------------------------------------
    def handle_request(self, msg, peer):
        if msg.get("token") != self.token:
            log.warning("control request from %s with bad token", peer)
            return {"status": "ERR", "msg": "unauthorized"}
        t = str(msg.get("type", "")).upper()
        try:
            if t == "BLOCK":
                n = self.block(msg["ip"], msg.get("reason", "unspecified"),
                               int(msg.get("duration", 60)), peer)
                return {"status": "OK", "type": t, "ip": msg["ip"],
                        "switches": n}
            if t == "UNBLOCK":
                existed = self.unblock(msg["ip"])
                return {"status": "OK", "type": t, "ip": msg["ip"],
                        "was_blocked": existed}
            if t == "LIST":
                return {"status": "OK", "type": t, "blocked": self.blocked,
                        "switches": [dpid_to_str(c.dpid)
                                     for c in core.openflow.connections]}
            return {"status": "ERR", "msg": f"unknown command {t}"}
        except (KeyError, ValueError, RuntimeError, OSError) as e:
            return {"status": "ERR", "msg": f"bad request: {e}"}


class ControlServer(threading.Thread):
    """Threaded TCP server; hands each request to the POX thread."""

    def __init__(self, blocker, host, port):
        super().__init__(daemon=True)
        self.blocker, self.host, self.port = blocker, host, port

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(32)
        log.info("control socket listening on %s:%d", self.host, self.port)
        while core.running:
            conn, addr = srv.accept()
            threading.Thread(target=self._serve, args=(conn, addr),
                             daemon=True).start()

    def _serve(self, conn, addr):
        peer = addr[0]
        conn.settimeout(10)
        buf = b""
        try:
            while b"\n" not in buf and len(buf) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            try:
                msg = json.loads(buf.split(b"\n", 1)[0].decode())
                assert isinstance(msg, dict)
            except Exception:
                reply = {"status": "ERR", "msg": "bad json"}
            else:
                # run on POX's cooperative thread and wait for the result
                done = threading.Event()
                box = {}

                def job():
                    try:
                        box["r"] = self.blocker.handle_request(msg, peer)
                    except Exception as e:  # never kill the POX loop
                        log.exception("control request failed")
                        box["r"] = {"status": "ERR", "msg": str(e)}
                    done.set()
                core.callLater(job)
                reply = box["r"] if done.wait(5) else \
                    {"status": "ERR", "msg": "controller busy"}
            conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError as e:
            log.debug("control conn %s error: %s", peer, e)
        finally:
            conn.close()


def launch(config=None, port=None, bind="0.0.0.0", event_log="events.csv"):
    if config is None:
        here = os.path.dirname(os.path.abspath(__file__))
        config = os.path.join(here, "..", "config", "config.json")
    with open(config) as f:
        cfg = json.load(f)["controller"]
    port = int(port or cfg.get("control_port", 6000))

    def start():
        blocker = HostBlocker(cfg, event_log)
        core.register("host_blocker", blocker)
        ControlServer(blocker, bind, port).start()

    core.call_when_ready(start, "openflow")
