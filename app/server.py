#!/usr/bin/env python3
"""
Multi-threaded TCP application server with a built-in intrusion detector.

* Accepts many concurrent clients (one thread per connection, capped).
* Authenticates users and serves ECHO / TIME / STATS.
* IDS watches application events:
    - repeated failed logins from one IP  (brute force)
    - too many connections from one IP     (connection flood)
  When a rule trips, the server sends a BLOCK request over a TCP socket to
  the SDN controller, which installs drop rules on every switch.
  This is the socket -> SDN integration point.

Run inside Mininet on the server host:
    h1 python3 app/server.py --config config/config.json
"""
import argparse
import json
import logging
import os
import socket
import sys
import threading
import time
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import LineReader, ProtocolError, send_msg, request  # noqa: E402

log = logging.getLogger("server")


class IDS:
    """Sliding-window detector. Thread-safe."""

    def __init__(self, cfg, reporter):
        self.cfg = cfg
        self.reporter = reporter
        self.whitelist = set(cfg["whitelist"])
        self.failed = defaultdict(deque)   # ip -> timestamps of failed AUTH
        self.conns = defaultdict(deque)    # ip -> timestamps of new connections
        self.reported = {}                 # ip -> time we asked for a block
        self.lock = threading.Lock()

    @staticmethod
    def _trim(q, window, now):
        while q and now - q[0] > window:
            q.popleft()

    def is_reported(self, ip):
        with self.lock:
            t = self.reported.get(ip)
            return t is not None and time.time() - t < self.cfg["block_duration_sec"]

    def clear_report(self, ip):
        """Allow a later detection to retry if controller blocking failed."""
        with self.lock:
            self.reported.pop(ip, None)

    def on_connect(self, ip):
        now = time.time()
        with self.lock:
            q = self.conns[ip]
            q.append(now)
            self._trim(q, self.cfg["conn_window_sec"], now)
            count = len(q)
        if count > self.cfg["max_conn_per_window"]:
            self._trigger(ip, f"connection flood: {count} conns in "
                              f"{self.cfg['conn_window_sec']}s")

    def on_auth_fail(self, ip):
        now = time.time()
        with self.lock:
            q = self.failed[ip]
            q.append(now)
            self._trim(q, self.cfg["failed_auth_window_sec"], now)
            count = len(q)
        if count >= self.cfg["max_failed_auth"]:
            self._trigger(ip, f"brute force: {count} failed logins in "
                              f"{self.cfg['failed_auth_window_sec']}s")

    def _trigger(self, ip, reason):
        if ip in self.whitelist:
            log.warning("IDS: %s tripped (%s) but is whitelisted", ip, reason)
            return
        with self.lock:
            if ip in self.reported and \
                    time.time() - self.reported[ip] < self.cfg["block_duration_sec"]:
                return  # already reported, don't spam the controller
            self.reported[ip] = time.time()
            self.failed.pop(ip, None)
            self.conns.pop(ip, None)
        log.warning("IDS ALERT %s -> %s", ip, reason)
        # report in background so a slow controller never stalls a client thread
        threading.Thread(target=self.reporter, args=(ip, reason),
                         daemon=True).start()


class AppServer:
    def __init__(self, cfg):
        self.scfg = cfg["server"]
        self.ccfg = cfg["controller"]
        self.ids = IDS(cfg["ids"], self.report_to_controller)
        self.active = 0
        self.blocked_reports = 0
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(self.scfg["max_clients"])

    # ---------- socket -> SDN integration ----------
    def report_to_controller(self, ip, reason):
        msg = {"type": "BLOCK", "token": self.ccfg["auth_token"], "ip": ip,
               "reason": reason,
               "duration": self.ids.cfg["block_duration_sec"]}
        for attempt in range(1, 4):
            try:
                reply = request(self.ccfg["control_host"],
                                self.ccfg["control_port"], msg)
                log.info("controller reply for %s: %s", ip, reply)
                if reply.get("status") == "OK":
                    with self.lock:
                        self.blocked_reports += 1
                    return
                log.error("controller rejected block request for %s: %s", ip, reply)
                break
            except (OSError, ProtocolError) as e:
                log.error("controller unreachable (try %d/3): %s", attempt, e)
                if attempt < 3:
                    time.sleep(1)
        self.ids.clear_report(ip)

    # ---------- client handling ----------
    def handle(self, conn, addr):
        ip = addr[0]
        user = None
        reader = LineReader(conn)
        conn.settimeout(self.scfg["client_timeout_sec"])
        with self.lock:
            self.active += 1
        log.info("connect %s:%d (active=%d)", ip, addr[1], self.active)
        try:
            send_msg(conn, {"status": "OK", "type": "HELLO",
                            "msg": "Jackfruit DHBS server. AUTH first."})
            while True:
                try:
                    msg = reader.read_msg()
                except ProtocolError as e:
                    # The frame cannot be safely resynchronised after malformed
                    # or oversized input; report the error and close this client.
                    try:
                        send_msg(conn, {"status": "ERR", "type": "PROTO",
                                        "msg": str(e)})
                    except OSError:
                        pass
                    break
                if msg is None:
                    break
                t = str(msg.get("type", "")).upper()

                if t == "AUTH":
                    u, p = msg.get("user"), msg.get("password")
                    if self.scfg["users"].get(u) == p:
                        user = u
                        send_msg(conn, {"status": "OK", "type": t,
                                        "msg": f"welcome {u}"})
                        log.info("%s authenticated as %s", ip, u)
                    else:
                        send_msg(conn, {"status": "ERR", "type": t,
                                        "msg": "invalid credentials"})
                        log.info("%s failed auth (user=%r)", ip, u)
                        self.ids.on_auth_fail(ip)
                        if self.ids.is_reported(ip):
                            break  # drop the attacker's session too
                elif t == "QUIT":
                    send_msg(conn, {"status": "OK", "type": t, "msg": "bye"})
                    break
                elif user is None:
                    send_msg(conn, {"status": "ERR", "type": t,
                                    "msg": "not authenticated"})
                elif t == "ECHO":
                    send_msg(conn, {"status": "OK", "type": t,
                                    "data": msg.get("data")})
                elif t == "TIME":
                    send_msg(conn, {"status": "OK", "type": t,
                                    "time": time.time()})
                elif t == "STATS":
                    with self.lock:
                        send_msg(conn, {"status": "OK", "type": t,
                                        "clients": self.active,
                                        "blocked_reports": self.blocked_reports})
                else:
                    send_msg(conn, {"status": "ERR", "type": t,
                                    "msg": "unknown command"})
        except socket.timeout:
            log.info("%s idle timeout", ip)
        except (ConnectionResetError, BrokenPipeError) as e:
            log.info("%s connection error: %s", ip, e)
        finally:
            conn.close()
            with self.lock:
                self.active -= 1
            self.slots.release()
            log.info("disconnect %s (active=%d)", ip, self.active)

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.scfg["host"], self.scfg["port"]))
        srv.listen(128)
        log.info("listening on %s:%d, controller at %s:%d",
                 self.scfg["host"], self.scfg["port"],
                 self.ccfg["control_host"], self.ccfg["control_port"])
        try:
            while True:
                conn, addr = srv.accept()
                self.ids.on_connect(addr[0])
                if not self.slots.acquire(blocking=False):
                    send_msg(conn, {"status": "ERR", "type": "BUSY",
                                    "msg": "server full"})
                    conn.close()
                    continue
                threading.Thread(target=self.handle, args=(conn, addr),
                                 daemon=True).start()
        except KeyboardInterrupt:
            log.info("shutting down")
        finally:
            srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/config.json")
    ap.add_argument("--controller", help="override controller IP")
    ap.add_argument("--log", default=None, help="also log to this file")
    a = ap.parse_args()
    handlers = [logging.StreamHandler()]
    if a.log:
        handlers.append(logging.FileHandler(a.log))
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
    with open(a.config) as f:
        cfg = json.load(f)
    if a.controller:
        cfg["controller"]["control_host"] = a.controller
    AppServer(cfg).serve()


if __name__ == "__main__":
    main()
