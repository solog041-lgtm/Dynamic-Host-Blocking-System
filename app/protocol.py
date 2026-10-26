"""
Application-level protocol shared by the server, clients and the controller
control channel.

Framing : one JSON object per line ("\n"-delimited), UTF-8, over TCP.
Requests: {"type": "<TYPE>", ...fields}
Replies : {"status": "OK" | "ERR", "type": "<TYPE>", ...fields}

Client <-> Server (port 5000)
    AUTH  {user, password}      -> OK / ERR (failed auth is counted by the IDS)
    ECHO  {data}                -> OK {data}
    TIME                        -> OK {time}
    STATS                       -> OK {clients, blocked_reports}
    QUIT                        -> OK, connection closed

Server/Admin <-> Controller (port 6000)
    BLOCK   {token, ip, reason, duration} -> OK / ERR
    UNBLOCK {token, ip}                   -> OK / ERR
    LIST    {token}                       -> OK {blocked: {ip: {...}}}
"""
import json
import socket

MAX_LINE = 64 * 1024  # protect against oversized/garbage input


class ProtocolError(Exception):
    pass


def encode(msg: dict) -> bytes:
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def send_msg(sock: socket.socket, msg: dict) -> None:
    sock.sendall(encode(msg))


class LineReader:
    """Buffered reader that splits a TCP byte stream into JSON messages.

    TCP is a stream, so one recv() may hold half a message or several
    messages; this class handles both cases.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def read_msg(self):
        """Return the next decoded message, or None when the peer closed."""
        while b"\n" not in self.buf:
            if len(self.buf) > MAX_LINE:
                self.buf = b""
                raise ProtocolError("line too long")
            chunk = self.sock.recv(4096)
            if not chunk:
                if self.buf:
                    self.buf = b""
                    raise ProtocolError("unterminated message")
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        if len(line) > MAX_LINE:
            raise ProtocolError("line too long")
        try:
            msg = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ProtocolError(f"bad json: {e}")
        if not isinstance(msg, dict) or "type" not in msg and "status" not in msg:
            raise ProtocolError("message must be an object with 'type'")
        return msg


def request(host: str, port: int, msg: dict, timeout: float = 5.0) -> dict:
    """One-shot request/response helper (used by server->controller, admin)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        send_msg(s, msg)
        reply = LineReader(s).read_msg()
        if reply is None:
            raise ProtocolError("connection closed without reply")
        return reply
