"""REPL client — connects to the REPL server in the Docker container.

Used by the API container to send code to the sandboxed REPL for execution.
Falls back to in-process execution if the socket is not available.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
from typing import Any

log = logging.getLogger(__name__)

REPL_SOCKET = os.environ.get("REPL_SOCKET", "/tmp/repl/sphinx_repl.sock")


class ReplClient:
    """Client for the REPL server socket."""

    def __init__(self, socket_path: str = REPL_SOCKET):
        self.socket_path = socket_path
        self._sock: socket.socket | None = None

    def connect(self) -> bool:
        """Connect to the REPL server. Returns True on success."""
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(self.socket_path)
            self._sock.settimeout(300)  # 5 min max for long steps
            return True
        except (FileNotFoundError, ConnectionRefusedError) as e:
            log.warning("REPL socket not available at %s: %s", self.socket_path, e)
            self._sock = None
            return False

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send(self, msg: dict) -> dict:
        """Send a message and receive the response."""
        if not self._sock:
            raise ConnectionError("Not connected to REPL server")

        payload = json.dumps(msg).encode("utf-8")
        self._sock.sendall(struct.pack("!I", len(payload)))
        self._sock.sendall(payload)

        # Read response
        header = self._recv_exact(4)
        resp_len = struct.unpack("!I", header)[0]
        raw = self._recv_exact(resp_len)
        return json.loads(raw.decode("utf-8"))

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("REPL server closed connection")
            buf += chunk
        return buf

    def init_session(self, case_id: str, task_id: int) -> dict:
        """Initialize a REPL session for a case/task."""
        return self._send({"cmd": "init", "case_id": case_id, "task_id": task_id})

    def execute(self, code: str, timeout: int = 120) -> dict[str, Any]:
        """Execute code and return the result dict."""
        return self._send({"cmd": "exec", "code": code, "timeout": timeout})

    def ping(self) -> bool:
        """Check if the REPL server is alive."""
        try:
            resp = self._send({"cmd": "ping"})
            return resp.get("pong", False)
        except Exception:
            return False

    def pcap_convert(self, case_id: str, pcap_path: str, work_dir: str | None = None) -> dict[str, Any]:
        """Run PCAP conversion pipeline (tshark + Suricata + Zeek)."""
        msg: dict[str, Any] = {"cmd": "pcap_convert", "case_id": case_id, "pcap_path": pcap_path}
        if work_dir:
            msg["work_dir"] = work_dir
        return self._send(msg)