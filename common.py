"""
common.py - Shared protocol helpers for the CNT3004 file sharing system.

Wire format (over TCP):
  * Control messages: 4-byte big-endian length + UTF-8 JSON body.
  * File data: raw bytes streamed right after a control message that announced
    the size, in 1 MB chunks (never loading a whole file into memory).
"""

import hashlib
import hmac
import json
import socket
import struct
import time

CHUNK = 1024 * 1024            # 1 MB transfer chunk
PBKDF2_ITERS = 200_000         # password-hardening cost
MAX_HEADER = 1024 * 1024       # reject absurd control messages


# ----------------------------------------------------------------- messaging
def send_msg(sock, obj):
    """Send one JSON control message."""
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock, n):
    """Read exactly n bytes or raise ConnectionError."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock):
    """Receive one JSON control message."""
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_HEADER:
        raise ValueError("control message too large")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


def tune_socket(sock):
    """Low-latency + larger buffers for bulk transfer."""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 1 << 20)
        except OSError:
            pass


# ------------------------------------------------------------- file streaming
def send_from_file(sock, fobj, nbytes, hasher=None, progress=None):
    """Stream nbytes from an open file to the socket in CHUNK pieces."""
    sent = 0
    while sent < nbytes:
        data = fobj.read(min(CHUNK, nbytes - sent))
        if not data:
            raise ConnectionError("file ended early while sending")
        sock.sendall(data)
        if hasher:
            hasher.update(data)
        sent += len(data)
        if progress:
            progress(sent)


def recv_to_file(sock, fobj, nbytes, hasher=None, progress=None):
    """Receive exactly nbytes from the socket and write them to an open file."""
    buf = bytearray(CHUNK)
    view = memoryview(buf)
    got = 0
    while got < nbytes:
        n = sock.recv_into(view, min(CHUNK, nbytes - got))
        if n == 0:
            raise ConnectionError("connection closed during transfer")
        fobj.write(view[:n])
        if hasher:
            hasher.update(view[:n])
        got += n
        if progress:
            progress(got)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------- authentication
def derive_key(password, salt):
    """PBKDF2-HMAC-SHA256 key from the password; the password itself never
    leaves the client."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)


def auth_response(key, nonce):
    """Challenge-response proof: HMAC(key, server_nonce)."""
    return hmac.new(key, nonce, hashlib.sha256).hexdigest()


# ------------------------------------------------------------------- progress
class Progress:
    """Throttled console progress bar. Call with bytes done this session."""

    def __init__(self, label, total, start=0):
        self.label, self.total, self.start = label, total, start
        self.t0 = self.last = time.perf_counter()

    def __call__(self, done):
        now = time.perf_counter()
        finished = self.start + done >= self.total
        if now - self.last < 0.5 and not finished:
            return
        self.last = now
        pct = 100.0 if not self.total else (self.start + done) / self.total * 100
        rate = done / max(now - self.t0, 1e-9) / 1e6
        print(f"\r{self.label}: {pct:5.1f}%  {rate:8.1f} MB/s", end="", flush=True)

    def finish(self):
        print()