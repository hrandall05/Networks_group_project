"""
server.py - Multithreaded TCP file sharing server (CNT3004).

  python server.py --adduser alice          # create a user (password prompt)
  python server.py [--port 5001]            # run the server
  python server.py --tls server.crt server.key   # optional TLS encryption

One thread per client. Files are stored on disk under a logical ID
(TS001 = Text/Server #1, AS = Audio, VS = Video, OS = Other) so names never
collide; .index.json maps the user-visible name to that ID, size and SHA-256.
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
import time
import uuid

from analysis import StatsCollector
from common import (PBKDF2_ITERS, Progress, auth_response, derive_key,
                    recv_msg, recv_to_file, send_from_file, send_msg,
                    tune_socket)

STORAGE_DIR = "server_storage"
USERS_FILE = "users.json"
INDEX_FILE = ".index.json"
SERVER_SECRET = os.urandom(32)       # used to fake salts for unknown users

TYPE_MAP = {}
for _e in (".txt", ".csv", ".log", ".md", ".json"):
    TYPE_MAP[_e] = "T"
for _e in (".wav", ".mp3", ".flac", ".aac", ".ogg", ".m4a"):
    TYPE_MAP[_e] = "A"
for _e in (".mp4", ".mkv", ".avi", ".mov", ".webm"):
    TYPE_MAP[_e] = "V"


def clean_vpath(p):
    """Normalise a client-supplied virtual path and block traversal."""
    parts = [x for x in str(p).replace("\\", "/").split("/") if x not in ("", ".")]
    if any(x == ".." or x.startswith(".") for x in parts):
        raise ValueError("Invalid path")
    return "/".join(parts)


class FileStore:
    """File system + metadata index shared by all client threads."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.lock = threading.RLock()
        self.busy = {}              # vpath -> number of active downloads
        self.uploading = set()      # vpaths currently being uploaded
        self.counters = {"T": 0, "A": 0, "V": 0, "O": 0}
        self.files = {}             # vpath -> {id, stored, size, sha256}
        self.index_path = os.path.join(self.root, INDEX_FILE)
        if os.path.exists(self.index_path):
            with open(self.index_path) as fh:
                data = json.load(fh)
            self.counters.update(data.get("counters", {}))
            self.files = data.get("files", {})

    def save(self):
        tmp = self.index_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"counters": self.counters, "files": self.files}, fh, indent=1)
        os.replace(tmp, self.index_path)

    def disk_path(self, rel):
        return os.path.join(self.root, *[p for p in rel.split("/") if p])

    def new_id(self, ext):
        prefix = TYPE_MAP.get(ext.lower(), "O")
        self.counters[prefix] += 1
        return f"{prefix}S{self.counters[prefix]:03d}"

    def find(self, key):
        """Look a file up by virtual name or by logical ID (e.g. TS001)."""
        with self.lock:
            if key in self.files:
                return key
            for vp, e in self.files.items():
                if e["id"].lower() == key.lower():
                    return vp
        return None


store = None
stats = None
users_lock = threading.Lock()
active_clients = 0
clients_lock = threading.Lock()


def load_users():
    with users_lock:
        if not os.path.exists(USERS_FILE):
            return {}
        with open(USERS_FILE) as fh:
            return json.load(fh)


def add_user(name):
    pw = getpass.getpass(f"Password for {name}: ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    salt = os.urandom(16)
    users = load_users()
    users[name] = {"salt": salt.hex(), "key": derive_key(pw, salt).hex()}
    with users_lock, open(USERS_FILE, "w") as fh:
        json.dump(users, fh, indent=1)
    print(f"User '{name}' saved to {USERS_FILE}")


class Session(threading.Thread):
    """Handles one client connection."""

    def __init__(self, conn, addr, tls_ctx):
        super().__init__(daemon=True)
        self.conn, self.addr, self.tls_ctx = conn, addr, tls_ctx
        self.user = "?"
        self._t0 = self._t_first = None
        self._status, self._logged = "ok", False

    # ---- helpers
    def reply(self, obj):
        send_msg(self.conn, obj)
        self._status = obj.get("status", "ok")
        if self._t_first is None:           # response time = receipt -> first reply
            self._t_first = time.perf_counter() - self._t0

    def error(self, text):
        self.reply({"status": "error", "message": text})

    def log_op(self, op, name="", nbytes=0, duration=0.0):
        self._logged = True
        stats.record(side="server", client=f"{self.addr[0]}:{self.addr[1]}",
                     user=self.user, op=op, filename=name, bytes=nbytes,
                     duration_s=round(duration, 4),
                     response_s=round(self._t_first or 0, 4),
                     status=self._status, active_clients=active_clients)

    # ---- main loop
    def run(self):
        global active_clients
        tag = f"{self.addr[0]}:{self.addr[1]}"
        try:
            if self.tls_ctx:
                self.conn = self.tls_ctx.wrap_socket(self.conn, server_side=True)
            self.conn.settimeout(120)
            if not self.authenticate():
                return
            with clients_lock:
                active_clients += 1
            print(f"[+] {self.user} connected from {tag} (active: {active_clients})")
            while True:
                msg = recv_msg(self.conn)
                self._t0, self._t_first = time.perf_counter(), None
                self._status, self._logged = "ok", False
                cmd = msg.get("cmd")
                if cmd == "quit":
                    self.reply({"status": "ok"})
                    break
                if cmd not in ("upload", "download", "delete", "dir", "subfolder", "stats"):
                    self.error("Unknown command")
                    continue
                try:
                    getattr(self, "cmd_" + cmd)(msg)
                except ConnectionError:
                    raise
                except ValueError as e:
                    self.error(str(e))
                except KeyError as e:
                    self.error(f"Missing field {e}")
                except OSError as e:
                    self.error(f"Server file error: {e}")
                if not self._logged and cmd != "stats":
                    self.log_op(cmd, msg.get("name") or msg.get("path") or "",
                                0, time.perf_counter() - self._t0)
        except (ConnectionError, socket.timeout, ssl.SSLError) as e:
            print(f"[!] {self.user}@{tag} dropped: {e}")
        finally:
            if self.user != "?":
                with clients_lock:
                    active_clients -= 1
                print(f"[-] {self.user} disconnected (active: {active_clients})")
            try:
                self.conn.close()
            except OSError:
                pass

    # ---- authentication (challenge-response; password never on the wire)
    def authenticate(self):
        self._t0 = time.perf_counter()
        hello = recv_msg(self.conn)
        name = str(hello.get("user", ""))
        rec = load_users().get(name)
        salt = bytes.fromhex(rec["salt"]) if rec else \
            hmac.new(SERVER_SECRET, name.encode(), hashlib.sha256).digest()[:16]
        nonce = os.urandom(16)
        self.reply({"status": "challenge", "salt": salt.hex(), "nonce": nonce.hex()})
        resp = recv_msg(self.conn).get("response", "")
        ok = bool(rec) and hmac.compare_digest(
            auth_response(bytes.fromhex(rec["key"]), nonce), str(resp))
        if ok:
            self.user = name
            self.reply({"status": "ok", "message": f"Welcome {name}"})
        else:
            time.sleep(1)                                  # slow brute force
            self.error("Authentication failed")
        stats.record(side="server", client=f"{self.addr[0]}:{self.addr[1]}", user=name,
                     op="auth", status="ok" if ok else "denied",
                     response_s=round(self._t_first or 0, 4),
                     duration_s=round(time.perf_counter() - self._t0, 4),
                     active_clients=active_clients)
        return ok

    # ---- commands
    def cmd_upload(self, msg):
        vpath, size = clean_vpath(msg["name"]), int(msg["size"])
        if not vpath or size < 0:
            raise ValueError("Invalid file name or size")
        parent = vpath.rsplit("/", 1)[0] if "/" in vpath else ""
        if parent and not os.path.isdir(store.disk_path(parent)):
            return self.error("Destination folder does not exist")
        with store.lock:
            if store.busy.get(vpath) or vpath in store.uploading:
                return self.error("File is currently being processed")
            store.uploading.add(vpath)
            exists = vpath in store.files
        tmp = os.path.join(store.disk_path(parent), f".upload_{uuid.uuid4().hex}.part")
        try:
            if exists:       # ask the client whether to overwrite
                self.reply({"status": "exists", "message": f"'{vpath}' already exists"})
                if not recv_msg(self.conn).get("overwrite"):
                    return self.reply({"status": "cancelled"})
            self.reply({"status": "ready"})
            h, t1 = hashlib.sha256(), time.perf_counter()
            try:
                with open(tmp, "wb") as f:
                    recv_to_file(self.conn, f, size, hasher=h)
            except ConnectionError:
                raise
            except OSError as e:
                raise ConnectionError(f"write failed: {e}")
            dur, sha = time.perf_counter() - t1, h.hexdigest()
            with store.lock:
                entry = store.files.get(vpath)
                if entry is None:
                    ext = os.path.splitext(vpath)[1]
                    fid = store.new_id(ext)
                    entry = {"id": fid, "stored": (parent + "/" if parent else "") + fid + ext}
                os.replace(tmp, store.disk_path(entry["stored"]))
                tmp = None
                entry.update(size=size, sha256=sha)
                store.files[vpath] = entry
                store.save()
            self.reply({"status": "ok", "id": entry["id"], "size": size, "sha256": sha})
            self.log_op("upload", vpath, size, dur)
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
            with store.lock:
                store.uploading.discard(vpath)

    def cmd_download(self, msg):
        key, offset = clean_vpath(msg["name"]), int(msg.get("offset", 0))
        with store.lock:
            vpath = store.find(key)
            if vpath is None:
                return self.error("File does not exist")
            if vpath in store.uploading:
                return self.error("File is currently being processed")
            entry = dict(store.files[vpath])
            store.busy[vpath] = store.busy.get(vpath, 0) + 1
        try:
            size = entry["size"]
            if not 0 <= offset <= size:
                return self.error("Invalid resume offset")
            self.reply({"status": "ok", "name": vpath, "id": entry["id"], "size": size,
                        "offset": offset, "sha256": entry["sha256"]})
            t1 = time.perf_counter()
            try:
                with open(store.disk_path(entry["stored"]), "rb") as f:
                    f.seek(offset)                       # resume support
                    send_from_file(self.conn, f, size - offset)
            except ConnectionError:
                raise
            except OSError as e:
                raise ConnectionError(f"read failed: {e}")
            self.log_op("download" if offset == 0 else "resume", vpath,
                        size - offset, time.perf_counter() - t1)
        finally:
            with store.lock:
                store.busy[vpath] -= 1
                if store.busy[vpath] <= 0:
                    del store.busy[vpath]

    def cmd_delete(self, msg):
        key = clean_vpath(msg["name"])
        with store.lock:
            vpath = store.find(key)
            if vpath is None:
                return self.error("File does not exist")
            if store.busy.get(vpath) or vpath in store.uploading:
                return self.error("File is currently being processed")
            entry = store.files.pop(vpath)
            try:
                os.remove(store.disk_path(entry["stored"]))
            except FileNotFoundError:
                pass
            store.save()
        self.reply({"status": "ok", "message": f"Deleted {vpath}"})

    def cmd_dir(self, msg):
        p = clean_vpath(msg.get("path", ""))
        d = store.disk_path(p)
        if not os.path.isdir(d):
            return self.error("Directory does not exist")
        dirs = sorted(n for n in os.listdir(d)
                      if not n.startswith(".") and os.path.isdir(os.path.join(d, n)))
        with store.lock:
            files = [{"name": vp.rsplit("/", 1)[-1], "id": e["id"], "size": e["size"]}
                     for vp, e in store.files.items()
                     if (vp.rsplit("/", 1)[0] if "/" in vp else "") == p]
        self.reply({"status": "ok", "path": p or "/", "dirs": dirs,
                    "files": sorted(files, key=lambda x: x["name"])})

    def cmd_subfolder(self, msg):
        action, p = msg.get("action"), clean_vpath(msg["path"])
        if not p:
            raise ValueError("A folder path is required")
        d = store.disk_path(p)
        if action == "create":
            if os.path.exists(d):
                return self.error("Folder already exists")
            os.makedirs(d)
            self.reply({"status": "ok", "message": f"Created {p}"})
        elif action == "delete":
            if not os.path.isdir(d):
                return self.error("Folder does not exist")
            try:
                os.rmdir(d)
            except OSError:
                return self.error("Folder is not empty")
            self.reply({"status": "ok", "message": f"Deleted {p}"})
        else:
            raise ValueError("Use: subfolder create|delete <path>")

    def cmd_stats(self, msg):
        """Client-side measurements pushed to the server's analysis module."""
        rec = {k: v for k, v in msg.get("record", {}).items()}
        rec.update(side="client", user=self.user, client=f"{self.addr[0]}:{self.addr[1]}")
        stats.record(**rec)
        self._logged = True
        self.reply({"status": "ok"})


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    global store, stats
    ap = argparse.ArgumentParser(description="CNT3004 file server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--adduser", metavar="NAME")
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    args = ap.parse_args()
    if args.adduser:
        return add_user(args.adduser)
    if not load_users():
        raise SystemExit("No users yet. Run: python server.py --adduser <name>")

    store = FileStore(STORAGE_DIR)
    stats = StatsCollector("server_stats.csv")        # analysis module starts with server
    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*args.tls)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(32)
    print(f"Server listening on {local_ip()}:{args.port}  "
          f"(TLS {'on' if ctx else 'off'}, storage: {store.root})")
    try:
        while True:
            conn, addr = srv.accept()
            tune_socket(conn)
            Session(conn, addr, ctx).start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        print(stats.summary())
        stats.stop()
        srv.close()


if __name__ == "__main__":
    main()