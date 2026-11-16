"""
client.py - Interactive client for the CNT3004 file server.

  python client.py [--tls server.crt]

Commands:
  connect <ip> <port>                 connect + log in
  upload <local_path> [remote_name]   (prompts if the file already exists)
  download <name_or_ID> [--drop-after-mb N]   auto-resumes a saved .part file
  delete <name_or_ID>
  dir [path]
  subfolder create|delete <path>
  stats                               local performance summary
  quit
"""

import argparse
import getpass
import hashlib
import os
import shlex
import socket
import ssl
import time

from analysis import StatsCollector
from common import (CHUNK, Progress, auth_response, derive_key, recv_msg,
                    recv_to_file, send_from_file, send_msg, sha256_file,
                    tune_socket, help as common_help)

DOWNLOAD_DIR = "downloads"


class Client:
    def __init__(self, tls_ca=None):
        self.sock = None
        self.tls_ca = tls_ca
        self.stats = StatsCollector("client_stats.csv")

    # ---- connection
    def connect(self, ip, port):
        self.close()
        raw = socket.create_connection((ip, port), timeout=10)
        tune_socket(raw)
        if self.tls_ca:
            ctx = ssl.create_default_context(cafile=self.tls_ca)
            ctx.check_hostname = False
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
            raw = ctx.wrap_socket(raw)
        raw.settimeout(60)
        self.sock = raw
        user = input("Username: ").strip()
        pw = getpass.getpass("Password: ")
        t0 = time.perf_counter()
        send_msg(self.sock, {"cmd": "hello", "user": user})
        ch = recv_msg(self.sock)
        key = derive_key(pw, bytes.fromhex(ch["salt"]))      # password stays local
        send_msg(self.sock, {"cmd": "auth",
                             "response": auth_response(key, bytes.fromhex(ch["nonce"]))})
        res = recv_msg(self.sock)
        if res["status"] != "ok":
            print("Error:", res.get("message"))
            self.close()
            return
        print(f"Connected to {ip}:{port} - {res.get('message')}")
        self.report("connect", "", 0, time.perf_counter() - t0, time.perf_counter() - t0)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def need_conn(self):
        if not self.sock:
            print("Not connected. Use: connect <ip> <port>")
            return False
        return True

    def report(self, op, name, nbytes, dur, resp, status="ok"):
        """Record locally and push to the server's analysis module."""
        rec = dict(op=op, filename=name, bytes=nbytes, duration_s=round(dur, 4),
                   response_s=round(resp, 4), status=status)
        self.stats.record(side="client", **rec)
        if self.sock and op != "connect":
            try:
                send_msg(self.sock, {"cmd": "stats", "record": rec})
                recv_msg(self.sock)
            except OSError:
                pass

    # ---- commands
    def upload(self, local, remote=None):
        if not os.path.isfile(local):
            return print("Local file not found:", local)
        size = os.path.getsize(local)
        remote = remote or os.path.basename(local)
        t0 = time.perf_counter()
        send_msg(self.sock, {"cmd": "upload", "name": remote, "size": size})
        resp = recv_msg(self.sock)
        resp_t = time.perf_counter() - t0
        if resp["status"] == "exists":
            ans = input(f"{resp['message']}. Overwrite? (y/n): ").strip().lower()
            send_msg(self.sock, {"overwrite": ans.startswith("y")})
            resp = recv_msg(self.sock)
            if resp["status"] == "cancelled":
                return print("Upload cancelled.")
        if resp["status"] != "ready":
            return print("Error:", resp.get("message"))
        h, prog, t1 = hashlib.sha256(), Progress("Uploading", size), time.perf_counter()
        try:
            with open(local, "rb") as f:
                send_from_file(self.sock, f, size, hasher=h, progress=prog)
            prog.finish()
            final = recv_msg(self.sock)
        except (OSError, KeyboardInterrupt) as e:
            self.close()
            return print(f"\nUpload interrupted ({e}). Reconnect and try again.")
        dur = time.perf_counter() - t1
        ok = final.get("sha256") == h.hexdigest()
        print(f"Uploaded as {final['id']}: {size/1e6:.1f} MB in {dur:.2f}s "
              f"({size/1e6/max(dur,1e-9):.1f} MB/s), integrity {'OK' if ok else 'MISMATCH'}")
        self.report("upload", remote, size, dur, resp_t, "ok" if ok else "hash_mismatch")

    def download(self, name, drop_after_mb=None):
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        part = os.path.join(DOWNLOAD_DIR, os.path.basename(name) + ".part")
        for attempt in range(2):
            offset = os.path.getsize(part) if os.path.exists(part) else 0
            t0 = time.perf_counter()
            send_msg(self.sock, {"cmd": "download", "name": name, "offset": offset})
            resp = recv_msg(self.sock)
            resp_t = time.perf_counter() - t0
            if resp["status"] == "error" and "offset" in resp["message"] and attempt == 0:
                print("Partial file no longer matches the server; restarting.")
                os.remove(part)
                continue
            break
        if resp["status"] != "ok":
            return print("Error:", resp.get("message"))
        size = resp["size"]
        final = os.path.join(DOWNLOAD_DIR, os.path.basename(resp["name"]))
        remaining = size - offset
        if offset:
            print(f"Resuming '{resp['name']}' from byte {offset:,} of {size:,} "
                  f"(requesting only {remaining:,} bytes)")
        limit = None if drop_after_mb is None else int(drop_after_mb * 1024 * 1024)
        p = Progress("Downloading", size, start=offset)

        def prog(done):
            p(done)
            if limit is not None and done >= limit:
                raise ConnectionAbortedError("simulated network drop")

        t1 = time.perf_counter()
        try:
            with open(part, "ab" if offset else "wb") as f:
                recv_to_file(self.sock, f, remaining, progress=prog)
        except (OSError, KeyboardInterrupt) as e:
            self.close()
            have = os.path.getsize(part)
            return print(f"\nTransfer interrupted ({e}). Kept partial file {part} "
                         f"({have:,}/{size:,} bytes).\n"
                         f"Reconnect and run 'download {name}' again to resume.")
        p.finish()
        dur = time.perf_counter() - t1
        print("Verifying SHA-256...")
        if sha256_file(part) == resp["sha256"]:
            os.replace(part, final)
            print(f"Saved {final}: received {remaining:,} bytes this session in {dur:.2f}s "
                  f"({remaining/1e6/max(dur,1e-9):.1f} MB/s). SHA-256 verified.")
            self.report("resume" if offset else "download", resp["name"], remaining, dur, resp_t)
        else:
            os.remove(part)
            print("SHA-256 MISMATCH - corrupt partial file deleted. Please download again.")
            self.report("download", resp["name"], remaining, dur, resp_t, "hash_mismatch")

    def simple(self, msg):
        t0 = time.perf_counter()
        send_msg(self.sock, msg)
        resp = recv_msg(self.sock)
        resp_t = time.perf_counter() - t0
        return resp, resp_t

    def delete(self, name):
        resp, rt = self.simple({"cmd": "delete", "name": name})
        print(resp.get("message", "ok") if resp["status"] != "error" else "Error: " + resp["message"])
        self.report("delete", name, 0, rt, rt, resp["status"])

    def dir(self, path=""):
        resp, rt = self.simple({"cmd": "dir", "path": path})
        if resp["status"] == "error":
            return print("Error:", resp["message"])
        print(f"Contents of /{'' if resp['path']=='/' else resp['path']}")
        for d in resp["dirs"]:
            print(f"  [DIR]  {d}/")
        for f in resp["files"]:
            print(f"  {f['id']:7} {f['size']/1e6:10.2f} MB  {f['name']}")
        if not resp["dirs"] and not resp["files"]:
            print("  (empty)")
        self.report("dir", path, 0, rt, rt)

    def subfolder(self, action, path):
        resp, rt = self.simple({"cmd": "subfolder", "action": action, "path": path})
        print(resp.get("message", "ok") if resp["status"] != "error" else "Error: " + resp["message"])
        self.report("subfolder_" + action, path, 0, rt, rt, resp["status"])

    # ---- command loop
    def shell(self):
        print(__doc__)
        while True:
            try:
                line = input("cloud> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            try:
                a = shlex.split(line)
            except ValueError as e:
                print("Parse error:", e)
                continue
            cmd, args = a[0].lower(), a[1:]
            try:
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "connect" and len(args) == 2:
                    self.connect(args[0], int(args[1]))
                elif cmd == "stats":
                    print(self.stats.summary())
                elif cmd in ("help", "?"):
                    common_help()
                elif cmd in ("upload", "download", "delete", "dir", "subfolder"):
                    if not self.need_conn():
                        continue
                    if cmd == "upload" and 1 <= len(args) <= 2:
                        self.upload(*args)
                    elif cmd == "download" and args:
                        drop = None
                        if "--drop-after-mb" in args:
                            i = args.index("--drop-after-mb")
                            drop = float(args[i + 1])
                        self.download(args[0], drop)
                    elif cmd == "delete" and len(args) == 1:
                        self.delete(args[0])
                    elif cmd == "dir" and len(args) <= 1:
                        self.dir(*args)
                    elif cmd == "subfolder" and len(args) == 2 and args[0] in ("create", "delete"):
                        self.subfolder(*args)
                    else:
                        print("Bad arguments. Type 'help'.")
                else:
                    print("Unknown command. Type 'help'.")
            except (OSError, ValueError, IndexError) as e:
                print(f"Error: {e}")
                if isinstance(e, OSError):
                    self.close()
        if self.sock:
            try:
                send_msg(self.sock, {"cmd": "quit"})
                recv_msg(self.sock)
            except OSError:
                pass
        self.close()
        self.stats.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tls", metavar="CERT", help="server certificate to trust")
    Client(ap.parse_args().tls).shell()