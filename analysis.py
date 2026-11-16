"""
analysis.py - Network Analysis module.

A StatsCollector is started by the server (and by each client). Worker threads
push records onto a queue; a background thread appends them to a CSV file and
keeps them in memory for offline review (CSV opens in Excel / pandas).

Run offline:   python analysis.py server_stats.csv [--plot]
"""

import csv
import datetime
import os
import queue
import statistics
import sys
import threading

FIELDS = ["timestamp", "side", "client", "user", "op", "filename", "bytes",
          "duration_s", "rate_MBps", "response_s", "status", "active_clients"]


class StatsCollector:
    def __init__(self, path):
        self.path = path
        self.records = []                      # in-memory copy
        self._q = queue.Queue()
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        self._fh = open(path, "a", newline="")
        self._w = csv.DictWriter(self._fh, fieldnames=FIELDS)
        if new:
            self._w.writeheader()
            self._fh.flush()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def record(self, **kw):
        """Thread-safe. Accepts any FIELDS keys; computes MB/s automatically."""
        row = {k: kw.get(k, "") for k in FIELDS}
        row["timestamp"] = row["timestamp"] or \
            datetime.datetime.now().isoformat(timespec="milliseconds")
        b, d = float(row["bytes"] or 0), float(row["duration_s"] or 0)
        row["rate_MBps"] = round(b / 1e6 / d, 3) if b > 0 and d > 0 else ""
        self._q.put(row)

    def _run(self):
        while True:
            row = self._q.get()
            if row is None:
                break
            self.records.append(row)
            self._w.writerow(row)
            self._fh.flush()

    def stop(self):
        self._q.put(None)
        self._t.join(timeout=5)
        self._fh.close()

    def summary(self):
        return summarize_rows(self.records)


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def summarize_rows(rows):
    """Per (side, op): count, avg/max MB/s, avg duration, avg response time."""
    groups = {}
    for r in rows:
        groups.setdefault((r["side"], r["op"]), []).append(r)
    lines = [f"{'side':7}{'op':20}{'n':>4}{'avgMB/s':>10}{'maxMB/s':>10}"
             f"{'avgDur(s)':>11}{'avgResp(s)':>12}{'totalMB':>10}"]
    for (side, op), rs in sorted(groups.items()):
        rates = [v for v in (_f(r["rate_MBps"]) for r in rs) if v]
        durs = [v for v in (_f(r["duration_s"]) for r in rs) if v is not None]
        resp = [v for v in (_f(r["response_s"]) for r in rs) if v is not None]
        mb = sum(_f(r["bytes"]) or 0 for r in rs) / 1e6
        avg = lambda xs: statistics.mean(xs) if xs else 0.0
        lines.append(f"{side:7}{op:20}{len(rs):>4}{avg(rates):>10.2f}"
                     f"{(max(rates) if rates else 0):>10.2f}{avg(durs):>11.3f}"
                     f"{avg(resp):>12.4f}{mb:>10.1f}")
    return "\n".join(lines)


def load_csv(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def plot(rows):
    """Optional: needs matplotlib. Saves transfer_performance.png."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    xfer = [r for r in rows if r["op"] in ("upload", "download", "resume")
            and _f(r["rate_MBps"])]
    if not xfer:
        print("No transfer records to plot.")
        return
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4))
    for op in sorted({r["op"] for r in xfer}):
        pts = [(_f(r["bytes"]) / 1e6, _f(r["duration_s"])) for r in xfer if r["op"] == op]
        a.scatter(*zip(*pts), label=op)
    a.set(xlabel="File size (MB)", ylabel="Transfer time (s)", title="Transfer time vs size")
    a.legend()
    for op in sorted({r["op"] for r in xfer}):
        pts = [(_f(r["active_clients"]) or 1, _f(r["rate_MBps"])) for r in xfer
               if r["op"] == op and r["side"] == "server"]
        if pts:
            b.scatter(*zip(*pts), label=op)
    b.set(xlabel="Active clients", ylabel="Rate (MB/s)", title="Throughput under load")
    b.legend()
    fig.tight_layout()
    fig.savefig("transfer_performance.png", dpi=150)
    print("Saved transfer_performance.png")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python analysis.py stats.csv [--plot]")
    data = load_csv(sys.argv[1])
    print(summarize_rows(data))
    if "--plot" in sys.argv:
        plot(data)