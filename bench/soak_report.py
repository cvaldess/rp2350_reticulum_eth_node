"""Read the overnight soak logs and answer the three questions that matter.

    python bench/soak_report.py probes     bench/logs/soak.log
    python bench/soak_report.py boards     bench/logs/bench1.log bench/logs/bench2.log
    python bench/soak_report.py collisions bench/logs/soak.log bench/logs/bench1.log bench/logs/bench2.log

`probes`     - the Pine64 log written by pine64_soak.sh: per destination, probes / packets sent and
               received / loss / RTT percentiles, every failed probe, and how the path count moved.
               By default only the segment after the last "soak start" line is counted.
`boards`     - the serial logs written by serial_soak.py: logger restarts, gaps, boot banners,
               [se050] and [WRN]/[ERR] lines, the free-heap series, and whether the LoRa rx/tx
               counters are monotonic since the last logger start. Monotonic counters are the proof
               that the board did not reboot: the [DBG] stamp is epoch time once NTP is in, not uptime.
`collisions` - for every 2-hop probe, the LoRa receptions (with size) and transmissions (announce /
               rebroadcast) of both boards inside the probe window. A lost probe whose receiver was
               transmitting at that second is the half-duplex collision, not a firmware fault.

Fetch the Pine64 log first: `scp linbox:soak.log bench/logs/soak.log`. The Pine64 clock was ~1 s
ahead of the PC on 2026-09-16; pass --skew if that changes.
"""
import argparse
import collections
import datetime as dt
import re
import sys

STAMP = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ?(.*)$")


def parse_stamp(s):
    return dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def records(path, join_continuations):
    """Yield (timestamp, text). rnprobe wraps 'Probe timed out' onto unstamped lines; those are
    glued to the record before them when join_continuations is set."""
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        m = STAMP.match(line)
        if m:
            out.append([parse_stamp(m.group(1)), m.group(2)])
        elif join_continuations and out:
            out[-1][1] += " " + line.strip()
    return [(t, r) for t, r in out]


def percentiles(values):
    v = sorted(values)
    if not v:
        return "n/a"
    return "%.0f/%.0f/%.0f/%.0f ms" % (v[0], v[len(v) // 2], v[int(len(v) * 0.95)], v[-1])


# ----------------------------------------------------------------------------------------- probes
def cmd_probes(args):
    recs = records(args.soaklog, join_continuations=True)
    starts = [i for i, (_, r) in enumerate(recs) if "soak start" in r]
    if args.all or not starts:
        seg = recs
    else:
        seg = recs[starts[-1]:]
    print("segment %s -> %s, %d records" % (seg[0][0], seg[-1][0], len(seg)))
    stats = collections.defaultdict(lambda: {"n": 0, "sent": 0, "recv": 0, "rtt": [], "bad": []})
    paths = []
    for t, r in seg:
        m = re.match(r"^probe (\w+) (.*)$", r)
        if not m:
            pm = re.search(r"paths: (\d+)", r)
            if pm:
                paths.append((t, int(pm.group(1))))
            continue
        dst, rest = m.groups()
        s = stats[dst]
        s["n"] += 1
        sr = re.search(r"Sent (\d+), received (\d+)", rest)
        if sr:
            sent, recv = int(sr.group(1)), int(sr.group(2))
        else:  # rnprobe printed nothing usable (no path, killed by timeout)
            sent, recv = 3, 0
        s["sent"] += sent
        s["recv"] += recv
        if recv != sent:
            s["bad"].append((t.strftime("%H:%M:%S"), recv, sent, rest.count("timed out"), rest[:60] if not sr else ""))
        for v, u in re.findall(r"Round-trip time is ([\d.]+) (milliseconds|seconds)", rest):
            s["rtt"].append(float(v) * (1000 if u == "seconds" else 1))
    for dst, s in stats.items():
        loss = 100.0 * (1 - s["recv"] / s["sent"]) if s["sent"] else float("nan")
        print("%s: probes=%d sent=%d recv=%d loss=%.2f%% rtt min/med/p95/max=%s"
              % (dst, s["n"], s["sent"], s["recv"], loss, percentiles(s["rtt"])))
        for when, recv, sent, timeouts, note in s["bad"]:
            print("   lost %s %d/%d timeouts=%d %s" % (when, recv, sent, timeouts, note))
    runs = []
    for t, p in paths:
        if runs and runs[-1][1] == p:
            runs[-1][2] = t
            runs[-1][3] += 1
        else:
            runs.append([t, p, t, 1])
    print("paths (from, count, to, samples):")
    for a, p, b, n in runs:
        print("   %s %d %s x%d" % (a.strftime("%H:%M"), p, b.strftime("%H:%M"), n))


# ----------------------------------------------------------------------------------------- boards
def cmd_boards(args):
    since = parse_stamp(args.since) if args.since else None
    for path in args.logs:
        print("===== %s" % path)
        recs = records(path, join_continuations=False)
        prev = None
        heap = []
        counters = []
        last_start = None
        for t, r in recs:
            if prev and (t - prev).total_seconds() > args.gap:
                print("  GAP %s -> %s (%.0f s)" % (prev.time(), t.time(), (t - prev).total_seconds()))
            prev = t
            if r.startswith("--- soak start"):
                last_start = t
                counters = []
            if (r.startswith("---") or "[clock] boot" in r or "Total flash" in r or "[se050]" in r
                    or "[WRN]" in r or "[ERR]" in r or "port error" in r):
                print("  %s %s" % (t.time(), r[:110]))
            cm = re.search(r"\[lora\] online rx=(\d+) tx=(\d+)", r)
            if cm:  # always from the logger start: this is the reboot detector
                counters.append((t, int(cm.group(1)), int(cm.group(2))))
            if since and t < since:
                continue
            hm = re.search(r"\[loop\] heap total=(\d+) free=(\d+)", r)
            if hm:
                heap.append((t, int(hm.group(2))))
        if heap:
            by_hour = collections.defaultdict(list)
            for t, h in heap:
                by_hour[t.strftime("%d %Hh")].append(h)
            print("  heap free%s: n=%d min=%d max=%d first=%d (%s) last=%d (%s)"
                  % (" since " + args.since if since else "", len(heap), min(h for _, h in heap),
                     max(h for _, h in heap), heap[0][1], heap[0][0].time(), heap[-1][1], heap[-1][0].time()))
            print("  per hour min/med/max: " + " | ".join(
                "%s %d/%d/%d" % (k, min(v), sorted(v)[len(v) // 2], max(v)) for k, v in sorted(by_hour.items())))
        if counters:
            drops = [(a, b) for a, b in zip(counters, counters[1:]) if b[1] < a[1] or b[2] < a[2]]
            print("  lora counters since logger start %s: samples=%d first=(rx %d, tx %d) last=(rx %d, tx %d) resets=%d"
                  % (last_start.time() if last_start else "?", len(counters), counters[0][1], counters[0][2],
                     counters[-1][1], counters[-1][2], len(drops)))
            for a, b in drops[:5]:
                print("     counter reset between %s (rx %d, tx %d) and %s (rx %d, tx %d)"
                      % (a[0].time(), a[1], a[2], b[0].time(), b[1], b[2]))


# ------------------------------------------------------------------------------------- collisions
def radio_events(path, tag):
    ev = []
    for t, r in records(path, join_continuations=False):
        m = re.search(r"LoRaInterface\]: rx (\d+) bytes", r)
        if m:
            ev.append((t, "%s:rx%s" % (tag, m.group(1))))
        elif "[node] announced" in r:
            ev.append((t, "%s:TX-announce" % tag))
        elif "Rebroadcasting announce" in r:
            ev.append((t, "%s:TX-rebroadcast" % tag))
    return ev


def cmd_collisions(args):
    recs = records(args.soaklog, join_continuations=True)
    starts = [i for i, (_, r) in enumerate(recs) if "soak start" in r]
    seg = recs[starts[-1]:] if starts and not args.all else recs
    skew = dt.timedelta(seconds=args.skew)
    events = sorted(radio_events(args.bench1, "b1") + radio_events(args.bench2, "b2"))
    windows = []
    prev_end = None
    for t, r in seg:
        m = re.match(r"^probe (\w+) (.*)$", r)
        if not m:
            continue
        if m.group(1).startswith(args.dst) and prev_end:
            sr = re.search(r"Sent (\d+), received (\d+)", m.group(2))
            sent, recv = (int(sr.group(1)), int(sr.group(2))) if sr else (3, 0)
            windows.append((prev_end, t, sent, recv))
        prev_end = t
    pad = dt.timedelta(seconds=2)
    ok = bad = ok_tx = bad_tx = 0
    for a, b, sent, recv in windows:
        lo, hi = a - skew - pad, b - skew + pad
        inside = [(t, e) for t, e in events if lo <= t <= hi]
        tx = any("TX" in e for _, e in inside)
        if recv == sent:
            ok += 1
            ok_tx += tx
            if not args.verbose:
                continue
        else:
            bad += 1
            bad_tx += tx
        print("%s %s -> %s %d/%d" % ("LOST" if recv != sent else "ok  ", a.time(), b.time(), recv, sent))
        for tag in ("b2", "b1"):
            print("   %s: %s" % (tag, " ".join("%s:%s" % (t.strftime("%M:%S"), e.split(":", 1)[1])
                                              for t, e in inside if e.startswith(tag))))
    print("probes to %s: ok=%d (with a TX inside the window: %d)  lost=%d (with a TX inside: %d)"
          % (args.dst, ok, ok_tx, bad, bad_tx))
    print("a lost probe is a collision when the receiver (b2 for the 132 B probe, b1 for the 84 B proof)"
          " shows a TX at the second the packet should have arrived")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probes")
    p.add_argument("soaklog")
    p.add_argument("--all", action="store_true", help="whole file, not just the last soak start")
    p.set_defaults(fn=cmd_probes)

    p = sub.add_parser("boards")
    p.add_argument("logs", nargs="+")
    p.add_argument("--since", help='"YYYY-MM-DD HH:MM:SS": heap series from here')
    p.add_argument("--gap", type=float, default=150.0, help="seconds of silence to report (default 150)")
    p.set_defaults(fn=cmd_boards)

    p = sub.add_parser("collisions")
    p.add_argument("soaklog")
    p.add_argument("bench1")
    p.add_argument("bench2")
    p.add_argument("--dst", default="46f55ff2", help="2-hop destination prefix (default 46f55ff2)")
    p.add_argument("--skew", type=float, default=1.0, help="Pine64 clock minus PC clock, seconds")
    p.add_argument("--all", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true", help="print the successful windows too")
    p.set_defaults(fn=cmd_collisions)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
