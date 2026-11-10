#!/usr/bin/env python3
"""
Build a shareable HTML report (plus a CSV of every event) from monitor.py's data.

    python report.py                  # last 7 days
    python report.py --days 1         # last 24 hours
    python report.py --since 2026-11-01 --until 2026-11-09
    python report.py --open           # open the report in your browser when done
"""
from __future__ import annotations

import argparse
import csv
import html
import sqlite3
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from monitor import CAUSES, DEFAULT_DB, KINDS, PUBLIC_TARGETS, ROOT

INTERNET = "#2563eb"
ROUTER = "#9ca3af"
LOST = "#dc2626"
LAG = "#f59e0b"
MAX_DETAIL = 100  # events that get a per-second timeline


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%a %b %d %Y, %I:%M:%S %p")


def dur(s: float) -> str:
    s = round(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


def ms(v) -> str:
    return "-" if v is None else f"{v:.0f} ms"


def pct(v) -> str:
    return "-" if v is None else f"{v:.0f}%"


# --------------------------------------------------------------------------- data

def load(conn: sqlite3.Connection, since: float, until: float) -> dict:
    conn.row_factory = sqlite3.Row
    sessions = conn.execute(
        "SELECT * FROM sessions WHERE end_ts >= ? AND start_ts <= ?", (since, until)).fetchall()
    monitored = sum(max(0.0, min(s["end_ts"], until) - max(s["start_ts"], since)) for s in sessions)
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM events WHERE end_ts >= ? AND start_ts <= ? ORDER BY start_ts", (since, until))]

    stats = {}
    for r in conn.execute(
            "SELECT target, COUNT(*) n, SUM(rtt_ms IS NULL) lost FROM pings "
            "WHERE ts BETWEEN ? AND ? GROUP BY target", (since, until)):
        n_ok = r["n"] - r["lost"]

        def quantile(q: float):
            if not n_ok:
                return None
            row = conn.execute(
                "SELECT rtt_ms FROM pings WHERE target = ? AND ts BETWEEN ? AND ? "
                "AND rtt_ms IS NOT NULL ORDER BY rtt_ms LIMIT 1 OFFSET ?",
                (r["target"], since, until, min(n_ok - 1, int(n_ok * q)))).fetchone()
            return row[0]

        stats[r["target"]] = dict(n=r["n"], loss=100 * r["lost"] / r["n"],
                                  median=quantile(0.5), p99=quantile(0.99))

    wifi = conn.execute(
        "SELECT ssid, COUNT(DISTINCT bssid) aps, AVG(signal) sig, MIN(signal) min_sig FROM wifi "
        "WHERE ts BETWEEN ? AND ? AND state = 'connected' GROUP BY ssid ORDER BY COUNT(*) DESC LIMIT 1",
        (since, until)).fetchone()
    gateways = sorted({s["gateway"] for s in sessions if s["gateway"]})
    return dict(sessions=sessions, monitored=monitored, events=events, stats=stats,
                wifi=dict(wifi) if wifi else None, gateways=gateways)


def event_window(conn: sqlite3.Connection, ev: dict, pad: float = 30) -> list[tuple]:
    """Per-second (ts, best internet rtt or None, router rtt or None/'na') around an event."""
    rows = conn.execute("SELECT ts, target, rtt_ms FROM pings WHERE ts BETWEEN ? AND ? ORDER BY ts",
                        (ev["start_ts"] - pad, ev["end_ts"] + pad)).fetchall()
    by_ts: dict[float, dict] = defaultdict(dict)
    for ts, target, rtt in rows:
        by_ts[ts][target] = rtt
    out = []
    for ts, d in sorted(by_ts.items()):
        pub = [d[ip] for ip in PUBLIC_TARGETS if ip in d]
        got = [v for v in pub if v is not None]
        out.append((ts, min(got) if got else None, d.get("gateway", "na")))
    return out


# --------------------------------------------------------------------------- svg

def bar_chart(labels: list[str], series: list[tuple[str, str, list[int]]], every: int = 1) -> str:
    W, H, L, B = 720, 170, 28, 22
    n = len(labels)
    totals = [sum(s[2][i] for s in series) for i in range(n)]
    top = max(totals + [1])
    bw = (W - L) / max(n, 1)
    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img">']
    for frac in (0.5, 1.0):
        y = H - B - (H - B - 10) * frac
        parts.append(f'<line x1="{L}" x2="{W}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                     f'<text x="{L - 4}" y="{y + 4:.1f}" class="axis" text-anchor="end">{top * frac:g}</text>')
    for i in range(n):
        y0 = H - B
        for _, color, vals in series:
            h = (H - B - 10) * vals[i] / top
            if h:
                parts.append(f'<rect x="{L + i * bw + 1:.1f}" y="{y0 - h:.1f}" width="{bw - 2:.1f}" '
                             f'height="{h:.1f}" fill="{color}" rx="1.5"/>')
            y0 -= h
        if totals[i]:
            parts.append(f'<title>{esc(labels[i])}: {totals[i]}</title>')
        if i % every == 0:
            parts.append(f'<text x="{L + (i + .5) * bw:.1f}" y="{H - 6}" class="axis" '
                         f'text-anchor="middle">{esc(labels[i])}</text>')
    parts.append("</svg>")
    return "".join(parts)


def timeline(points: list[tuple], ev: dict) -> str:
    if not points:
        return '<p class="muted">No per-second data stored for this event.</p>'
    W, H = 720, 90
    lo, hi = points[0][0], points[-1][0] + 1
    span = max(hi - lo, 1)
    vals = [p[1] for p in points if p[1] is not None] + \
           [p[2] for p in points if isinstance(p[2], (int, float))]
    ymax = min(max(vals + [100]) * 1.1, 1500)

    def x(ts):
        return (ts - lo) / span * W

    def y(v):
        return H - 4 - min(v, ymax) / ymax * (H - 16)

    step = W / span
    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img">',
             f'<rect x="{x(ev["start_ts"]):.1f}" y="0" width="{max(x(ev["end_ts"]) - x(ev["start_ts"]), 2):.1f}" '
             f'height="{H}" class="window"/>']
    for ts, net, gw in points:
        if net is None:
            parts.append(f'<rect x="{x(ts):.1f}" y="8" width="{max(step - 1, 1.5):.1f}" height="{H - 12}" '
                         f'fill="{LOST}" opacity=".75"><title>{when(ts)}: internet LOST</title></rect>')
        if gw is None:
            parts.append(f'<rect x="{x(ts):.1f}" y="{H - 6}" width="{max(step - 1, 1.5):.1f}" height="6" '
                         f'fill="{LAG}"><title>{when(ts)}: router LOST</title></rect>')
    for idx, color in ((2, ROUTER), (1, INTERNET)):
        seg: list[str] = []
        for p in points:
            v = p[idx]
            if isinstance(v, (int, float)):
                seg.append(f"{x(p[0] + .5):.1f},{y(v):.1f}")
            else:
                if len(seg) > 1:
                    parts.append(f'<polyline points="{" ".join(seg)}" fill="none" stroke="{color}" stroke-width="1.6"/>')
                seg = []
        if len(seg) > 1:
            parts.append(f'<polyline points="{" ".join(seg)}" fill="none" stroke="{color}" stroke-width="1.6"/>')
    parts.append(f'<text x="4" y="11" class="axis">{ymax:.0f} ms</text>'
                 f'<text x="4" y="{H - 8}" class="axis">0</text></svg>')
    return "".join(parts)


# --------------------------------------------------------------------------- html

CSS = """
:root{--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#fff;--soft:#f9fafb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 10px;padding-top:8px;border-top:1px solid var(--line)}
.muted{color:var(--muted)}.small{font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:20px 0}
.tile{background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:24px;line-height:1.2}.tile span{font-size:13px;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;background:var(--soft)}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto}.chart{width:100%;height:auto;display:block}
.grid{stroke:var(--line)}.axis{font-size:10px;fill:var(--muted)}.window{fill:#fde68a;opacity:.45}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.outage{background:#fee2e2;color:#991b1b}.lag{background:#fef3c7;color:#92400e}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--muted);margin:6px 0}
.legend i{display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.ev{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:10px 0;break-inside:avoid}
.ev header{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline;margin-bottom:4px}
@media print{main{padding:0}h2{break-after:avoid}}
"""


def build_html(data: dict, conn: sqlite3.Connection, since: float, until: float) -> str:
    ev = data["events"]
    hours = data["monitored"] / 3600
    total_bad = sum(e["end_ts"] - e["start_ts"] for e in ev)
    outages = [e for e in ev if e["kind"] == "outage"]
    w = data["wifi"]
    gw = ", ".join(data["gateways"]) or "unknown"
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Internet Reliability Report</title><style>{CSS}</style></head><body><main>"]

    out.append("<h1>Internet Reliability Report</h1>")
    out.append(f"<p class='muted'>{esc(when(since))} &rarr; {esc(when(until))}<br>"
               f"Network: <b>{esc(w['ssid'] if w else 'unknown')}</b> &middot; router {esc(gw)} &middot; "
               f"generated {esc(when(datetime.now().timestamp()))}</p>")

    longest = max((e["end_ts"] - e["start_ts"] for e in ev), default=0)
    tiles = [
        (f"{hours:.1f} h", "actively monitored"),
        (str(len(ev)), "disruptions recorded"),
        (f"{len(ev) / hours:.1f}" if hours else "-", "disruptions per hour"),
        (str(len(outages)), "full outages (no internet)"),
        (dur(total_bad), "total time disrupted"),
        (dur(longest) if ev else "-", "longest disruption"),
    ]
    out.append("<div class='tiles'>" + "".join(f"<div class='tile'><b>{esc(a)}</b><span>{esc(b)}</span></div>"
                                                for a, b in tiles) + "</div>")

    # ---- summary sentence
    by_cause = Counter(e["cause"] for e in ev)
    if ev:
        top_cause, top_n = by_cause.most_common(1)[0]
        out.append(f"<p>During {hours:.1f} hours of monitoring the connection was disrupted "
                   f"<b>{len(ev)} times</b> ({len(outages)} complete outages, {len(ev) - len(outages)} "
                   f"severe lag spikes), for a total of <b>{dur(total_bad)}</b>. "
                   f"The most common location was <b>{esc(CAUSES[top_cause][0].lower())}</b> "
                   f"({top_n} of {len(ev)}). {esc(CAUSES[top_cause][1])}</p>")
    else:
        out.append("<p>No disruptions were recorded in this period.</p>")

    # ---- causes
    out.append("<h2>Where the problems happened</h2><div class='wrap'><table><tr><th>Location</th>"
               "<th class='n'>Events</th><th class='n'>Outages</th><th class='n'>Total time</th><th>Meaning</th></tr>")
    for cause, n in by_cause.most_common():
        sub = [e for e in ev if e["cause"] == cause]
        out.append(f"<tr><td><b>{esc(CAUSES[cause][0])}</b></td><td class='n'>{n}</td>"
                   f"<td class='n'>{sum(e['kind'] == 'outage' for e in sub)}</td>"
                   f"<td class='n'>{dur(sum(e['end_ts'] - e['start_ts'] for e in sub))}</td>"
                   f"<td class='small'>{esc(CAUSES[cause][1])}</td></tr>")
    out.append("</table></div>")

    # ---- charts
    if ev:
        legend = (f"<div class='legend'><span><i style='background:{LOST}'></i>Outage</span>"
                  f"<span><i style='background:{LAG}'></i>Lag spike</span></div>")
        days = []
        d = datetime.fromtimestamp(since).date()
        while d <= datetime.fromtimestamp(until).date():
            days.append(d)
            d += timedelta(days=1)
        per_day = {k: Counter() for k in ("outage", "lag")}
        per_hour = {k: Counter() for k in ("outage", "lag")}
        for e in ev:
            t = datetime.fromtimestamp(e["start_ts"])
            per_day[e["kind"]][t.date()] += 1
            per_hour[e["kind"]][t.hour] += 1
        if len(days) > 1:
            out.append("<h2>Disruptions per day</h2>" + legend + bar_chart(
                [f"{x:%b %d}" for x in days],
                [("Outage", LOST, [per_day["outage"][x] for x in days]),
                 ("Lag", LAG, [per_day["lag"][x] for x in days])],
                every=max(1, len(days) // 14)))
        out.append("<h2>Disruptions by time of day</h2>" + legend + bar_chart(
            [f"{h % 12 or 12}{'a' if h < 12 else 'p'}" for h in range(24)],
            [("Outage", LOST, [per_hour["outage"][h] for h in range(24)]),
             ("Lag", LAG, [per_hour["lag"][h] for h in range(24)])], every=2))

    # ---- baseline stats
    out.append("<h2>Overall connection quality</h2><p class='small muted'>All one-second probes in the period, "
               "including the disruptions. A good median with high loss or a high 99th percentile is "
               "the signature of short drops that speed tests miss.</p>"
               "<div class='wrap'><table><tr><th>Target</th><th class='n'>Probes</th><th class='n'>Packet loss</th>"
               "<th class='n'>Median latency</th><th class='n'>99th pct latency</th></tr>")
    order = ["gateway"] + list(PUBLIC_TARGETS)
    for t in sorted(data["stats"], key=lambda k: order.index(k) if k in order else 99):
        s = data["stats"][t]
        name = f"Your router ({gw})" if t == "gateway" else f"{PUBLIC_TARGETS.get(t, t)} ({t})"
        out.append(f"<tr><td>{esc(name)}</td><td class='n'>{s['n']:,}</td><td class='n'>{s['loss']:.2f}%</td>"
                   f"<td class='n'>{ms(s['median'])}</td><td class='n'>{ms(s['p99'])}</td></tr>")
    out.append("</table></div>")
    if w:
        out.append(f"<p class='small muted'>WiFi: average signal {w['sig']:.0f}% (lowest {w['min_sig']}%), "
                   f"{w['aps']} different access point(s) seen.</p>")

    # ---- event log
    out.append("<h2>Event log</h2><div class='wrap'><table><tr><th>Start</th><th class='n'>Duration</th><th>Type</th>"
               "<th>Location</th><th class='n'>Internet loss</th><th class='n'>Worst latency</th>"
               "<th class='n'>Router loss</th><th class='n'>WiFi</th></tr>")
    for e in reversed(ev):
        out.append(f"<tr><td>{esc(when(e['start_ts']))}</td><td class='n'>{dur(e['end_ts'] - e['start_ts'])}</td>"
                   f"<td><span class='pill {e['kind']}'>{KINDS[e['kind']]}</span></td>"
                   f"<td>{esc(CAUSES[e['cause']][0])}</td><td class='n'>{pct(e['internet_loss_pct'])}</td>"
                   f"<td class='n'>{ms(e['worst_rtt_ms'])}</td><td class='n'>{pct(e['gateway_loss_pct'])}</td>"
                   f"<td class='n'>{pct(e['min_signal'])}{' &#8644;' if e['roamed'] else ''}</td></tr>")
    out.append("</table></div><p class='small muted'>&#8644; = switched WiFi access point during the event. "
               "WiFi column is the lowest signal strength seen.</p>")

    # ---- per-event timelines
    if ev:
        shown = list(reversed(ev))[:MAX_DETAIL]
        out.append(f"<h2>Second-by-second detail</h2><p class='small muted'>Each chart shows 30 seconds before "
                   f"and after the event{' (most recent ' + str(MAX_DETAIL) + ')' if len(ev) > MAX_DETAIL else ''}. "
                   f"Shaded = event window.</p><div class='legend'>"
                   f"<span><i style='background:{INTERNET}'></i>Internet latency (best of {len(PUBLIC_TARGETS)} servers)</span>"
                   f"<span><i style='background:{ROUTER}'></i>Router latency</span>"
                   f"<span><i style='background:{LOST}'></i>Internet unreachable</span>"
                   f"<span><i style='background:{LAG}'></i>Router unreachable</span></div>")
        for e in shown:
            out.append(f"<div class='ev'><header><b>{esc(when(e['start_ts']))}</b>"
                       f"<span class='pill {e['kind']}'>{KINDS[e['kind']]}</span>"
                       f"<span>{dur(e['end_ts'] - e['start_ts'])}</span>"
                       f"<span class='muted'>{esc(CAUSES[e['cause']][0])}</span></header>"
                       + timeline(event_window(conn, e), e) + "</div>")

    # ---- method
    out.append("<h2>How this was measured</h2><ul class='small'>"
               f"<li>Every second, ICMP echo (ping) requests were sent in parallel to the local router and to "
               f"{len(PUBLIC_TARGETS)} independent public servers: "
               + ", ".join(f"{esc(n)} {esc(ip)}" for ip, n in PUBLIC_TARGETS.items()) +
               ". A reply slower than 1 second counts as lost.</li>"
               "<li>A second is <b>bad</b> when all public servers are unreachable, most are unreachable, or "
               "their median latency is above 150 ms. An <b>event</b> starts after 2 consecutive bad seconds "
               "and ends after 3 consecutive good seconds. It is an <b>outage</b> when at least 2 seconds had "
               "no internet at all, otherwise a <b>lag spike</b>.</li>"
               "<li>Using several unrelated servers rules out a single remote server being the problem. "
               "Pinging the router at the same moment separates local WiFi problems from problems "
               "beyond the router.</li>"
               "<li>WiFi signal, access point (BSSID) and link state were sampled every 3 seconds. "
               "Periods when the computer was asleep are excluded.</li></ul>")
    out.append("</main></body></html>")
    return "".join(out)


def write_csv(path: Path, events: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["start", "end", "duration_s", "type", "location", "internet_loss_pct",
                     "worst_latency_ms", "router_loss_pct", "router_worst_latency_ms",
                     "min_wifi_signal_pct", "switched_access_point", "network", "access_points", "router"])
        for e in events:
            wr.writerow([
                datetime.fromtimestamp(e["start_ts"]).isoformat(timespec="seconds"),
                datetime.fromtimestamp(e["end_ts"]).isoformat(timespec="seconds"),
                round(e["end_ts"] - e["start_ts"]), KINDS[e["kind"]], CAUSES[e["cause"]][0],
                e["internet_loss_pct"], e["worst_rtt_ms"], e["gateway_loss_pct"], e["gateway_worst_rtt_ms"],
                e["min_signal"], "yes" if e["roamed"] else "no", e["ssid"], e["bssids"], e["gateway"]])


def main() -> None:
    p = argparse.ArgumentParser(description="Build an HTML report from monitor.py data.")
    p.add_argument("--db", default=str(DEFAULT_DB))
    p.add_argument("--days", type=float, default=7, help="how many days back (default 7)")
    p.add_argument("--since", help="start date YYYY-MM-DD (overrides --days)")
    p.add_argument("--until", help="end date YYYY-MM-DD, inclusive (default now)")
    p.add_argument("--out", help="output HTML path (default reports/internet-report-<date>.html)")
    p.add_argument("--open", action="store_true", help="open the report in a browser")
    a = p.parse_args()

    until = (datetime.fromisoformat(a.until) + timedelta(days=1)) if a.until else datetime.now()
    since = datetime.fromisoformat(a.since) if a.since else until - timedelta(days=a.days)
    db = Path(a.db)
    if not db.exists():
        raise SystemExit(f"No data yet at {db}. Run `python monitor.py` first.")

    conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
    data = load(conn, since.timestamp(), until.timestamp())
    out = Path(a.out) if a.out else ROOT / "reports" / f"internet-report-{datetime.now():%Y-%m-%d}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(data, conn, since.timestamp(), until.timestamp()), encoding="utf-8")
    csv_path = out.with_suffix(".csv")
    write_csv(csv_path, data["events"])

    print(f"{len(data['events'])} events over {data['monitored'] / 3600:.1f} monitored hours")
    print(f"Report: {out}\nCSV:    {csv_path}")
    if a.open:
        webbrowser.open(out.resolve().as_uri())


if __name__ == "__main__":
    main()
