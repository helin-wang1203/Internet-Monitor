#!/usr/bin/env python3
"""
Internet Monitor - records short internet drops and lag spikes.

Every second it pings your router (default gateway) and several public servers
in parallel, samples WiFi state (signal, access point, link rate), and stores it
all in SQLite. When the connection goes bad for a couple of seconds it records an
*event* and classifies where the problem was:

  * local     - the router was also unreachable/slow  -> WiFi / router problem
  * wifi_roam - the laptop switched WiFi access points during the event
  * wifi_disconnect - the WiFi connection itself dropped
  * upstream  - router fine, internet not             -> provider's side

Run:   python monitor.py        (Ctrl+C to stop)
Then:  python report.py         (HTML report + CSV you can send to your provider)

Standard library only. On Windows it uses the built-in ICMP API (no admin needed).
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import re
import socket
import sqlite3
import statistics
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "monitor.db"

PUBLIC_TARGETS = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google", "9.9.9.9": "Quad9"}

CAUSES = {
    "upstream": (
        "Upstream / provider network",
        "The router answered normally while the internet did not, so the fault "
        "was beyond the router - on the provider's side.",
    ),
    "local": (
        "Local network (WiFi / router)",
        "The router itself was unreachable or slow at the same time, so the fault "
        "was between this computer and the router (WiFi link, access point, or router).",
    ),
    "wifi_roam": (
        "WiFi access-point switch",
        "The computer switched to a different WiFi access point (BSSID) during the "
        "event. Roaming between access points can cause multi-second stalls.",
    ),
    "wifi_disconnect": (
        "WiFi disconnected",
        "The computer's WiFi connection dropped entirely during the event.",
    ),
    "unknown": (
        "Unclassified",
        "The router address was unknown at the time, so the location of the fault "
        "could not be determined.",
    ),
}
KINDS = {"outage": "Outage", "lag": "Lag spike"}

GAP_SECONDS = 10    # a pause longer than this means the PC slept/hibernated
GRACE_SECONDS = 30  # ignore events right after waking while WiFi reconnects

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: no console flashes


def _run(cmd: list[str], timeout: float) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout, creationflags=NO_WINDOW,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------- ping

if IS_WINDOWS:
    from ctypes import wintypes as wt

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                    ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                    ("OptionsData", ctypes.c_void_p)]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [("Address", wt.ULONG), ("Status", wt.ULONG),
                    ("RoundTripTime", wt.ULONG), ("DataSize", wt.USHORT),
                    ("Reserved", wt.USHORT), ("Data", ctypes.c_void_p),
                    ("Options", _IP_OPTION_INFORMATION)]

    _iphlp = ctypes.WinDLL("iphlpapi.dll")
    _iphlp.IcmpCreateFile.restype = wt.HANDLE
    _iphlp.IcmpCloseHandle.argtypes = [wt.HANDLE]
    _iphlp.IcmpSendEcho.argtypes = [wt.HANDLE, wt.ULONG, ctypes.c_char_p, wt.WORD,
                                    ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, wt.DWORD]
    _iphlp.IcmpSendEcho.restype = wt.DWORD
    _PAYLOAD = b"internet-monitor".ljust(32, b".")

    def ping(ip: str, timeout_ms: int) -> float | None:
        """Round-trip time in ms, or None if the packet was lost."""
        addr = struct.unpack("=I", socket.inet_aton(ip))[0]
        buf = ctypes.create_string_buffer(ctypes.sizeof(_ICMP_ECHO_REPLY) + len(_PAYLOAD) + 8)
        handle = _iphlp.IcmpCreateFile()
        try:
            start = time.perf_counter()
            n = _iphlp.IcmpSendEcho(handle, addr, _PAYLOAD, len(_PAYLOAD), None,
                                    buf, len(buf), timeout_ms)
            elapsed = (time.perf_counter() - start) * 1000
        finally:
            _iphlp.IcmpCloseHandle(handle)
        if n == 0:
            return None
        reply = _ICMP_ECHO_REPLY.from_buffer(buf)
        if reply.Status != 0:
            return None
        # The API reports whole ms (0 for sub-ms); use our timer when finer.
        return round(float(reply.RoundTripTime) if reply.RoundTripTime else min(elapsed, 1.0), 1)
else:
    def ping(ip: str, timeout_ms: int) -> float | None:
        wait = str(max(1, round(timeout_ms / 1000)))
        out = _run(["ping", "-c", "1", "-W", wait, ip], timeout_ms / 1000 + 2)
        m = re.search(r"time[=<]([\d.]+)", out)
        return float(m.group(1)) if m else None


def detect_gateway() -> str | None:
    """The router address that internet traffic actually goes through."""
    if IS_WINDOWS:
        out = _run(["powershell", "-NoProfile", "-Command",
                    "Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where-Object NextHop "
                    "| Select-Object -ExpandProperty NextHop"], 20)
        for line in out.splitlines():
            ip = line.strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and ip != "0.0.0.0":
                return ip
        return None
    m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "route", "get", "8.8.8.8"], 5))
    return m.group(1) if m else None


# --------------------------------------------------------------------------- wifi

@dataclass(frozen=True)
class WifiState:
    state: str
    ssid: str | None = None
    bssid: str | None = None
    signal: int | None = None      # percent, as Windows reports it
    channel: str | None = None
    rx_mbps: float | None = None
    tx_mbps: float | None = None


def read_wifi() -> WifiState | None:
    """Current WiFi state via `netsh wlan show interfaces` (Windows only)."""
    if not IS_WINDOWS:
        return None
    fields: dict[str, str] = {}
    for line in _run(["netsh", "wlan", "show", "interfaces"], 5).splitlines():
        key, sep, val = line.partition(" : ")
        if not sep:
            continue
        key = key.strip().lower()
        if key in fields:  # second adapter starts - keep only the first
            break
        fields[key] = val.strip()
    if "state" not in fields:
        return None

    def num(key: str) -> float | None:
        m = re.match(r"[\d.]+", fields.get(key, ""))
        return float(m.group()) if m else None

    signal = num("signal")
    return WifiState(
        state=fields["state"].lower(),
        ssid=fields.get("ssid"),
        bssid=fields.get("ap bssid") or fields.get("bssid"),
        signal=int(signal) if signal is not None else None,
        channel=fields.get("channel"),
        rx_mbps=num("receive rate (mbps)"),
        tx_mbps=num("transmit rate (mbps)"),
    )


# --------------------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS pings (ts REAL NOT NULL, target TEXT NOT NULL, rtt_ms REAL);
CREATE INDEX IF NOT EXISTS pings_ts ON pings(ts);
CREATE TABLE IF NOT EXISTS wifi (
    ts REAL NOT NULL, state TEXT, ssid TEXT, bssid TEXT, signal INTEGER,
    channel TEXT, rx_mbps REAL, tx_mbps REAL);
CREATE INDEX IF NOT EXISTS wifi_ts ON wifi(ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, start_ts REAL NOT NULL, end_ts REAL NOT NULL,
    kind TEXT NOT NULL, cause TEXT NOT NULL,
    internet_loss_pct REAL, worst_rtt_ms REAL,
    gateway_loss_pct REAL, gateway_worst_rtt_ms REAL,
    min_signal INTEGER, roamed INTEGER, ssid TEXT, bssids TEXT, gateway TEXT);
CREATE INDEX IF NOT EXISTS events_start ON events(start_ts);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY, start_ts REAL NOT NULL, end_ts REAL NOT NULL,
    gateway TEXT, host TEXT);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")  # lets report.py read while we write
        self.conn.executescript(SCHEMA)
        self.pings: list[tuple] = []
        self.wifi: list[tuple] = []
        self.session_id: int | None = None

    def start_session(self, ts: float, gateway: str | None) -> None:
        cur = self.conn.execute(
            "INSERT INTO sessions (start_ts, end_ts, gateway, host) VALUES (?, ?, ?, ?)",
            (ts, ts, gateway, socket.gethostname()))
        self.session_id = cur.lastrowid
        self.conn.commit()

    def add_event(self, row: dict) -> None:
        cols = ", ".join(row)
        self.conn.execute(f"INSERT INTO events ({cols}) VALUES ({', '.join('?' * len(row))})",
                          tuple(row.values()))
        self.conn.commit()

    def flush(self, now: float) -> None:
        self.conn.executemany("INSERT INTO pings VALUES (?, ?, ?)", self.pings)
        self.conn.executemany("INSERT INTO wifi VALUES (?, ?, ?, ?, ?, ?, ?, ?)", self.wifi)
        self.conn.execute("UPDATE sessions SET end_ts = ? WHERE id = ?", (now, self.session_id))
        self.conn.commit()
        self.pings.clear()
        self.wifi.clear()


# --------------------------------------------------------------------------- monitor

@dataclass
class Tick:
    ts: float
    public: dict[str, float | None]
    gw_known: bool
    gw_rtt: float | None
    gw_bad: bool
    status: str  # good | lag | down
    wifi: WifiState | None


def fmt_ms(v: float | None) -> str:
    return "LOST" if v is None else f"{v:.0f}ms"


class Monitor:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.store = Store(Path(args.db))
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.stop = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=len(PUBLIC_TARGETS) + 1)
        self.gateway = args.gateway or detect_gateway()
        self.wifi: WifiState | None = read_wifi()
        self.wifi_recent: collections.deque = collections.deque(maxlen=400)
        self.pending: list[Tick] = []      # bad ticks not yet long enough to be an event
        self.event: list[Tick] | None = None
        self.good_streak = 0
        self.event_count = 0

    # ---- output
    def say(self, msg: str) -> None:
        with self.print_lock:
            clear = "" if self.args.quiet else "\r" + " " * 110 + "\r"
            print(f"{clear}[{datetime.now():%H:%M:%S}] {msg}", flush=True)

    def status_line(self, t: Tick) -> None:
        if self.args.quiet:
            return
        parts = [f"router {fmt_ms(t.gw_rtt)}" if t.gw_known else "router ?"]
        parts += [f"{ip} {fmt_ms(v)}" for ip, v in t.public.items()]
        w = t.wifi
        if w:
            parts.append(f"WiFi {w.signal}% ch{w.channel}" if w.state == "connected" else f"WiFi {w.state}")
        state = {"good": "ok  ", "lag": "LAG ", "down": "DOWN"}[t.status]
        if self.event is not None:
            state = "*EVT"
        line = f"{datetime.fromtimestamp(t.ts):%H:%M:%S} {state} | " + " | ".join(parts)
        line += f" | events: {self.event_count}"
        with self.print_lock:
            print("\r" + line.ljust(110), end="", flush=True)

    # ---- wifi sampler thread
    def wifi_loop(self) -> None:
        last_key = (self.wifi.state, self.wifi.bssid) if self.wifi else None
        last_gw_check = time.time()
        while not self.stop.wait(self.args.wifi_interval):
            w = read_wifi()
            now = time.time()
            if w:
                with self.lock:
                    self.wifi = w
                    self.wifi_recent.append((now, w))
                    self.store.wifi.append((now, w.state, w.ssid, w.bssid, w.signal,
                                            w.channel, w.rx_mbps, w.tx_mbps))
                key = (w.state, w.bssid)
                changed = last_key is not None and key != last_key
                if changed:
                    if w.state == "connected" and last_key[0] == "connected":
                        self.say(f"WiFi switched access point {last_key[1]} -> {w.bssid} (signal {w.signal}%)")
                    else:
                        self.say(f"WiFi state: {last_key[0]} -> {w.state}")
                last_key = key
            else:
                changed = False
            if not self.args.gateway and ((changed and w and w.state == "connected")
                                          or now - last_gw_check > 300):
                last_gw_check = now
                gw = detect_gateway()
                if gw and gw != self.gateway:
                    self.say(f"Router address is now {gw} (was {self.gateway})")
                    self.gateway = gw

    # ---- event detection
    def make_tick(self, ts: float, public: dict, gw_known: bool, gw_rtt: float | None) -> Tick:
        ok = [v for v in public.values() if v is not None]
        if not ok:
            status = "down"
        elif len(ok) * 2 < len(public) or statistics.median(ok) > self.args.lag_ms:
            status = "lag"
        else:
            status = "good"
        gw_bad = gw_known and (gw_rtt is None or gw_rtt > self.args.gw_lag_ms)
        with self.lock:
            wifi = self.wifi
        return Tick(ts, public, gw_known, gw_rtt, gw_bad, status, wifi)

    def on_tick(self, t: Tick) -> None:
        bad = t.status != "good"
        if self.event is None:
            if not bad:
                self.pending.clear()
                return
            self.pending.append(t)
            if len(self.pending) >= self.args.min_bad:
                self.event, self.pending, self.good_streak = self.pending, [], 0
                self.event_count += 1
                self.say(f"Problem started: internet {t.status.upper()}"
                         + (f", router {fmt_ms(t.gw_rtt)}" if t.gw_known else ""))
            return
        self.event.append(t)
        self.good_streak = 0 if bad else self.good_streak + 1
        if self.good_streak >= self.args.recover:
            self.close_event()

    def close_event(self) -> None:
        ticks = self.event[: len(self.event) - self.good_streak] if self.event else []
        self.event, self.good_streak = None, 0
        if not ticks:
            return
        start, end = ticks[0].ts, ticks[-1].ts + self.args.interval

        pub = [v for t in ticks for v in t.public.values()]
        got = [v for v in pub if v is not None]
        gw = [t.gw_rtt for t in ticks if t.gw_known]
        gw_got = [v for v in gw if v is not None]
        signals = [t.wifi.signal for t in ticks if t.wifi and t.wifi.signal is not None]

        with self.lock:
            nearby = [w for ts, w in self.wifi_recent if start - 10 <= ts <= end + 3]
        nearby += [t.wifi for t in ticks if t.wifi]
        bssids = sorted({w.bssid for w in nearby if w.bssid})
        disconnected = any(w.state != "connected" for w in nearby)
        roamed = len(bssids) > 1

        if disconnected:
            cause = "wifi_disconnect"
        elif roamed:
            cause = "wifi_roam"
        elif not gw:
            cause = "unknown"
        elif sum(t.gw_bad for t in ticks) * 2 >= len(ticks):
            cause = "local"
        else:
            cause = "upstream"

        kind = "outage" if sum(t.status == "down" for t in ticks) >= 2 else "lag"
        ssid = next((w.ssid for w in reversed(nearby) if w.ssid), None)
        row = dict(
            start_ts=start, end_ts=end, kind=kind, cause=cause,
            internet_loss_pct=round(100 * (len(pub) - len(got)) / len(pub), 1),
            worst_rtt_ms=max(got) if got else None,
            gateway_loss_pct=round(100 * (len(gw) - len(gw_got)) / len(gw), 1) if gw else None,
            gateway_worst_rtt_ms=max(gw_got) if gw_got else None,
            min_signal=min(signals) if signals else None,
            roamed=int(roamed), ssid=ssid, bssids=", ".join(bssids), gateway=self.gateway,
        )
        self.store.add_event(row)
        router = (f"router loss {row['gateway_loss_pct']:.0f}%" if gw else "router unknown")
        self.say(f"{KINDS[kind].upper()} {end - start:.0f}s - {CAUSES[cause][0]} | "
                 f"internet loss {row['internet_loss_pct']:.0f}%, worst {fmt_ms(row['worst_rtt_ms'])}, "
                 f"{router}" + (f", WiFi {min(signals)}%" if signals else ""))

    # ---- main loop
    def run(self) -> None:
        a = self.args
        self.say(f"Monitoring. Router: {self.gateway or 'unknown'} | targets: "
                 + ", ".join(f"{n} {ip}" for ip, n in PUBLIC_TARGETS.items())
                 + (f" | WiFi: {self.wifi.ssid} ({self.wifi.signal}%)" if self.wifi and self.wifi.ssid else ""))
        self.say(f"Event = {a.min_bad}+ s of loss or latency > {a.lag_ms:.0f} ms; "
                 f"ends after {a.recover} good s. Data: {a.db}. Ctrl+C to stop.")
        now = time.time()
        self.store.start_session(now, self.gateway)
        threading.Thread(target=self.wifi_loop, daemon=True).start()

        next_t, last_ts, last_flush, grace_until = now, now, now, 0.0
        try:
            while True:
                ts = time.time()
                if ts - last_ts > GAP_SECONDS:
                    self.say(f"No samples for {ts - last_ts:.0f}s (PC asleep?). "
                             f"Ignoring the next {GRACE_SECONDS}s while WiFi reconnects.")
                    self.pending, self.event = [], None
                    with self.lock:
                        self.store.flush(last_ts)
                    self.store.start_session(ts, self.gateway)
                    grace_until = ts + GRACE_SECONDS
                last_ts = ts

                gateway = self.gateway
                jobs = {ip: self.pool.submit(ping, ip, a.timeout_ms) for ip in PUBLIC_TARGETS}
                gw_job = self.pool.submit(ping, gateway, a.timeout_ms) if gateway else None
                public = {ip: j.result() for ip, j in jobs.items()}
                gw_rtt = gw_job.result() if gw_job else None

                self.store.pings.extend((ts, ip, v) for ip, v in public.items())
                if gateway:
                    self.store.pings.append((ts, "gateway", gw_rtt))

                tick = self.make_tick(ts, public, gateway is not None, gw_rtt)
                if ts >= grace_until:
                    self.on_tick(tick)
                self.status_line(tick)

                if ts - last_flush >= 5:
                    with self.lock:
                        self.store.flush(ts)
                    last_flush = ts

                next_t += a.interval
                delay = next_t - time.time()
                if delay > 0:
                    time.sleep(delay)
                else:
                    next_t = time.time()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            if self.event:
                self.close_event()
            with self.lock:
                self.store.flush(time.time())
            self.say(f"Stopped. {self.event_count} event(s) this run. Run `python report.py` for a report.")


_instance_lock: socket.socket | None = None
INSTANCE_PORT = 47823  # localhost port held while a monitor is running


def claim_single_instance() -> bool:
    """False if another monitor is already running (the OS frees the port when it exits)."""
    global _instance_lock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if IS_WINDOWS:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        s.bind(("127.0.0.1", INSTANCE_PORT))
    except OSError:
        s.close()
        return False
    _instance_lock = s
    return True


def main() -> None:
    if not claim_single_instance():
        print("Another internet monitor is already running - not starting a second one.")
        sys.exit(1)
    p = argparse.ArgumentParser(description="Record internet drops and lag spikes.")
    p.add_argument("--db", default=str(DEFAULT_DB), help="SQLite file (default: data/monitor.db)")
    p.add_argument("--gateway", help="router IP (auto-detected if omitted)")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between probes (default 1)")
    p.add_argument("--timeout-ms", type=int, default=1000, help="ping timeout; slower = lost (default 1000)")
    p.add_argument("--lag-ms", type=float, default=150, help="internet latency counted as lag (default 150)")
    p.add_argument("--gw-lag-ms", type=float, default=100, help="router latency counted as bad (default 100)")
    p.add_argument("--min-bad", type=int, default=2, help="bad seconds in a row to start an event (default 2)")
    p.add_argument("--recover", type=int, default=3, help="good seconds in a row to end an event (default 3)")
    p.add_argument("--wifi-interval", type=float, default=3, help="seconds between WiFi samples (default 3)")
    p.add_argument("--quiet", action="store_true", help="no live status line, only events")
    Monitor(p.parse_args()).run()


if __name__ == "__main__":
    main()
