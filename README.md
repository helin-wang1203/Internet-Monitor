# Internet Monitor

Catches the short (5–20 s) drops and lag spikes that speed tests miss, works out
**where** each one happened, and produces a report you can send to your provider.

## How it works

Every second it pings, in parallel:

| Target | Why |
|---|---|
| Your router (auto-detected default gateway) | Is the link between you and the router OK? |
| 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9) | Is the internet reachable? Three unrelated servers rule out one bad server. |

Every 3 seconds it also records WiFi state: signal, access point (BSSID), channel, and link rate.

A second counts as **bad** when the public servers are unreachable or their median latency is over 150 ms.
After 2 bad seconds in a row it opens an **event**, which closes after 3 good seconds. Each event gets a location:

| Location | Evidence | Usually means |
|---|---|---|
| **Upstream / provider network** | Router answered fine, internet didn't | The provider's side. This is the strongest evidence for a complaint. |
| **Local network (WiFi / router)** | Router was also unreachable or slow | WiFi interference, a weak or overloaded access point, or the router |
| **WiFi access-point switch** | Laptop changed BSSID during the event | Roaming between building access points |
| **WiFi disconnected** | WiFi association dropped | Driver/power-saving issue or an access-point problem |

## Usage

```powershell
python monitor.py            # live view; Ctrl+C to stop
python report.py --open      # HTML report + CSV for the last 7 days
```

Run it in the background all day:

```powershell
.\start-background.ps1
```

To start it automatically at every login (hidden, kept running on battery, restarted if it crashes):

```powershell
.\install-autostart.ps1
```

Only one monitor runs at a time; any extra launch exits immediately.

Report options: `--days 1`, `--since 2026-11-01 --until 2026-11-09`, `--out path.html`.
Monitor tuning: `python monitor.py --help` (thresholds, intervals, router IP override).

Data lives in `data/monitor.db` (SQLite, about 18 MB per day). Reports go in `reports/`.
Time the PC spends asleep is detected and excluded, so reconnect-on-wake doesn't count as an outage.

Requirements: Python 3.10+, standard library only. Full features on Windows. On other OSes it
falls back to the system `ping` and has no WiFi details.
