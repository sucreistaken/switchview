# switchview

**SNMP-based switch & MAC-address visibility for campus networks.**

Polls a list of switches via SNMPv3, reads the bridge MAC-address table + per-port stats, resolves vendors via MAC OUI, and serves a Flask web dashboard so the network team can answer "which port is this device on, and what is it" in seconds instead of CLI sessions.

In active production use at Izmir University of Economics on a Huawei + Cisco mixed fleet.

## What it shows

- All switches in the fleet, filterable by IP
- Per-switch MAC table: MAC → port → VLAN → vendor (via maclookup.app, locally cached)
- Per-port stats: speed, oper status, in/out octets, in/out errors
- Trunk-port awareness (excluded from the per-VLAN counting where it would be misleading)

## How it's built

| Layer | Stack |
|---|---|
| Poller | Python + `pysnmp` (`poller_snmp.py`) — walks `dot1dTpFdbAddress`, `dot1dTpFdbPort`, ifTable, dot1q PVID |
| Cache | Local JSON (`data/mac_table.json`, `data/vendor_cache.json`) |
| API + UI | Flask (`app.py`) + Jinja templates (`templates/`) |
| Vendor lookup | `api.maclookup.app` with on-disk cache |

Switch inventory lives in `switches.json` (per-switch IP, brand, SNMP creds, SSH creds for remote actions). The poller runs on a schedule; the Flask app reads the cached JSON and renders.

## Quick start

```bash
git clone https://github.com/sucreistaken/switchview.git
cd switchview

pip install flask pysnmp requests

# 1. Copy switches.json.example -> switches.json and fill in your inventory
# 2. Run the poller (writes data/mac_table.json)
python poller_snmp.py

# 3. Serve the dashboard
python app.py
# -> http://localhost:5000
```

For production: run `poller_snmp.py` on a cron/systemd timer (every 5-15 min depending on table size), and the Flask app behind nginx + gunicorn.

## Security notes

- **Never commit real `switches.json` with SNMP / SSH credentials to a public repo.** Use `switches.json.example` as a template, gitignore the real file, and inject credentials via environment variables or a secrets manager in production.
- The maclookup API is read-only and rate-limited; the local cache keeps you well under the free tier for normal campus traffic.

## Why this exists

Manual `display mac-address` on Huawei or `show mac address-table` on Cisco gets old when you have 8,000 students and ~40 switches and you're trying to track down which port a rogue device is on. switchview reduces "find the port" from a CLI session to a search box.

## Status

Production-deployed; iterating on the UI and stats layer. Not packaged for general distribution yet — repo serves as the reference implementation for the IEU network team and a portfolio piece.
