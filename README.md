# switchview

Web dashboard that shows which devices are connected to which switch ports on a campus network. Used in production at Izmir University of Economics on a fleet of around 40 Huawei and Cisco switches.

## What it does

Polls each switch over SNMPv3, reads the MAC address table and port stats, and stores them as JSON. A Flask app reads that JSON and shows:

- All switches in the fleet, filterable by IP
- For each switch: every MAC address, which port it sits on, what VLAN it's in, and the device vendor (looked up from the MAC prefix via maclookup.app, cached locally)
- Per-port stats: link speed, operational status, in/out bytes, in/out errors
- Trunk ports are detected and excluded from VLAN-specific counting (where the VLAN data would be misleading on a trunk)

This replaces the daily routine of SSHing into each switch and running `display mac-address` (Huawei) or `show mac address-table` (Cisco) to find where a device is plugged in.

## Tech stack

| Part | Built with |
|---|---|
| Poller (`poller_snmp.py`) | Python, pysnmp. Walks the bridge MAC table, ifTable, dot1q PVID. |
| Cache | Local JSON files in `data/` |
| Web app (`app.py`) | Flask, Jinja templates |
| Vendor lookup | api.maclookup.app, results cached on disk |

## Run it

```bash
git clone https://github.com/sucreistaken/switchview.git
cd switchview
pip install flask pysnmp requests

# 1. Edit switches.json with your inventory (use the .example file as a template)
# 2. Run the poller once to generate data/mac_table.json
python poller_snmp.py

# 3. Start the web app
python app.py
# Open http://localhost:5000
```

In production: run the poller on a 5 to 15 minute timer (cron or systemd) and put the Flask app behind nginx + gunicorn.

## Important: credentials

Do not commit a real `switches.json` to a public repository. It contains SNMPv3 user/auth/priv credentials and SSH passwords for every switch. Use `switches.json.example` as a placeholder, add the real file to `.gitignore`, and load credentials from environment variables or a secrets manager.

## Status

Live in production. Iterating on the UI and the stats view. Not packaged as a general-purpose product. This is the reference implementation we use at IEU.
