from flask import Flask, render_template, jsonify, request, redirect, url_for
import json
import os
import subprocess

app = Flask(__name__)

DATA_PATH = 'data/mac_table.json'
SWITCHES_FILE = 'switches.json'

@app.route('/')
def index():
    # JSON verisini oku (tarama sonrası oluşmuş)
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            data = json.load(f)
    else:
        data = []

    switch_ips = sorted(set(entry['switch_ip'] for entry in data))
    return render_template('index.html', switch_ips=switch_ips)

@app.route('/api/macs')
def mac_api():
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            data = json.load(f)
    else:
        data = []
    return jsonify(data)

@app.route('/switch/<ip>')
def switch_detail(ip):
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            data = json.load(f)
    else:
        data = []

    filtered = [entry for entry in data if entry.get('switch_ip') == ip]
    x_ports = sorted(set(e['port'] for e in filtered if e['port'].startswith("XGigabitEthernet")))
    return render_template('switch_detail.html', entries=filtered, switch_ip=ip, x_ports=x_ports)

@app.route('/scan', methods=['POST'])
def scan_switch():
    ip = request.form.get('switch_ip')
    if not ip:
        return "IP adresi eksik", 400

    # Yeni IP'yi switches.json'a ekle (eğer yoksa)
    switches = []
    if os.path.exists(SWITCHES_FILE):
        with open(SWITCHES_FILE) as f:
            switches = json.load(f)

    exists = any(sw['ip'] == ip for sw in switches)
    if not exists:
        new_entry = {
            "ip": ip,
            "snmp": {
                "user": "",
                "auth": "",
                "priv": ""
            }
        }
        switches.append(new_entry)
        with open(SWITCHES_FILE, 'w') as f:
            json.dump(switches, f, indent=2)

    # Python scriptini çalıştır (poller)
    try:
        subprocess.run(["python", "poller_snmp.py",ip], check=True)
    except subprocess.CalledProcessError as e:
        return f"Tarama sırasında hata oluştu: {e}", 500

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)

