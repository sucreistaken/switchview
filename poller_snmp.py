import json
import os
from pysnmp.hlapi import *

SWITCHES_FILE = r"C:\Users\BILGIISLEM\Desktop\nac-panel\switches.json"
OUTPUT_FILE = 'data/mac_table.json'
IFSPEED = '1.3.6.1.2.1.2.2.1.5'
IFHIGHSPEED = '1.3.6.1.2.1.31.1.1.1.15'  # Mbps olarak döner

DOT1D_TP_FDB_ADDRESS = '1.3.6.1.2.1.17.4.3.1.1'
DOT1D_TP_FDB_PORT    = '1.3.6.1.2.1.17.4.3.1.2'
DOT1D_BASEPORT_IFIDX = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR              = '1.3.6.1.2.1.2.2.1.2'
DOT1Q_PVID           = '1.3.6.1.2.1.17.7.1.4.5.1.1'
IFOPERSTATUS = '1.3.6.1.2.1.2.2.1.8'  # Port operasyon durumu
IFINOCTETS     = '1.3.6.1.2.1.2.2.1.10'
IFOUTOCTETS    = '1.3.6.1.2.1.2.2.1.16'
IFINERRORS     = '1.3.6.1.2.1.2.2.1.14'
IFOUTERRORS    = '1.3.6.1.2.1.2.2.1.20'
SYS_UPTIME = '1.3.6.1.2.1.1.3.0'


TRUNK_PORTS = ["GE0/0/24", "GigabitEthernet0/0/24"]  # trunk portlar için VLAN güvenilmez


MODEL_OID = '1.3.6.1.2.1.1.1.0'  # sysDescr
def get_single_value(ip, user, auth, priv, oid):
    for (errInd, errStat, errIdx, varBinds) in getCmd(
        SnmpEngine(),
        UsmUserData(user, auth, priv,
                    authProtocol=usmHMACMD5AuthProtocol,
                    privProtocol=usmDESPrivProtocol),
        UdpTransportTarget((ip, 161), timeout=5.0, retries=3),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    ):
        if errInd or errStat:
            return None
        return str(varBinds[0][1])

def get_device_model(ip, user, auth, priv):
    for (errInd, errStat, errIdx, varBinds) in getCmd(
        SnmpEngine(),
        UsmUserData(user, auth, priv,
                    authProtocol=usmHMACMD5AuthProtocol,
                    privProtocol=usmDESPrivProtocol),
        UdpTransportTarget((ip, 161), timeout=5.0, retries=3),
        ContextData(),
        ObjectType(ObjectIdentity(MODEL_OID))
    ):
        if errInd or errStat:
            return "Bilinmiyor"
        return str(varBinds[0][1])

def format_uptime(ticks):
    try:
        seconds = int(ticks) // 100
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}g {hours}s {minutes}d {seconds}s"
    except:
        return "Bilinmiyor"

def snmp_bulk(ip, oid, user, auth, priv):
    result = []
    for (errInd, errStat, errIdx, varBinds) in bulkCmd(
        SnmpEngine(),
        UsmUserData(user, auth, priv, authProtocol=usmHMACMD5AuthProtocol, privProtocol=usmDESPrivProtocol),
        UdpTransportTarget((ip, 161), timeout=5.0, retries=3),
        ContextData(),
        0, 50,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errInd or errStat:
            break
        result.extend(varBinds)
    return result


def format_mac(oid):
    parts = oid.prettyPrint().split('.')[-6:]
    return '-'.join(f'{int(x):02x}' for x in parts).upper()


def resolve_port_number(port_name):
    """
    GigabitEthernet0/0/N → N
    XGigabitEthernet0/0/N → 48 + N
    """
    try:
        if port_name.startswith("GigabitEthernet0/0/"):
            return int(port_name.split('/')[-1])
        elif port_name.startswith("XGigabitEthernet0/0/"):
            return 48 + int(port_name.split('/')[-1])
        else:
            return None
    except:
        return None

def collect_switch_data(sw):
    ip = sw['ip']
    user = sw['snmp']['user']
    auth = sw['snmp']['auth']
    priv = sw['snmp']['priv']

    macs = snmp_bulk(ip, DOT1D_TP_FDB_ADDRESS, user, auth, priv)
    ports = snmp_bulk(ip, DOT1D_TP_FDB_PORT, user, auth, priv)
    bridge_if = snmp_bulk(ip, DOT1D_BASEPORT_IFIDX, user, auth, priv)
    ifdesc = snmp_bulk(ip, IFDESCR, user, auth, priv)
    ifoperstatus = snmp_bulk(ip, IFOPERSTATUS, user, auth, priv)
    in_octets    = snmp_bulk(ip, IFINOCTETS, user, auth, priv)
    out_octets   = snmp_bulk(ip, IFOUTOCTETS, user, auth, priv)
    in_errors    = snmp_bulk(ip, IFINERRORS, user, auth, priv)
    out_errors   = snmp_bulk(ip, IFOUTERRORS, user, auth, priv)

    pvids = snmp_bulk(ip, DOT1Q_PVID, user, auth, priv)
    ifhighspeed = snmp_bulk(ip, IFHIGHSPEED, user, auth, priv)
    speed_map = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in ifhighspeed}
    
    status_map = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in ifoperstatus}
    in_oct_map  = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in in_octets}
    out_oct_map = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in out_octets}
    in_err_map  = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in in_errors}
    out_err_map = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in out_errors}

    bridge_map = {int(v[0].prettyPrint().split('.')[-1]): int(v[1]) for v in bridge_if}
    ifname_map = {int(v[0].prettyPrint().split('.')[-1]): str(v[1]) for v in ifdesc}
    vlan_map = {int(v[0].prettyPrint().split('.')[-1]): str(v[1]) for v in pvids}

    result = []
    for i in range(min(len(macs), len(ports))):
        mac = format_mac(macs[i][0])
        bridge_port = int(ports[i][1])
        ifindex = bridge_map.get(bridge_port)
        port_name = ifname_map.get(ifindex, f'ifIndex-{ifindex}')
        vlan = vlan_map.get(ifindex, 'UNKNOWN')

        if port_name in TRUNK_PORTS:
            vlan += " (PVID, gerçek VLAN olmayabilir)"
            
        port_number = resolve_port_number(port_name)

        result.append({
            "switch_ip": ip,
            "port": port_name,
            "mac": mac,
            "vlan": vlan,
            "port_number": port_number,
            "speed_mbps": speed_map.get(ifindex, None),
            "status": "up" if status_map.get(ifindex, 2) == 1 else "down",
            "in_octets": in_oct_map.get(ifindex, 0),
            "out_octets": out_oct_map.get(ifindex, 0),
            "in_errors": in_err_map.get(ifindex, 0),
            "out_errors": out_err_map.get(ifindex, 0),
        })
            # Fiziksel port sayısını say
    gigabit_count = len([name for name in ifname_map.values() if name.startswith("GigabitEthernet0/0/")])

    # XGigabit port adedini belirle
    if gigabit_count == 24:
        base = 24
        virtual_x_ports = 8
    elif gigabit_count == 48:
        base= 48
        virtual_x_ports = 4
    else:
        base = 0
        virtual_x_ports = 0

    # Virtual XGigabitEthernet portlarını ekle
    for i in range(1, virtual_x_ports + 1):
        port_name = f"XGigabitEthernet0/0/{i}"
        port_number = base + i
        result.append({
            "switch_ip": ip,
            "port": port_name,
            "mac": "",
            "vlan": "",
            "port_number": port_number,
            "status": "down"
        })

    return result
 
import sys

def main():
    try:
        if len(sys.argv) < 2:
            print("Kullanım: python poller_snmp.py <ip>")
            return

        target_ip = sys.argv[1]

        with open(SWITCHES_FILE) as f:
            switches = json.load(f)

        sw = next((s for s in switches if s['ip'] == target_ip), None)
        if not sw:
            print(f"Switch bulunamadı: {target_ip}")
            return

        print(f"[+] {target_ip} sorgulaniyor...")
        data = collect_switch_data(sw)

        
        model = get_device_model(target_ip, sw['snmp']['user'], sw['snmp']['auth'], sw['snmp']['priv'])
        uptime_raw = get_single_value(target_ip, sw['snmp']['user'], sw['snmp']['auth'], sw['snmp']['priv'], SYS_UPTIME)
        uptime = format_uptime(uptime_raw)
        print(f"[+] Cihaz Modeli: {model}")

        switch_info = {
            "switch_info": {
                "switch_ip": target_ip,
                "device_model": model,
                "uptime": uptime
            }
        }
        for entry in data:
            entry["device_model"] = model
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE) as f:
                all_data = json.load(f)
        else:
            all_data = []

        
        all_data = [entry for entry in all_data if entry.get('switch_ip') != target_ip and entry.get('switch_info', {}).get('switch_ip') != target_ip]
        all_data.append(switch_info)
        all_data.extend(data)

        with open(OUTPUT_FILE, 'w') as f:
            json.dump(all_data, f, indent=2)

        print(f"[✓] {target_ip} için {len(data)} kayıt eklendi → {OUTPUT_FILE}")

    except Exception as e:
        print(f"[!] HATA: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)  # Bu exit Flask tarafından hata olarak algılanıyor

if __name__ == '__main__':
    main()
