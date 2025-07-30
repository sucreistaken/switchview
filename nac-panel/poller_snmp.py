import json
from pysnmp.hlapi import *

SWITCHES_FILE = 'switches.json'
OUTPUT_FILE = 'data/mac_table.json'

DOT1D_TP_FDB_ADDRESS = '1.3.6.1.2.1.17.4.3.1.1'
DOT1D_TP_FDB_PORT    = '1.3.6.1.2.1.17.4.3.1.2'
DOT1D_BASEPORT_IFIDX = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR              = '1.3.6.1.2.1.2.2.1.2'
DOT1Q_PVID           = '1.3.6.1.2.1.17.7.1.4.5.1.1'

TRUNK_PORTS = ["GE0/0/24", "GigabitEthernet0/0/24"]  # trunk portlar için VLAN güvenilmez
def snmp_bulk(ip, oid, user, auth, priv):
    result = []
    for (errInd, errStat, errIdx, varBinds) in bulkCmd(
        SnmpEngine(),
        UsmUserData(user, auth, priv, authProtocol=usmHMACMD5AuthProtocol, privProtocol=usmDESPrivProtocol),
        UdpTransportTarget((ip, 161), timeout=2.0, retries=1),
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

def collect_switch_data(sw):
    ip = sw['ip']
    user = sw['snmp']['user']
    auth = sw['snmp']['auth']
    priv = sw['snmp']['priv']

    macs = snmp_bulk(ip, DOT1D_TP_FDB_ADDRESS, user, auth, priv)
    ports = snmp_bulk(ip, DOT1D_TP_FDB_PORT, user, auth, priv)
    bridge_if = snmp_bulk(ip, DOT1D_BASEPORT_IFIDX, user, auth, priv)
    ifdesc = snmp_bulk(ip, IFDESCR, user, auth, priv)
    pvids = snmp_bulk(ip, DOT1Q_PVID, user, auth, priv)

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

        result.append({
            "switch_ip": ip,
            "port": port_name,
            "mac": mac,
            "vlan": vlan
        })
    return result

def main():
    with open(SWITCHES_FILE) as f:
        switches = json.load(f)

    all_data = []
    for sw in switches:
        print(f"[+] {sw['ip']} sorgulaniyor...")
        data = collect_switch_data(sw)
        all_data.extend(data)

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(all_data, f, indent=2)

    print(f"[✓] Toplam {len(all_data)} MAC kaydi yazildi → {OUTPUT_FILE}")

if __name__ == '__main__':
    main()