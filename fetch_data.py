#!/usr/bin/env python3
import os
import csv
import json
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv("/opt/floormap/.env")

COMMUNITY1 = os.getenv("COMMUNITY1")
COMMUNITY2 = os.getenv("COMMUNITY2")
CORE_SWITCH = os.getenv("CORE_SWITCH")
DNS_SERVERS = os.getenv("DNS_SERVERS", "").split(",")

# Define file paths
MAPPING_FILE = "/opt/floormap/mapping.csv"
DB_FILE = "/opt/floormap/floormap.db"
JSON_OUT = "/opt/floormap/live_status.json"

OID_ARP_TABLE = "1.3.6.1.2.1.4.22.1.2"
OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"

def run_snmp(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        return res.stdout.strip().splitlines()
    except Exception:
        return []

def normalize_mac(raw_mac):
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw_mac).lower()
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
    return cleaned

def fetch_arp_table(core_ip):
    arp = {}
    lines = run_snmp(f"snmpwalk -v2c -c {COMMUNITY1} -t 1 -r 1 {core_ip} {OID_ARP_TABLE}")
    for line in lines:
        match = re.search(r"\.(\d+\.\d+\.\d+\.\d+)\s+=\s+Hex-STRING:\s+(.+)", line)
        if match:
            ip, raw_mac = match.group(1), match.group(2)
            arp[normalize_mac(raw_mac)] = ip
    return arp

def get_latest_db_record(conn, desk_id):
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, in_octets, out_octets 
        FROM desk_history 
        WHERE desk_id = ? 
        ORDER BY id DESC LIMIT 1
    """, (desk_id,))
    return cur.fetchone()

def get_last_online_record(conn, desk_id):
    """Retrieve the most recent record where the machine was online."""
    cur = conn.cursor()
    cur.execute("""
        SELECT ip, hostname, mac, timestamp
        FROM desk_history 
        WHERE desk_id = ? AND status = 'online'
        ORDER BY id DESC LIMIT 1
    """, (desk_id,))
    return cur.fetchone()

def compute_bandwidth_mbps(curr_bytes, prev_bytes, delta_sec):
    if delta_sec <= 0 or prev_bytes is None:
        return 0.0
    delta_bytes = curr_bytes - prev_bytes
    if delta_bytes < 0:
        delta_bytes += (1 << 64)
    return round((delta_bytes * 8) / (delta_sec * 1_000_000), 2)

def main():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    print(f"Fetching ARP table from Core Switch ({CORE_SWITCH})...")
    arp_table = fetch_arp_table(CORE_SWITCH)
    print(f"-> Discovered {len(arp_table)} IP entries.")

    live_desks = {}
    now = datetime.now(timezone.utc)
    epoch_now = time.time()

    switch_mac_tables = {}
    switch_in_octets = {}
    switch_out_octets = {}

    with open(MAPPING_FILE, mode="r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 3:
                continue

            switch_ip = row[0].strip().lstrip("\ufeff")
            port_val = row[1].strip()
            desk_id = row[2].strip()
            workstation_id = row[3].strip() if len(row) > 3 else ""
            category = row[4].strip() if len(row) > 4 and row[4].strip() else "Workstation"

            try:
                if_index = int(port_val)
            except ValueError:
                if_index = None

            if switch_ip not in switch_mac_tables:
                bridge_lines = run_snmp(f"snmpwalk -v2c -c {COMMUNITY2} -t 1 -r 1 {switch_ip} 1.3.6.1.2.1.17.4.3.1.2")
                
                if not bridge_lines:
                    switch_mac_tables[switch_ip] = None
                    switch_in_octets[switch_ip] = None
                    switch_out_octets[switch_ip] = None
                else:
                    mac_to_port = {}
                    for bl in bridge_lines:
                        bm = re.search(r"\.1\.2\.(\d+\.\d+\.\d+\.\d+\.\d+\.\d+)\s+=\s+INTEGER:\s+(\d+)", bl)
                        if bm:
                            dec_bytes = [int(x) for x in bm.group(1).split(".")]
                            mac = ":".join(f"{b:02x}" for b in dec_bytes)
                            mac_to_port[int(bm.group(2))] = mac
                    switch_mac_tables[switch_ip] = mac_to_port

                    in_lines = run_snmp(f"snmpwalk -v2c -c {COMMUNITY2} -t 1 -r 1 {switch_ip} {OID_IF_HC_IN}")
                    out_lines = run_snmp(f"snmpwalk -v2c -c {COMMUNITY2} -t 1 -r 1 {switch_ip} {OID_IF_HC_OUT}")
                    
                    in_dict, out_dict = {}, {}
                    for line in in_lines:
                        m = re.search(r"\.(\d+)\s+=\s+Counter64:\s+(\d+)", line)
                        if m: in_dict[int(m.group(1))] = int(m.group(2))
                    for line in out_lines:
                        m = re.search(r"\.(\d+)\s+=\s+Counter64:\s+(\d+)", line)
                        if m: out_dict[int(m.group(1))] = int(m.group(2))
                        
                    switch_in_octets[switch_ip] = in_dict
                    switch_out_octets[switch_ip] = out_dict

            port_mac = None
            in_octets, out_octets = 0, 0

            if switch_mac_tables.get(switch_ip) and if_index:
                port_mac = switch_mac_tables[switch_ip].get(if_index)
                in_octets = switch_in_octets[switch_ip].get(if_index, 0)
                out_octets = switch_out_octets[switch_ip].get(if_index, 0)

            assigned_ip = arp_table.get(port_mac, "N/A") if port_mac else "N/A"
            hostname = "N/A"
            status = "offline"

            if assigned_ip != "N/A":
                status = "online"
                for dns in DNS_SERVERS:
                    try:
                        host_res = subprocess.run(f"host -W 2 {assigned_ip} {dns}", shell=True, capture_output=True, text=True)
                        if "domain name pointer" in host_res.stdout:
                            hostname = host_res.stdout.split()[-1].rstrip(".")
                            break
                    except Exception:
                        continue

            # Fallback to last known online details if port is offline
            last_known_ip = None
            last_known_hostname = None
            last_known_mac = None
            last_seen_ts = None

            if status == "offline":
                last_online = get_last_online_record(conn, desk_id)
                if last_online:
                    last_known_ip, last_known_hostname, last_known_mac, last_seen_ts = last_online

            prev_record = get_latest_db_record(conn, desk_id)
            rx_speed, tx_speed = 0.0, 0.0
            if prev_record and in_octets > 0 and out_octets > 0:
                prev_ts_str, prev_in, prev_out = prev_record
                try:
                    prev_epoch = time.mktime(datetime.strptime(prev_ts_str, "%Y-%m-%d %H:%M:%S").timetuple())
                    delta_t = epoch_now - prev_epoch
                    rx_speed = compute_bandwidth_mbps(out_octets, prev_out, delta_t)
                    tx_speed = compute_bandwidth_mbps(in_octets, prev_in, delta_t)
                except Exception:
                    pass

            cur.execute("""
                INSERT INTO desk_history (
                    timestamp, desk_id, workstation_id, switch_ip, port_name, if_index, 
                    mac, ip, hostname, status, in_octets, out_octets, 
                    rx_speed_mbps, tx_speed_mbps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now.strftime("%Y-%m-%d %H:%M:%S"), desk_id, workstation_id, switch_ip, str(port_val), if_index,
                port_mac, assigned_ip, hostname, status, in_octets, out_octets,
                rx_speed, tx_speed
            ))

            live_desks[desk_id] = {
                "status": status,
                "mac": port_mac,
                "ip": assigned_ip,
                "hostname": hostname,
                "workstation_id": workstation_id,
                "category": category,
                "switch_ip": switch_ip,
                "port": str(port_val),
                "download_mbps": rx_speed,
                "upload_mbps": tx_speed,
                "total_in_mb": round(in_octets / (1024 * 1024), 2),
                "total_out_mb": round(out_octets / (1024 * 1024), 2),
                "last_known_ip": last_known_ip,
                "last_known_hostname": last_known_hostname,
                "last_known_mac": last_known_mac,
                "last_seen_ts": last_seen_ts
            }

    conn.commit()
    conn.close()

    with open(JSON_OUT, "w") as f:
        json.dump({"updated_at": now.isoformat(), "desks": live_desks}, f, indent=2)

if __name__ == "__main__":
    main()
