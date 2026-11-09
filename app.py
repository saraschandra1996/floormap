#!/usr/bin/env python3
from flask import Flask, jsonify, send_from_directory, request
import sqlite3
import json
import csv

app = Flask(__name__, static_folder="frontend")
DB_FILE = "/opt/floormap/floormap.db"
LIVE_FILE = "/opt/floormap/live_status.json"
MAPPING_FILE = "/opt/floormap/mapping.csv"

@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

@app.route("/history")
def history_page():
    return send_from_directory("frontend", "history.html")

@app.route("/api/live")
def get_live():
    try:
        with open(LIVE_FILE, "r") as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify({"desks": {}})

@app.route("/api/history/<desk_id>")
def get_history(desk_id):
    hours = request.args.get("hours", default=4, type=int)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, rx_speed_mbps, tx_speed_mbps, status, mac, ip
        FROM desk_history
        WHERE desk_id = ? AND timestamp >= datetime('now', ?)
        ORDER BY timestamp ASC
    """, (desk_id, f"-{hours} hours"))
    rows = cur.fetchall()
    conn.close()
    return jsonify([{ "timestamp": r[0], "download_mbps": r[1], "upload_mbps": r[2], "status": r[3], "mac": r[4], "ip": r[5] } for r in rows])

@app.route("/api/history_data")
def get_history_data():
    start = request.args.get("start")
    end = request.args.get("end")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    
    query = """
        SELECT timestamp, desk_id, switch_ip, port_name, mac, ip, hostname, 
               status, in_octets, out_octets, rx_speed_mbps, tx_speed_mbps, workstation_id
        FROM desk_history
    """
    params, conditions = [], []
    if start:
        conditions.append("timestamp >= ?")
        params.append(start + " 00:00:00")
    if end:
        conditions.append("timestamp <= ?")
        params.append(end + " 23:59:59")
        
    if conditions: query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT 10000"
    
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    
    data = [{ "timestamp": r[0], "desk_id": r[1], "switch_ip": r[2], "port": r[3], "mac": r[4], "ip": r[5], "hostname": r[6], "status": r[7], "download_mbps": r[10], "upload_mbps": r[11], "workstation_id": r[12] } for r in rows]
    return jsonify({"data": data})

@app.route("/api/last_online/<desk_id>")
def get_last_online(desk_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp 
        FROM desk_history 
        WHERE desk_id = ? AND status = 'online'
        ORDER BY timestamp DESC LIMIT 1
    """, (desk_id,))
    row = cur.fetchone()
    conn.close()
    
    if row:
        return jsonify({"last_online": row[0]})
    return jsonify({"last_online": "Never recorded / Unknown"})

@app.route("/api/update_workstation", methods=["POST"])
def update_workstation():
    data = request.json
    desk_id = data.get("desk_id")
    workstation_id = data.get("workstation_id")
    
    if not desk_id:
        return jsonify({"error": "desk_id required"}), 400

    updated_rows = []
    found = False
    
    with open(MAPPING_FILE, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 3:
                updated_rows.append(row)
                continue
            
            if row[2].strip() == desk_id:
                while len(row) < 4:
                    row.append("")
                row[3] = workstation_id
                found = True
            updated_rows.append(row)

    if found:
        with open(MAPPING_FILE, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerows(updated_rows)
        return jsonify({"status": "success"})
    return jsonify({"error": "desk_id not found in CSV"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
