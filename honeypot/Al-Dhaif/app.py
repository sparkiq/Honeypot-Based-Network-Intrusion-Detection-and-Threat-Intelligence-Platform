from flask import Flask, render_template_string, request, jsonify, redirect, url_for, make_response
from datetime import datetime
import sqlite3
import requests
import json
import random
import subprocess
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aldhaif_secret_key_2026'

DB_FILE = "aldhaif_bank.db"
HONEYPOT_LOG_PATH = "/home/ubuntu/honeypot/cisco_attacks.log"

REGISTERED_ORG_DEVICES = {
    "10.0.0.45": {"employee": "Ahmed Hassan", "department": "IT Infra", "mac": "00:1A:2B:3C:4D:5E"},
    "10.0.0.88": {"employee": "Mustafa Ghaith Faris", "department": "SOC Manager", "mac": "A4:C3:F0:12:34:56"},
    "79.72.1.65": {"employee": "Gateway Server", "department": "Core Network", "mac": "52:54:00:12:34:56"}
}

SESSIONS = {}


def get_mac_address(ip):
    if ip in REGISTERED_ORG_DEVICES:
        return REGISTERED_ORG_DEVICES[ip]["mac"]
    try:
        output = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.STDOUT).decode('utf-8')
        match = re.search(r"(([a-fA-F0-9]{2}[:-\b]){5}[a-fA-F0-9]{2})", output)
        if match:
            return match.group(0).upper()
    except Exception:
        pass
    return "WAN (L3 Layer Routed)"


def enrich_log_data(data):
    ip = data.get("ip", "Unknown")
    user_agent = data.get("user_agent", "")

    geo_info = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": 0.0, "lon": 0.0}
    if ip not in ["127.0.0.1", "localhost", "Unknown"]:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon", headers=headers, timeout=3).json()
            if res.get("status") == "success":
                geo_info["country"] = res.get("country", "Unknown")
                geo_info["city"] = res.get("city", "Unknown")
                geo_info["isp"] = res.get("isp", "Unknown")
                geo_info["lat"] = res.get("lat", 0.0)
                geo_info["lon"] = res.get("lon", 0.0)
        except Exception:
            try:
                res2 = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=3).json()
                geo_info["country"] = res2.get("countryName", "Unknown")
                geo_info["city"] = res2.get("cityName", "Unknown")
                geo_info["isp"] = res2.get("ipVersion", "ISP Unknown")
                geo_info["lat"] = res2.get("latitude", 0.0)
                geo_info["lon"] = res2.get("longitude", 0.0)
            except Exception:
                pass

    is_internal = ip in REGISTERED_ORG_DEVICES
    org_details = REGISTERED_ORG_DEVICES.get(ip, None)
    resolved_mac = get_mac_address(ip)

    detected_tools = []
    ua_lower = user_agent.lower()
    if "nmap" in ua_lower:
        detected_tools.append("Nmap Port Scanner")
    elif "sqlmap" in ua_lower:
        detected_tools.append("SQLMap Automated Exploiter")
    elif "hydra" in ua_lower:
        detected_tools.append("Hydra Password Brute-Forcer")
    elif "metasploit" in ua_lower:
        detected_tools.append("Metasploit Penetration Framework")
    elif "python-requests" in ua_lower or "python" in ua_lower:
        detected_tools.append("Python Automated Script")
    elif "curl" in ua_lower or "wget" in ua_lower:
        detected_tools.append("cURL/Wget CLI Tool")
    elif "burp" in ua_lower or "zap" in ua_lower:
        detected_tools.append("BurpSuite / OWASP ZAP Proxy")
    else:
        detected_tools.append("Interactive Web Browser")

    hardware = "Unknown System"
    if "windows" in ua_lower:
        hardware = "Windows PC (x86_64)"
    elif "macintosh" in ua_lower:
        hardware = "Apple Mac (macOS)"
    elif "android" in ua_lower:
        hardware = "Android Mobile Device"
    elif "iphone" in ua_lower:
        hardware = "Apple iPhone (iOS)"
    elif "linux" in ua_lower:
        hardware = "Linux Workstation / Host"

    return {
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "device_name": org_details["employee"] if is_internal else f"Host-{ip.replace('.', '-')}",
        "ip": ip,
        "mac": resolved_mac,
        "is_registered_org": is_internal,
        "location": geo_info,
        "hardware": hardware,
        "tools_used": detected_tools,
        "target_endpoint": data.get("path", "/")
    }


def save_threat_to_db(record):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threat_logs (timestamp, device_name, ip, mac, is_registered_org, location_json, hardware, tools_json, target_endpoint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["timestamp"],
        record["device_name"],
        record["ip"],
        record["mac"],
        1 if record["is_registered_org"] else 0,
        json.dumps(record["location"]),
        record["hardware"],
        json.dumps(record["tools_used"]),
        record["target_endpoint"]
    ))
    conn.commit()
    conn.close()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            is_manager BOOLEAN DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_name TEXT,
            ip TEXT,
            mac TEXT,
            is_registered_org INTEGER,
            location_json TEXT,
            hardware TEXT,
            tools_json TEXT,
            target_endpoint TEXT
        )
    """)
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users_to_seed = []
        first_names = ["Ali", "Hussein", "Mohammed", "Ahmed", "Hassan", "Karrar", "Omar", "Youssef", "Mustafa", "Zaid",
                       "Hamza", "Bilal", "Tariq", "Saad", "Faris", "Amir"]
        father_names = ["Abbas", "Jassim", "Fadhil", "Kadhim", "Jabbar", "Mahdi", "Razaq", "Salih", "Karim", "Sattar",
                        "Hadi", "Nazar", "Ghaith", "Tariq"]
        tribal_family_names = ["Al-Basri", "Al-Maliki", "Al-Sadi", "Al-Tamimi", "Al-Saadi", "Al-Zubaidi", "Al-Mayahi",
                               "Al-Asadi", "Al-Khafaji", "Al-Mansouri"]

        random.seed(42)
        for i in range(1, 76):
            full_name = f"{random.choice(first_names)} {random.choice(father_names)} {random.choice(tribal_family_names)}"
            users_to_seed.append((f"client{i}", "client123", full_name, "client", 0))

        users_to_seed.append(("finance1", "fin123", "Tariq Aziz Al-Saffar", "finance", 0))
        users_to_seed.append(("finance2", "fin123", "Yasser Mahmood Al-Sudani", "finance", 0))
        users_to_seed.append(("finance3", "fin123", "Duraid Salman Al-Obaidi", "finance", 0))
        users_to_seed.append(("finance4", "fin123", "Layan Hisham Al-Husseini", "finance", 0))
        users_to_seed.append(("finance_mgr", "fin123", "Haider Jassim Al-Ameri", "finance", 1))

        users_to_seed.append(("soc1", "admin123", "Karrar Fadhil Al-Rubaie", "cybersecurity", 0))
        users_to_seed.append(("soc2", "admin123", "Bilal Kasseem Al-Shammari", "cybersecurity", 0))
        users_to_seed.append(("mustafa_ghaith", "admin123", "Mustafa Ghaith Faris", "cybersecurity", 1))

        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users_to_seed)
        conn.commit()

    cursor.execute("SELECT COUNT(*) FROM threat_logs")
    if cursor.fetchone()[0] == 0 and os.path.exists(HONEYPOT_LOG_PATH):
        try:
            with open(HONEYPOT_LOG_PATH, "r") as f:
                for line in f:
                    if "PROBE DETECTED:" in line or "CREDENTIAL CAPTURED:" in line:
                        json_str = line.split(" - ", 1)[-1].replace("PROBE DETECTED: ", "").replace(
                            "CREDENTIAL CAPTURED: ", "").strip()
                        raw_data = json.loads(json_str)
                        enriched = enrich_log_data(raw_data)
                        save_threat_to_db(enriched)
        except Exception as e:
            print(f"Log import error: {e}")

    conn.close()


init_db()


def get_user_from_db(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, full_name, role, is_manager FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"username": row[0], "password": row[1], "full_name": row[2], "role": row[3], "is_manager": bool(row[4])}
    return None


def fetch_threats_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, device_name, ip, mac, is_registered_org, location_json, hardware, tools_json, target_endpoint FROM threat_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "timestamp": r[0],
            "device_name": r[1],
            "ip": r[2],
            "mac": r[3],
            "is_registered_org": bool(r[4]),
            "location": json.loads(r[5]),
            "hardware": r[6],
            "tools_used": json.loads(r[7]),
            "target_endpoint": r[8]
        })
    return logs


@app.route('/', methods=['GET'])
def login_page():
    error = request.args.get('error')
    err_html = '<div class="bg-red-500/10 border border-red-500/20 text-red-400 text-xs p-3 rounded-lg mb-4 text-center">Invalid credentials</div>' if error else ''
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Al-Dhaif Bank - Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 min-h-screen flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl w-full max-w-md shadow-2xl">
        <div class="text-center mb-6">
            <h1 class="text-2xl font-bold text-white tracking-tight">Al-Dhaif Bank</h1>
            <p class="text-xs text-slate-400 mt-1">Enterprise Banking & Threat Operations</p>
        </div>
        {err_html}
        <form action="/login" method="POST" class="space-y-4">
            <div>
                <input type="text" name="username" placeholder="Username" required class="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-xl focus:outline-none focus:border-cyan-500 text-sm">
            </div>
            <div>
                <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-xl focus:outline-none focus:border-cyan-500 text-sm">
            </div>
            <button type="submit" class="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-3 rounded-xl transition text-sm">Sign In</button>
        </form>
    </div>
</body>
</html>"""


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = get_user_from_db(username)
    if not user or user["password"] != password:
        return redirect('/?error=1')

    session_id = f"session_{username}"
    SESSIONS[session_id] = user
    resp = make_response(redirect(f"/dashboard/{user['role']}"))
    resp.set_cookie('session_token', session_id)
    return resp


@app.route('/dashboard/cybersecurity')
def soc_dashboard():
    session_token = request.cookies.get('session_token')
    user = SESSIONS.get(session_token)
    if not user or user["role"] != "cybersecurity":
        return redirect('/')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Al-Dhaif SOC Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <style>body {{ font-family: 'JetBrains Mono', monospace; }}</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6">
    <header class="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-800 pb-4 mb-6 gap-4">
        <div>
            <div class="flex items-center gap-3">
                <h1 class="text-lg font-bold text-white tracking-wide">AL-DHAIF SOC // THREAT MONITOR</h1>
                <span class="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs px-2.5 py-1 rounded-full flex items-center gap-1.5">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> LIVE
                </span>
            </div>
            <p class="text-xs text-slate-400 mt-1">Telemetry Feed: Cisco RV340 (79.72.1.65:8080)</p>
        </div>
        <div class="flex items-center gap-4 text-xs">
            <span class="text-slate-300"><span class="text-slate-500">Analyst:</span> {user['full_name']}</span>
            <a href="/" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition">Logout</a>
        </div>
    </header>

    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span class="text-xs text-slate-500 block mb-1">TOTAL PROBES</span>
            <span class="text-2xl font-bold text-white" id="totalCount">0</span>
        </div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span class="text-xs text-slate-500 block mb-1">INSIDER RISKS</span>
            <span class="text-2xl font-bold text-red-400" id="insiderCount">0</span>
        </div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span class="text-xs text-slate-500 block mb-1">EXTERNAL SCANS</span>
            <span class="text-2xl font-bold text-cyan-400" id="externalCount">0</span>
        </div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span class="text-xs text-slate-500 block mb-1">ACTIVE HONEYPOT</span>
            <span class="text-2xl font-bold text-emerald-400">Cisco RV340</span>
        </div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table class="w-full text-left text-xs min-w-[900px]">
                <thead class="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0 z-10">
                    <tr>
                        <th class="p-3.5">TIME</th>
                        <th class="p-3.5">1. DEVICE</th>
                        <th class="p-3.5">2. IP & MAC (ORG CHECK)</th>
                        <th class="p-3.5">3. LOCATION & MAP</th>
                        <th class="p-3.5">4. HARDWARE</th>
                        <th class="p-3.5">5. TOOLS DETECTED</th>
                        <th class="p-3.5">6. TARGET PATH</th>
                    </tr>
                </thead>
                <tbody id="threatTable" class="divide-y divide-slate-800/50">
                    <tr><td colspan="7" class="p-6 text-center text-slate-500">Waiting for Honeypot Telemetry...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div id="mapModal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 w-full max-w-2xl">
            <div class="flex justify-between items-center mb-3">
                <h3 class="text-sm font-bold text-white flex items-center gap-2">📍 Target Geolocation Pinpoint</h3>
                <button onclick="closeMap()" class="text-slate-400 hover:text-white text-lg">&times;</button>
            </div>
            <div class="w-full h-80 rounded-xl overflow-hidden border border-slate-800">
                <iframe id="mapFrame" class="w-full h-full" frameborder="0" scrolling="no" marginheight="0" marginwidth="0"></iframe>
            </div>
        </div>
    </div>

    <script>
        function showMap(lat, lon, label) {{
            const frame = document.getElementById('mapFrame');
            frame.src = `https://maps.google.com/maps?q=${{lat}},${{lon}}&hl=es&z=10&output=embed`;
            document.getElementById('mapModal').classList.remove('hidden');
            document.getElementById('mapModal').classList.add('flex');
        }}

        function closeMap() {{
            document.getElementById('mapModal').classList.remove('flex');
            document.getElementById('mapModal').classList.add('hidden');
        }}

        async function updateDashboard() {{
            try {{
                const res = await fetch('/api/v1/soc/threats');
                const data = await res.json();

                document.getElementById('totalCount').innerText = data.total_attacks;

                let insider = 0, external = 0;
                data.threats.forEach(t => t.is_registered_org ? insider++ : external++);
                document.getElementById('insiderCount').innerText = insider;
                document.getElementById('externalCount').innerText = external;

                const tbody = document.getElementById('threatTable');
                if (data.threats.length === 0) return;

                tbody.innerHTML = data.threats.map(t => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-3.5 text-slate-400 whitespace-nowrap">${{new Date(t.timestamp).toLocaleTimeString()}}</td>
                        <td class="p-3.5 font-bold text-white whitespace-nowrap">${{t.device_name}}</td>
                        <td class="p-3.5">
                            <span class="text-slate-200 font-mono">${{t.ip}}</span><br>
                            <span class="text-[10px] text-slate-400 font-mono">${{t.mac}}</span><br>
                            ${{t.is_registered_org ? 
                                '<span class="inline-block bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-bold px-1.5 py-0.5 rounded mt-1">INSIDER THREAT</span>' : 
                                '<span class="inline-block bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[10px] font-bold px-1.5 py-0.5 rounded mt-1">EXTERNAL</span>'}}
                        </td>
                        <td class="p-3.5">
                            <span class="text-slate-300 block">${{t.location.city}}, ${{t.location.country}}</span>
                            <span class="text-[10px] text-slate-500 block mb-1">${{t.location.isp}}</span>
                            <button onclick="showMap(${{t.location.lat}}, ${{t.location.lon}}, '${{t.ip}}')" class="bg-cyan-950 border border-cyan-700/50 hover:bg-cyan-900 text-cyan-300 text-[10px] px-2 py-0.5 rounded transition flex items-center gap-1">
                                🗺️ View Map (${{t.location.lat}}, ${{t.location.lon}})
                            </button>
                        </td>
                        <td class="p-3.5 text-slate-300 whitespace-nowrap">${{t.hardware}}</td>
                        <td class="p-3.5">${{t.tools_used.map(tool => `<span class="bg-slate-800 border border-slate-700 text-slate-200 text-[10px] px-1.5 py-0.5 rounded mr-1 inline-block mb-1">${{tool}}</span>`).join('')}}</td>
                        <td class="p-3.5 text-amber-400 font-mono whitespace-nowrap">${{t.target_endpoint}}</td>
                    </tr>
                `).join('');
            }} catch (err) {{
                console.error("Dashboard Sync Error:", err);
            }}
        }}
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>"""


@app.route('/api/v1/soc/threats')
def get_soc_threats():
    logs = fetch_threats_from_db()
    return jsonify({"total_attacks": len(logs), "threats": logs})


@app.route('/api/v1/telemetry/receive', methods=['POST'])
def receive_telemetry():
    data = request.get_json() or {}
    enriched = enrich_log_data(data)
    save_threat_to_db(enriched)
    return jsonify({"status": "success"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)