# Honeypot-Based Network Intrusion Detection and Threat Intelligence Platform

An enterprise-grade, lightweight Security Operations Center (SOC) and Threat Intelligence platform integrated with an active decoy honeypot (`Cisco RV340` emulation). Designed and built for real-time network intrusion detection, GeoIP threat mapping, automated telemetry logging, and perimeter defense mitigation.

---

## 🚀 Key Features

* **Active Honeypot Emulation:** Simulates a vulnerable Cisco RV340 router (Port 8080) to safely capture malicious botnet probes, path traversal attempts, and exploit scans without risking core server infrastructure.
* **Real-Time SOC Threat Intelligence Dashboard:** 
  * Live telemetry feed monitoring external scans and attack vectors.
  * Multi-tier Role-Based Access Control (RBAC) supporting SOC Managers, Finance Staff, and standard Clients.
  * Interactive threat mapping with fallback-enabled GeoIP lookup (Country, City, ISP, and coordinate rendering).
* **Intrusion Detection System (IDS) Layer:** Signature and behavior-based analysis inspecting incoming payloads, URI paths, and request frequencies to classify threats.
* **Persistent Telemetry Logging:** SQLite-backed relational storage tracking probe frequencies, target paths, and timestamps for comprehensive incident analysis.
* **Perimeter Defense Ready:** Structured roadmap for automated kernel-level `iptables` drop mitigation and manager-only firewall unblocking controls.

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask / FastAPI framework)
* **Frontend:** HTML5, Modern CSS / Tailwind-inspired UI, JavaScript, Interactive Maps
* **Database:** SQLite (Persistent telemetry and user audit logs)
* **Security & Infrastructure:** Oracle Cloud (Ubuntu Linux), Nginx (Reverse Proxy & SSL Termination via Let's Encrypt), IPTables Firewall rules.

---

## 📂 Project Architecture

```text
├── app.py                 # Core Flask application, routing, and SOC API endpoints
├── database.db            # Persistent SQLite database (Users, telemetry, logs)
├── templates/             # HTML templates for Bank Portal and SOC Dashboard
├── static/                # CSS styling, JavaScript mapping assets, and UI assets
└── requirements.py/txt    # Project dependencies and environment config
