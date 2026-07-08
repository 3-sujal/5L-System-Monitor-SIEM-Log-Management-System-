# 5L System Monitor — Enhanced SIEM Dashboard

A self-contained Flask web application that turns a Windows machine into a lightweight SIEM-style monitoring dashboard. It tracks live system performance, network activity, Windows event logs, USB devices, and scans the user's Downloads folder for suspicious files — all surfaced through a browser dashboard with charts, incident tracking, and dark mode.

## Features

- **Live system metrics** — CPU, memory, and disk usage with a 5-minute rolling history
- **Process monitor** — running applications auto-categorized (browsers, office, media, development, system, utilities)
- **Network monitor** — per-interface status, IP addresses, and bytes/packets sent & received
- **Windows Event Log viewer** — pulls recent Application, System, and Security events and classifies them by severity
- **File-based threat scanning** — scans the current user's `Downloads` folder for suspicious filenames/extensions (configurable depth and file limit)
- **USB device monitoring** — lists connected USB hubs/controllers/devices via WMI
- **SIEM incident management** — create, resolve, and escalate incidents; auto-creates incidents for high-severity threats
- **Dashboard charts** — application breakdown (pie) and network/CPU trend (line), rendered in-browser
- **Login screen & dark mode** — simple login gate and persistent dark/light theme toggle
- **File-based logging** — system, threat, and access logs written under `logs/`

## Requirements

- **Windows OS** (uses `pywin32` / WMI for event logs and USB monitoring — will not run on macOS/Linux)
- Python 3.8+

### Python dependencies

```
Flask
psutil
pywin32
```

Install with:

```bash
pip install flask psutil pywin32
```

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/3-sujal/5L-System-Monitor-SIEM-Log-Management-System.git
   cd 5L-System-Monitor-SIEM-Log-Management-System
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python enhanced_monitor.py
   ```
4. Open your browser to:
   ```
   http://localhost:5000
   ```
5. Log in with the demo credentials (see **Security Notes** below), then land on `/dashboard`.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Login page |
| `/dashboard` | GET | Main monitoring dashboard |
| `/logout` | GET | Log out |
| `/api/data` | GET | Combined snapshot: system, apps, logs, performance, threats, network, SIEM data |
| `/api/system-stats` | GET | CPU, memory, disk, network counters |
| `/api/system-info` | GET | Full system info + top 10 processes by CPU |
| `/api/logs/system` | GET | Recent formatted event log entries |
| `/api/logs/files` | GET | Contents of local log files |
| `/api/threats` | GET | Formatted threat list |
| `/api/scan-files` | GET | Run a file scan and return results |
| `/api/network-info` | GET | Network interfaces + uptime |
| `/api/agent-status` | GET | Agent ID, hostname, status, uptime |
| `/api/siem/incidents` | GET | Recent open incidents |
| `/api/siem/incidents/resolved` | GET | Resolved incidents |
| `/api/siem/incidents` | POST | Create a new incident |
| `/api/siem/incidents/<id>/resolve` | POST | Resolve an incident |
| `/api/siem/incidents/<id>/escalate` | POST | Escalate an incident |
| `/api/siem/threats` | GET | Recent threats |
| `/api/siem/usb-devices` | GET | Connected USB devices |
| `/api/siem/charts/applications` | GET | Data for the application pie chart |
| `/api/siem/charts/network-cpu` | GET | Data for the network/CPU line chart |
| `/api/toggle-dark-mode` | POST | Persist dark mode preference (cookie) |

## Configuration

Key constants at the top of `enhanced_monitor.py`:

| Setting | Default | Description |
|---|---|---|
| `SCAN_INTERVAL` | `5` | Seconds between scans |
| `MAX_SCAN_DEPTH` | `3` | Max directory depth scanned inside Downloads |
| `SCAN_LIMIT` | `500` | Max files scanned per run |
| `PERFORMANCE_HISTORY_MINUTES` | `5` | Length of retained performance history |
| `NETWORK_HISTORY_MINUTES` | `5` | Length of retained network history |
| `AGENT_ID` / `AGENT_NAME` | `AGENT-002` / `Enhanced SIEM Monitor` | Agent identity shown in the dashboard |

## Security Notes ⚠️

This project is intended as a **learning/demo tool**, not a production security product:

- The login page uses a **hardcoded username/password (`admin` / `admin`)** checked client-side in JavaScript — it provides no real authentication or session security.
- The app runs with `debug=True` and binds to `0.0.0.0:5000`, exposing it on your local network.
- Disk I/O utilization is currently a **simulated/cycling placeholder value**, not a real measurement.
- Threat detection is filename/extension/size heuristics only — it is **not** a substitute for real antivirus/EDR software.

Before deploying anywhere beyond your own machine, replace the login system with proper authentication, disable debug mode, and bind to `127.0.0.1` or add a reverse proxy with TLS.

## Project Structure

```
.
├── enhanced_monitor.py   # Main Flask app
└── logs/                 # Auto-created at runtime
    ├── system_monitor.log
    ├── threat_detection.log
    └── access_logs.log
```

## License

Add a license of your choice (e.g. MIT) before publishing.
