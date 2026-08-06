# Firewall Evasion Detection Simulator

A Flask-based web application that simulates common cybersecurity attack scenarios and visualizes security events through a simple monitoring dashboard. The application records simulated attack events, tracks repeated attempts from the same IP address, generates attack statistics, and demonstrates the workflow of a basic security event monitoring system.

> **Note:** This project is intended for educational purposes only. It does **not** capture live network traffic, inspect firewall rules, perform intrusion detection, or block real network connections.

---

## Overview

The Firewall Evasion Detection Simulator demonstrates how a security monitoring dashboard can log, visualize, and manage simulated attack events.

Users can generate different attack scenarios from the web interface, which are recorded in an Excel workbook along with metadata such as IP address, country, attack type, and timestamp. The application also tracks repeated simulated attacks from the same IP and marks an address as blocked after a configurable threshold.

The project focuses on learning Flask development, data logging, simple event processing, and dashboard visualization rather than implementing a production-grade firewall or IDS.

---

## Features

- Simulate five common cybersecurity attack scenarios:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Brute Force
  - Port Scan
  - Distributed Denial of Service (DDoS)

- Log each simulated event with:
  - Source IP Address
  - Country
  - Attack Type
  - Timestamp

- Maintain an in-memory IP attempt counter

- Mark IP addresses as "Blocked" after three simulated attack attempts

- Display a live threat log that refreshes automatically

- Generate a bar chart showing attacks grouped by country

- Lightweight Flask web interface built using HTML, CSS, and JavaScript

---

## Screenshots

> Add screenshots of your dashboard here.

Example:

```
screenshots/
├── dashboard.png
├── attack-log.png
└── country-chart.png
```

---

# Technology Stack

| Component | Technology |
|------------|------------|
| Backend | Python 3 |
| Web Framework | Flask |
| Frontend | HTML, CSS, JavaScript |
| Data Processing | Pandas |
| Excel Handling | OpenPyXL |
| Visualization | Matplotlib |

---

# Project Structure

```
Firewall-Evasion-Detection-Simulator/
│
├── server.py                 # Main Flask application
├── firewall_rules.py         # Simulated IP blocking logic
├── requirements.txt
├── threats.xlsx              # Event log
├── index.html                # Dashboard page
├── styles.css                # Dashboard styling
└── README.md
```

---

# How It Works

1. A user clicks **Simulate Attack** from the dashboard.
2. The application randomly selects attack metadata such as:
   - IP Address
   - Country
   - Attack Type
3. The event is written into `threats.xlsx`.
4. The IP attempt counter is updated.
5. After three simulated attempts, the IP is added to an in-memory block list.
6. The dashboard refreshes to display the latest events.
7. A country-wise attack chart can be regenerated from the logged data.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Rajavarman-GR/Firewall-Evasion-Detection-Simulator.git
```

Navigate into the project:

```bash
cd Firewall-Evasion-Detection-Simulator
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Application

Start the Flask server:

```bash
python server.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

Use the dashboard to simulate attack events and monitor the generated logs.

---

# Attack Simulation Workflow

```
User
   │
   ▼
Dashboard
   │
   ▼
Select Attack Type
   │
   ▼
Generate Simulated Event
   │
   ▼
Write to threats.xlsx
   │
   ▼
Update IP Counter
   │
   ▼
Check Block Threshold
   │
   ▼
Refresh Dashboard
   │
   ▼
Generate Country Statistics
```

---

# Sample Logged Event

| Timestamp | IP Address | Country | Attack Type |
|------------|------------|----------|-------------|
| 2026-08-05 14:23:11 | 192.168.10.24 | India | SQL Injection |

---

# Current Limitations

This project intentionally keeps the implementation simple for educational purposes.

Current limitations include:

- No live packet capture
- No real firewall integration
- No real intrusion detection
- No packet inspection
- No traffic analysis
- IP blocking is maintained only in memory
- Blocked IPs are not persisted between application restarts
- Simulated attacks continue to be logged even after an IP is marked as blocked
- Attack data is generated from predefined sample values
- `threats.xlsx` is rewritten whenever new events are added
- No authentication or user management
- Frontend files currently reside in the project root rather than Flask's recommended `templates/` and `static/` directories

---

# Possible Improvements

Future enhancements could include:

- Organize the project using Flask's standard structure (`templates/` and `static/`)
- Store logs in SQLite or PostgreSQL instead of Excel
- Persist blocked IP addresses across application restarts
- Prevent additional logging after an IP is blocked
- Add configurable attack thresholds
- Export logs as CSV or PDF
- Add authentication for dashboard access
- Introduce filtering and search for threat logs
- Add REST API endpoints for log retrieval
- Containerize the application using Docker
- Improve dashboard responsiveness and UI design
- Add unit and integration tests

---

# Learning Outcomes

This project helped reinforce practical concepts including:

- Flask web application development
- HTTP routing and request handling
- Event-driven application workflows
- Data logging using Pandas and OpenPyXL
- Reading and writing Excel files
- Dynamic chart generation with Matplotlib
- Basic dashboard development using HTML, CSS, and JavaScript
- Simple state management using Python data structures

---

# Disclaimer

This application is an educational simulator.

It is **not** a real firewall, intrusion detection system (IDS), intrusion prevention system (IPS), or security information and event management (SIEM) platform.

The simulated attacks do not interact with any real network, system, or application. All attack data is generated internally to demonstrate logging and visualization workflows.

---

# Author

**Rajavarman G.R.**

Cybersecurity Undergraduate | Security Engineering | Python | Flask

GitHub  
https://github.com/Rajavarman-GR

LinkedIn  
https://www.linkedin.com/in/rajavarman-g-r

---

## License

This project is released for educational and learning purposes.

Feel free to fork, modify, and use it for personal learning while providing appropriate attribution.
