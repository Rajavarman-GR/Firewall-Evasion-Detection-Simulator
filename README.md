# Firewall Evasion Detection Simulator

A Flask-based cybersecurity dashboard that simulates common cyberattack scenarios, logs security events, automatically blocks repeatedly offending IP addresses, and visualizes attack statistics. The project demonstrates the implementation of a basic threat monitoring workflow and security event management using Python.

---

## Overview

This project is designed to simulate a simple firewall monitoring environment where predefined attack events are generated, recorded, and analyzed. It focuses on demonstrating defensive security concepts such as:

- Security event logging
- Automated IP blocking based on repeated attacks
- Threat visualization
- Basic incident monitoring dashboard

This project is intended for educational purposes and does **not** inspect live network traffic or bypass real firewall systems.

---

## Features

- Simulates common attack types
  - SQL Injection
  - DDoS
  - Port Scan
  - Cross-Site Scripting (XSS)
  - Brute Force

- Logs security events into an Excel workbook

- Automatically blocks IP addresses after repeated attack attempts

- Displays the latest threat logs through a web dashboard

- Generates a bar chart showing attacks grouped by country

- Simple Flask-based web interface

---

## Technologies Used

- Python
- Flask
- Pandas
- Matplotlib
- OpenPyXL

---

## Project Structure

```
Firewall-Evasion-Detection/

│── server.py
│── firewall_rules.py
│── requirements.txt
│── threats.xlsx
│
├── templates/
│      index.html
│
├── static/
│      styles.css
│
└── static/logs/
       threats_graph.png
```

---

## How It Works

1. The user launches the Flask application.

2. Clicking **Simulate Attack** generates a random:

   - IP Address
   - Country
   - Attack Type

3. Each simulated event is stored in **threats.xlsx**.

4. The application keeps track of the number of attacks originating from each IP.

5. If an IP exceeds the configured threshold (default: 3 attempts), it is marked as blocked using the firewall_rules module.

6. A bar chart is generated showing the number of threats originating from each country.

7. The dashboard displays the most recent threat logs.

---

## Installation

Clone the repository

```bash
git clone https://github.com/Rajavarman-GR/Firewall-Bypass-Detection.git
```

Move into the project directory

```bash
cd Firewall-Bypass-Detection
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python server.py
```

Open your browser

```
http://127.0.0.1:5000
```

---

## Dependencies

```
Flask
pandas
matplotlib
openpyxl
```

Install all dependencies using:

```bash
pip install -r requirements.txt
```

---

## Sample Workflow

```
Simulate Attack
        │
        ▼
Generate Random Threat
        │
        ▼
Store Event in Excel
        │
        ▼
Increase Attack Counter
        │
        ▼
Attack Threshold Reached?
      │
  Yes ▼
Block IP
      │
      ▼
Generate Threat Statistics
      │
      ▼
Display Updated Dashboard
```

---

## Limitations

This project currently uses simulated attack data.

It does not:

- Capture live packets
- Monitor real firewall logs
- Perform intrusion detection
- Use machine learning
- Detect real firewall evasion techniques
- Integrate with SIEM platforms

---

## Possible Improvements

Future enhancements may include:

- Live packet inspection using Scapy
- Firewall log parsing
- GeoIP lookup for source addresses
- Email alert notifications
- SQLite or PostgreSQL database support
- REST API for threat ingestion
- User authentication
- Docker deployment
- SIEM integration (Splunk/Wazuh)
- Rule-based threat detection

---

## Learning Outcomes

This project demonstrates practical understanding of:

- Flask Web Development
- Python Automation
- Security Event Logging
- Data Visualization
- Basic Firewall Rule Management
- Threat Monitoring Concepts
- Incident Logging

---

## Author

**Rajavarman G.R.**

GitHub:
https://github.com/Rajavarman-GR

LinkedIn:
https://www.linkedin.com/in/rajavarman-g-r

---


