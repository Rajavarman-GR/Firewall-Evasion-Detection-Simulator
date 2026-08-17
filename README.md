# Cybersecurity Incident Monitoring & Firewall Simulation Dashboard

An educational Flask application that demonstrates a small Security Operations Center (SOC) workflow using **synthetic, local data only**. It never captures network traffic, executes attacks, connects to external targets, or changes the host firewall.

## Overview

Synthetic normal and malicious events are persisted in SQLite, evaluated by a simulated firewall and rule-based detector, risk-scored, correlated, and turned into simulated incidents. The dashboard then exposes the resulting events, incidents, blocks, and audit history.

## Features

- SQLite + SQLAlchemy persistence for events, incidents, firewall rules, blocked IPs, users, and audit logs.
- Synthetic normal traffic plus brute-force, port-scan, web-attack, DDoS, and multi-stage scenarios.
- Configurable simulation-only firewall rules with priority, rule matching, temporary/permanent blocks, and whitelist data support.
- Brute-force, port-scan, and repeated web-event detection with human-readable reasons.
- Transparent risk scoring (base severity, recent-event frequency, unique ports, existing block state).
- Same-source/time-window correlation and automatic incidents, including educational MITRE ATT&CK technique labels.
- Incident lifecycle: `OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`.
- Role-based sessions: viewer, analyst, admin. Passwords use Werkzeug hashes.
- JSON REST API and responsive dashboard pages for events, incidents, and firewall state.

## Architecture

```text
app/
  models/       SQLAlchemy entities
  routes/       dashboard pages and JSON API
  services/     simulation, detection, risk, correlation, firewall workflow
  seed/         local development users and default policy
templates/      dashboard UI
static/         CSS and browser-side API client
tests/          integration tests
run.py          application entry point
```

Workflow:

```text
Synthetic event → risk score → detection → firewall decision
                → correlation → incident → audit trail → dashboard/API
```

Firewall rules are checked in ascending numeric priority; the first matching enabled rule decides the simulated action. Existing active blocks are evaluated first. This behavior is intentionally simple and documented for learning rather than production enforcement.

## Database design

`Event` includes timestamp, source/destination network metadata, type, severity, risk, action, status, scenario, incident relation, and synthetic metadata. `Incident`, `FirewallRule`, `BlockedIP`, `User`, and `AuditLog` implement the matching persistent records. `threats.xlsx` is preserved as legacy sample data; it is not runtime storage.

## API

- `GET /api/dashboard/stats`, `GET /api/events`, `GET /api/events/<id>`
- `GET /api/incidents`, `GET/PATCH /api/incidents/<id>`
- `GET/POST /api/firewall/rules`, `PUT/DELETE /api/firewall/rules/<id>`
- `GET /api/firewall/blocked`, `POST /api/firewall/block`, `POST /api/firewall/unblock`
- `POST /api/simulation/attack`, `/api/simulation/scenario`, `/api/simulation/start`

Administrative mutation endpoints require a signed session; analyst actions are limited to blocks and incident status transitions.

## Install and run

```powershell
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`. The SQLite file is created automatically in Flask's instance directory.

Development-only local users are seeded at first run:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Analyst | `analyst` | `analyst123` |
| Viewer | `viewer` | `viewer123` |

Change or remove these accounts before any shared deployment. Copy `.env.example` and set `SECRET_KEY` and `DATABASE_URL` for your environment.

## Test

```powershell
python -m unittest discover -s tests -v
```

## Limitations and future work

This is deliberately not a firewall, IDS/IPS, SIEM, or packet-capture tool. Rules, alerts, IP addresses, responses, and MITRE labels are simulated. Current next steps include richer rule-editing forms, persisted administrative configuration, and additional coverage for every policy-conflict case.

## Educational disclaimer

Use this project only to understand incident-monitoring concepts. It produces synthetic records within the application and performs no offensive, network, or operating-system security action.
