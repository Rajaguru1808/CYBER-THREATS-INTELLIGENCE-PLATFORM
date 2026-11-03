# Cyber Threat Intelligence (CTI) Platform using Indicators of compromise

A full-stack Cyber Threat Intelligence platform built with **Flask**, **MySQL**, and **Bootstrap**, integrating **MISP**, **VirusTotal**, **AlienVault OTX**, and **AbuseIPDB** for indicator enrichment, correlation, and reporting. Built as a final-year Cyber Security mini project, following clean **MVC architecture**.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-black)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Tech Stack](#tech-stack)
5. [Database Schema](#database-schema)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Running the Application](#running-the-application)
9. [Default Credentials](#default-credentials)
10. [REST API Reference](#rest-api-reference)
11. [Screenshots / Pages](#screenshots--pages)
12. [Security Notes](#security-notes)
13. [Future Improvements](#future-improvements)

---

## Features

- **Authentication & RBAC** — Admin and Analyst roles via Flask-Login, bcrypt password hashing.
- **Dashboard** — Total threats, critical threats, IOC counts, recent events, live Chart.js charts, threat feed status.
- **IOC Management** — Full CRUD for IPs, domains, URLs, emails, and file hashes (MD5/SHA1/SHA256).
- **Threat Search** — Unified search across all IOCs with automatic type detection.
- **Event Management** — Create/update/delete threat events; optional push/sync to a live MISP instance via PyMISP.
- **External Threat Intel Import** — Pull events/attributes from MISP and pulses from AlienVault OTX directly into the local database.
- **Enrichment** — One-click IOC enrichment against VirusTotal, AlienVault OTX, and AbuseIPDB.
- **Threat Correlation Engine** — Automatically flags IOCs that share a value or tags across multiple events.
- **Severity Classification** — Weighted scoring engine (VT verdicts + OTX pulse count + AbuseIPDB score) producing a 0-100 confidence score and low/medium/high/critical label.
- **PDF Reporting** — Per-event and platform-wide summary reports generated with ReportLab.
- **Activity Logs** — Full audit trail of logins, CRUD actions, imports, and report generation.
- **REST API** — JSON endpoints for IOCs, events, and search, for integration with other tools.
- **Responsive UI** — Bootstrap 5 + Bootstrap Icons, works on desktop and mobile.

---

## Architecture

The project follows an **MVC (Model–View–Controller)** pattern implemented with Flask Blueprints:

- **Model** (`app/models/`) — SQLAlchemy ORM models (`User`, `ThreatEvent`, `IOCAttribute`, `Report`, `ActivityLog`, `APIConfiguration`).
- **View** (`app/templates/`) — Jinja2 templates + Bootstrap 5.
- **Controller** (`app/controllers/`) — Flask Blueprints handling routes, form/JSON input, and calling services.
- **Service layer** (`app/services/`) — All external API calls (MISP, VirusTotal, OTX, AbuseIPDB) and business logic (correlation, severity scoring, PDF generation) live here, decoupled from routes.

```
Browser (Bootstrap/JS)
        │
        ▼
Flask Controllers (Blueprints)  ── Validation (app/utils/validators.py)
        │                       ── RBAC (app/utils/decorators.py)
        ▼
Service Layer (MISP / VT / OTX / AbuseIPDB / Correlation / Severity / PDF)
        │
        ▼
SQLAlchemy Models  ──────────────►  MySQL Database
```

---

## Project Structure

```
cti-platform/
├── app/
│   ├── __init__.py                 # Application factory (create_app)
│   ├── config.py                   # Environment-based configuration classes
│   ├── extensions.py                # Shared extension instances (db, login_manager, bcrypt)
│   │
│   ├── models/                      # SQLAlchemy models (the "M" in MVC)
│   │   ├── user.py                  # User accounts, roles, password hashing
│   │   ├── event.py                 # ThreatEvent (mirrors MISP event structure)
│   │   ├── ioc.py                   # IOCAttribute (IP/domain/URL/email/hash)
│   │   ├── report.py                # Generated PDF report records
│   │   ├── activity_log.py          # Audit trail entries
│   │   └── api_config.py            # Stored API keys/status for external feeds
│   │
│   ├── controllers/                 # Flask Blueprints (the "C" in MVC)
│   │   ├── auth_controller.py       # Login/logout/user management
│   │   ├── dashboard_controller.py  # Stats + chart JSON endpoint
│   │   ├── ioc_controller.py        # IOC CRUD, search, enrichment, REST API
│   │   ├── event_controller.py      # Event CRUD, MISP push/sync, REST API
│   │   ├── report_controller.py     # PDF generation & downloads
│   │   ├── settings_controller.py   # API config + activity log viewer
│   │   └── import_controller.py     # Bulk import from MISP / OTX
│   │
│   ├── services/                    # External API wrappers & business logic
│   │   ├── misp_service.py          # PyMISP wrapper (create/update events, attributes)
│   │   ├── virustotal_service.py    # VirusTotal API v3 client
│   │   ├── otx_service.py           # AlienVault OTX API client
│   │   ├── abuseipdb_service.py     # AbuseIPDB API client
│   │   ├── correlation_service.py   # IOC correlation engine
│   │   ├── severity_service.py      # Severity/confidence scoring
│   │   └── pdf_service.py           # ReportLab-based PDF report builder
│   │
│   ├── utils/
│   │   ├── decorators.py            # @admin_required, @analyst_or_admin_required
│   │   ├── validators.py            # IOC/format validation (IP, domain, URL, hash, etc.)
│   │   └── logger.py                # Rotating file logger setup
│   │
│   ├── static/
│   │   ├── css/style.css            # All custom styling (sidebar, cards, badges, auth page)
│   │   ├── js/main.js               # Sidebar toggle + alert auto-dismiss
│   │   ├── js/dashboard.js          # Chart.js rendering
│   │   ├── js/settings.js           # AJAX "Test Connection" buttons
│   │   └── img/                     # Logo/icons
│   │
│   └── templates/                   # Jinja2 views (the "V" in MVC)
│       ├── base.html                # Master layout (sidebar/navbar/flash messages)
│       ├── login.html
│       ├── dashboard.html
│       ├── ioc_management.html
│       ├── event_management.html
│       ├── event_detail.html
│       ├── search.html
│       ├── reports.html
│       ├── settings.html
│       ├── activity_logs.html
│       ├── partials/                # sidebar.html, navbar.html, flash_messages.html
│       └── errors/                  # 404.html, 403.html, 500.html
│
├── database/
│   ├── schema.sql                   # CREATE TABLE statements for all 6 tables
│   └── sample_data.sql              # Sample events/IOCs/users for demo purposes
│
├── reports_output/                  # Generated PDF reports are saved here
├── logs/                            # Rotating application log files
├── run.py                           # Entry point + `init-db` / `seed-db` CLI commands
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Tech Stack

| Layer               | Technology                                             |
|----------------------|--------------------------------------------------------|
| Frontend             | HTML5, CSS3, Bootstrap 5, Bootstrap Icons, JavaScript (fetch/AJAX), Chart.js |
| Backend              | Python 3.10+, Flask 3, Flask-Login, Flask-Bcrypt        |
| ORM / Database       | SQLAlchemy (Flask-SQLAlchemy), MySQL 8, PyMySQL driver  |
| Threat Intel Platform| MISP (via PyMISP)                                       |
| External APIs        | VirusTotal API v3, AlienVault OTX API, AbuseIPDB API    |
| PDF Reporting        | ReportLab                                               |
| Architecture         | MVC via Flask Blueprints + a dedicated Service layer    |

---

## Database Schema

Six core tables (full DDL in [`database/schema.sql`](database/schema.sql)):

| Table               | Purpose                                                          |
|----------------------|-------------------------------------------------------------------|
| `users`              | Accounts with `admin` / `analyst` roles, bcrypt password hashes   |
| `threat_events`      | Threat events (mirrors MISP event fields: threat level, analysis status, MISP event ID/UUID) |
| `ioc_attributes`     | Individual IOCs (IP/domain/URL/email/hash) linked to an event, with severity, confidence score, correlation flags |
| `reports`            | Metadata + file path for every generated PDF report               |
| `activity_logs`      | Audit trail: who did what, from which IP, and when                |
| `api_configuration`  | Stored base URL/API key/status for MISP, VirusTotal, OTX, AbuseIPDB |

Entity relationships:
- `threat_events.created_by` → `users.id`
- `ioc_attributes.event_id` → `threat_events.id` (cascade delete)
- `ioc_attributes.created_by` → `users.id`
- `reports.event_id` → `threat_events.id`
- `activity_logs.user_id` → `users.id`

---

## Installation

### Prerequisites
- Python 3.10+
- MySQL 8.0+ running locally or remotely
- (Optional) A MISP instance + API key, if you want live MISP sync
- API keys for VirusTotal / AlienVault OTX / AbuseIPDB (all have free tiers)

### 1. Clone and set up a virtual environment
```bash
git clone <your-repo-url> cti-platform
cd cti-platform
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create the MySQL database
```bash
mysql -u root -p < database/schema.sql
```
This creates the `cti_platform` database and all tables. (`database/sample_data.sql` is available as a reference SQL dump, but the recommended way to seed demo data is the `seed-db` CLI command below, since it generates correct bcrypt password hashes.)

### 3. Configure environment variables
```bash
cp .env.example .env
```
Edit `.env` and fill in your MySQL credentials and (optionally) your MISP / VirusTotal / OTX / AbuseIPDB API keys. You can also leave the API keys blank and configure them later from the in-app **Settings** page (admin only).

### 4. Initialize tables and seed demo data
```bash
export FLASK_APP=run.py        # Windows (cmd): set FLASK_APP=run.py
flask init-db
flask -db
```

---

## Configuration

All configuration is environment-driven (see `app/config.py` and `.env.example`):

| Variable              | Description                                      |
|------------------------|---------------------------------------------------|
| `SECRET_KEY`           | Flask session signing key — set a long random value in production |
| `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_PORT` / `DB_NAME` | MySQL connection details |
| `MISP_URL` / `MISP_API_KEY` / `MISP_VERIFY_SSL` | MISP instance connection |
| `VIRUSTOTAL_API_KEY`   | VirusTotal API v3 key                              |
| `OTX_API_KEY`          | AlienVault OTX API key                             |
| `ABUSEIPDB_API_KEY`    | AbuseIPDB API key                                  |

API keys can also be entered/updated live from **Settings → API Configuration** (admin only); these are stored in the `api_configuration` table and take precedence at runtime.

---

## Running the Application

```bash
python run.py
```
The app starts on `http://127.0.0.1:5000`. Log in with one of the [default credentials](#default-credentials) below.

For production, run behind a WSGI server instead of the Flask dev server, e.g.:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 run:app
```

---

## Default Credentials

Created by `flask seed-db`:

| Role    | Username  | Password    |
|---------|-----------|-------------|
| Admin   | `admin`   | `Admin@123` |
| Analyst | `analyst` | `Analyst@123` |

**Change these immediately in any real deployment.**

---

## REST API Reference

All endpoints require an authenticated session (log in via the browser first, then reuse the session cookie, or adapt to token auth for external automation).

| Method | Endpoint                    | Description                          |
|--------|------------------------------|---------------------------------------|
| GET    | `/api/iocs`                  | List recent IOCs (JSON)               |
| POST   | `/api/iocs`                  | Create a new IOC                      |
| DELETE | `/api/iocs/<id>`             | Delete an IOC                         |
| GET    | `/api/search?q=<value>`      | Search IOCs by value, with type auto-detection |
| GET    | `/api/events`                | List recent threat events             |
| GET    | `/api/events/<id>`           | Get a single event with its IOCs      |
| POST   | `/api/events`                | Create a new threat event             |

Example:
```bash
curl -X POST http://127.0.0.1:5000/api/iocs \
  -H "Content-Type: application/json" \
  --cookie "session=<your-session-cookie>" \
  -d '{"ioc_type": "ip", "ioc_value": "1.2.3.4", "severity": "high", "tags": "botnet"}'
```

---

## Screenshots / Pages

| Page              | Route              |
|-------------------|---------------------|
| Login              | `/login`            |
| Dashboard          | `/dashboard`        |
| IOC Management     | `/iocs`             |
| Threat Search      | `/search`           |
| Event Management   | `/events`           |
| Event Detail       | `/events/<id>`      |
| Reports            | `/reports`          |
| Settings (Admin)   | `/settings`         |
| Users (Admin)      | `/users`            |
| Activity Logs (Admin) | `/settings/activity-logs` |

---

## Security Notes

- Passwords are hashed with **bcrypt** (Flask-Bcrypt) — never stored in plain text.
- Role-based access control restricts Settings, User Management, and Activity Logs to `admin` accounts only.
- All external API keys are stored server-side and masked in the UI (`APIConfiguration.to_dict()`).
- CSRF protection: for a production deployment, add `Flask-WTF`'s `CSRFProtect` and convert forms to use `{{ form.hidden_tag() }}` / a CSRF token — this mini-project keeps forms plain for simplicity, but this is the first hardening step recommended before any real deployment.
- IOC input is validated server-side (`app/utils/validators.py`) against strict regex patterns for IPs, domains, URLs, emails, and hash formats.
- Set `MISP_VERIFY_SSL=True` in production and use a properly signed certificate on your MISP instance.

---

## Future Improvements

- CSRF tokens + rate limiting (Flask-Limiter) on login and API routes
- WebSocket/live updates for the dashboard threat feed status
- STIX/TAXII feed support alongside MISP
- Docker Compose setup for one-command deployment (Flask + MySQL + MISP)
- Automated scheduled imports (Celery/APScheduler) instead of manual "Import" buttons
- Unit + integration test suite (pytest)

---

## License

This project is provided under the MIT License for educational use as part of a final-year Cyber Security mini project.
