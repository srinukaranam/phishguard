# 🛡️ PhishGuard

**Phishing Email Analysis and Threat Intelligence Platform**

PhishGuard is a full-stack, SOC-grade web application designed to analyze suspicious `.eml` emails. It extracts Indicators of Compromise (IOCs), applies explainable detection rules, enriches them with threat intelligence, and generates investigation reports.

## ✨ Features
- **Secure Ingestion:** Validates magic bytes, enforces size limits, and safely stores `.eml` files outside the web root.
- **Deep Parsing:** Extracts RFC 5322 / MIME headers, bodies, and attachment hashes without executing payloads.
- **Explainable Detection:** Modular rules identify spoofing (`HDR`), dangerous URLs (`URL`), and malicious attachments (`ATT`).
- **Threat Intelligence:** Asynchronously queries VirusTotal v3 with PostgreSQL caching to respect API rate limits.
- **Case Management:** Analyst notes, status workflows, and a print-ready HTML/PDF investigation report.
- **Secure by Design:** CSRF protection, rate limiting, CSP headers, and SSRF-safe URL extraction.

## 🧱 Tech Stack
- **Backend:** Python 3.13, Flask, SQLAlchemy, PostgreSQL
- **Frontend:** Tailwind CSS, Chart.js, Vanilla JS
- **Testing:** pytest, pytest-flask
- **APIs:** VirusTotal v3

## 🚀 Quickstart

### 1. Prerequisites
- Python 3.11+
- PostgreSQL 14+

### 2. Installation
```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

Configuration
cp .env.example .env

Edit .env:

Generate a SECRET_KEY (e.g., python -c "import secrets; print(secrets.token_hex(32))")

Set your DATABASE_URL

Get a free VIRUSTOTAL_API_KEY from virustotal.com

 Database Setup
 Create the database in PostgreSQL, then run:

bash
flask db upgrade
python -m scripts.create_admin --email admin@phishguard.local

Run
bash
flask --app app.py run --debug

 License


---

### Step 3: Create `.env.example`
Recruiters need to know which environment variables are required. Create `E:\phishguard\.env.example`:

```dotenv
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=replace-with-a-long-random-string
DATABASE_URL=postgresql://phishguard:change_me_dev_only@127.0.0.1:5432/phishguard_db
MAX_UPLOAD_BYTES=5242880
VIRUSTOTAL_API_KEY=