# Phishing URL & Email Analyzer

An educational Django application for examining suspicious characteristics in URLs and emails through explainable local heuristics.

> **Phase 8 status:** The project includes the foundation, persistence, offline URL and email analyzers, centralized risk engine, end-to-end local workflow, persisted results, real history, database-driven dashboard statistics, security hardening, adversarial tests, and browser QA. Authentication and user-specific isolation are not enabled.

## Overview

The application helps users understand common phishing signals without opening or connecting to submitted URLs. The local analyzers and RiskEngine preserve evidence for each finding and explain why it matters; Phase 6 persists completed results and Phase 7 presents those records through history and dashboard views.

## Current architecture

This is a simple Django monolith using:

- Python
- Django
- Django templates
- SQLite configuration
- HTML5 and CSS3
- Minimal vanilla JavaScript

The logical components are `core`, `scans`, `analysis`, and `dashboard`. The project includes the configuration, reusable base template, responsive navigation, landing page, About page, connected URL and email forms, persisted result page, real filtered and paginated history, database-driven dashboard, Django ORM persistence models, migrations, admin registrations, deterministic offline URL and email analysis, centralized risk scoring, transactional scan orchestration, adversarial security tests, browser QA, documentation, and repository hygiene files.

## Current implementation

The Phase 3 URL analyzer and Phase 4 email analyzer return indicators and points metadata; the Phase 5 risk engine consumes those indicators, and the Phase 6 workflow persists its bounded score, risk level, verdict, breakdown-derived indicators, recommendations, and `risk-v1` metadata. Phase 7 reads those persisted records for all-database history and server-side dashboard aggregation. Phase 8 hardens the local boundary with security headers, safe failure rendering, adversarial regression tests, runtime network checks, and browser QA.

## Project structure

```text
config/       Django settings and root routing
core/         Home and About pages
scans/        Scan forms, persistence, workflow services, history, and results
analysis/     Pure-Python URL, email, and risk-analysis engines
dashboard/    Database-backed dashboard statistics
 templates/   Server-rendered HTML templates
 static/      CSS and minimal JavaScript
docs/         Architecture, threat model, rules, testing, and demo notes
data/         Local SQLite database location
```

## Local setup

Create and activate a virtual environment if desired, then install the current dependency set:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` only if you want to manage local environment values separately. The current settings module reads environment variables directly; no dotenv package is required for the current phase.

## Running the project

From the project root:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

Then open `http://127.0.0.1:8000/` in a browser.

## Testing

Phase 8 verification includes Django system checks, migration checks, ORM model tests, URL analyzer tests, email analyzer tests, risk-engine tests, service and view workflow tests, adversarial hostile-input tests, XSS and SQL-injection-shaped input tests, CSRF checks, security-header checks, transaction rollback tests, score-boundary tests, runtime network blocking, filesystem/process safety checks, malformed email and URL handling, bounded resource tests, history filters and pagination, dashboard aggregations, persisted result rendering, safe 404 handling, browser QA, and all-database privacy messaging.

## Security

The application performs local rule-based analysis and does not verify live website reputation or remote content. It never fetches submitted URLs, performs DNS lookups, executes attachments, or uses external APIs. Explainable scoring is produced from deterministic local rules, while all user-provided text remains untrusted and escaped in rendered output. CSRF protection, bounded inputs, ORM-based filtering, safe error states, transaction rollback coverage, and conservative security headers are enabled and tested.

The current application has no authentication, user accounts, authorization, or user isolation. History and dashboard pages therefore show every scan stored in the local SQLite database.

## Security boundary

The application must never open, crawl, resolve, or connect to a submitted URL. Phase 8 contains URL and email analysis logic, centralized local scoring, local persistence, history, dashboard aggregation, and adversarial security coverage, but no network client; all submitted URLs, email content, and attachment names are treated as untrusted local data only. User-provided content remains untrusted input and must continue to be escaped when rendered.

The current email foundation accepts attachment names as text only. It does not accept, execute, unpack, preview, or scan binary files. Model fields are bounded to reduce unnecessary retention of sensitive submitted content.

## Limitations

This is an analysis aid, not a guarantee of safety or maliciousness. Local heuristics can produce false positives and false negatives. External reputation, DNS, crawling, malware scanning, and machine learning are not part of the current foundation.

## Future improvements

Possible later work includes richer accessibility testing, optional `.eml` parsing improvements, and—only if the scope changes explicitly—user-specific history, external threat intelligence, or separate quarantine architecture for binary uploads. Those capabilities are not part of the current application.
