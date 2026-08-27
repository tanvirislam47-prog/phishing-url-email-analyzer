# Phishing URL & Email Analyzer

An educational Django application for examining suspicious characteristics in URLs and emails through explainable local heuristics.

> **Phase 6 status:** The project foundation, interface, database models, migration, admin registrations, offline URL analyzer, offline email analyzer, centralized risk engine, end-to-end local scan workflow, persisted result page, analyzer tests, workflow tests, and documentation are implemented. History functionality and dashboard statistics remain planned for later phases.

## Overview

The application helps users understand common phishing signals without opening or connecting to submitted URLs. The local analyzers and RiskEngine preserve evidence for each finding and explain why it matters; Phase 6 now persists completed results for review.

## Current architecture

This is a simple Django monolith using:

- Python
- Django
- Django templates
- SQLite configuration
- HTML5 and CSS3
- Minimal vanilla JavaScript

The logical components are `core`, `scans`, `analysis`, and `dashboard`. Phase 6 includes the project configuration, reusable base template, responsive navigation, landing page, About page, connected URL and email forms, persisted result page, empty history state, zero-state dashboard, Django ORM persistence models, migrations, admin registrations, deterministic offline URL and email analysis, centralized risk scoring, transactional scan orchestration, workflow tests, documentation, and repository hygiene files.

## Planned features

Later phases will implement real scan history and dashboard summaries. The Phase 3 URL analyzer and Phase 4 email analyzer return indicators and points metadata; the Phase 5 risk engine consumes those indicators, and the Phase 6 workflow persists its bounded score, risk level, verdict, breakdown-derived indicators, recommendations, and `risk-v1` metadata.

## Project structure

```text
config/       Django settings and root routing
core/         Home and About pages
scans/        Scan forms, placeholder routes, and future persistence
analysis/     Future pure-Python analyzers and risk engine
dashboard/    Dashboard foundation
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

Copy `.env.example` to `.env` only if you want to manage local environment values separately. The current settings module reads environment variables directly; no dotenv package is required for Phase 1.

## Running the project

From the project root:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

Then open `http://127.0.0.1:8000/` in a browser.

## Testing

Phase 6 verification includes Django system checks, migration checks, ORM model tests, URL analyzer tests, email analyzer tests, risk-engine tests, service and view workflow tests, transaction rollback tests, MIME and URL-reuse tests, network-safety tests, relationship tests, database-constraint tests, admin-registration tests, route rendering, persisted result rendering, static assets, CSRF-protected forms, responsive layout, safe 404 handling, and honest zero or planned states. Future phases will add history and dashboard workflow tests.

## Security boundary

The application must never open, crawl, resolve, or connect to a submitted URL. Phase 6 contains URL and email analysis logic, centralized local scoring, and local persistence, but no network client; all submitted URLs, email content, and attachment names are treated as untrusted local data only. User-provided content remains untrusted input and must continue to be escaped when rendered.

The current email foundation accepts attachment names as text only. It does not accept, execute, unpack, preview, or scan binary files. Model fields are bounded to reduce unnecessary retention of sensitive submitted content.

## Limitations

This is an analysis aid, not a guarantee of safety or maliciousness. Local heuristics can produce false positives and false negatives. External reputation, DNS, crawling, malware scanning, and machine learning are not part of the current foundation.

## Future improvements

Possible later work includes a versioned deterministic rule catalog, scan persistence, user-specific history, richer accessibility testing, optional `.eml` parsing, external threat intelligence behind explicit consent, and separate quarantine architecture for any future binary uploads.
