# Phishing URL & Email Analyzer

An educational Django application for examining suspicious characteristics in URLs and emails through explainable local heuristics.

> **Phase 1 status:** The project foundation and interface are implemented. Real URL analysis, email analysis, risk scoring, scan persistence, history records, and dashboard statistics are planned for later phases and are not currently available.

## Overview

The application is designed to help users understand common phishing signals without opening or connecting to submitted URLs. The future analysis engine will preserve evidence for each finding and explain why it matters.

## Current architecture

This is a simple Django monolith using:

- Python
- Django
- Django templates
- SQLite configuration
- HTML5 and CSS3
- Minimal vanilla JavaScript

The logical components are `core`, `scans`, `analysis`, and `dashboard`. Phase 1 includes the project configuration, reusable base template, responsive navigation, landing page, About page, URL and email input foundations, placeholder result page, empty history state, zero-state dashboard, documentation stubs, and repository hygiene files.

## Planned features

Later phases will implement local URL structural analysis, email social-engineering analysis, explainable 0–100 risk scoring, detailed result pages, persisted scan history, and real dashboard summaries.

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

Phase 1 verification centers on Django system checks, route rendering, template references, static assets, CSRF-protected forms, responsive layout, and honest zero or planned states. Future phases will add unit and security regression tests for the analysis engines and risk engine.

## Security boundary

The application must never open, crawl, resolve, or connect to a submitted URL. Phase 1 contains no URL analysis logic and no network client. User-provided content remains untrusted input and must continue to be escaped when rendered.

The current email foundation accepts attachment names as text only. It does not accept, execute, unpack, preview, or scan binary files.

## Limitations

This is an analysis aid, not a guarantee of safety or maliciousness. Local heuristics can produce false positives and false negatives. External reputation, DNS, crawling, malware scanning, and machine learning are not part of the current foundation.

## Future improvements

Possible later work includes a versioned deterministic rule catalog, scan persistence, user-specific history, richer accessibility testing, optional `.eml` parsing, external threat intelligence behind explicit consent, and separate quarantine architecture for any future binary uploads.
