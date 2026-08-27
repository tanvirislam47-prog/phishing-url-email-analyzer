# Architecture

## Project status

Phase 2 adds the database and persistence foundation to the Django monolith. The current project includes the Phase 1 interface plus Django ORM models, a proper migration, admin registrations, and model tests.

Real URL detection rules, email detection rules, risk scoring, and user-facing scan orchestration remain deferred. The database is ready to store those future results without requiring an analyzer to rerun when a historical result is displayed.

## Current architecture

The project uses Django templates, CSS3, minimal vanilla JavaScript, SQLite, and the Django ORM. The logical components are `core`, `scans`, `analysis`, and `dashboard`.

The `scans` app owns persistence models, forms, routes, and a small pending-scan helper. The `analysis` package remains a placeholder for future pure-Python analyzers and the risk engine. The dashboard remains a zero-state presentation foundation and does not query scan statistics yet.

## Database layer

The database uses a central `Scan` model for shared metadata and future result summaries. `URLScan` and `EmailScan` store type-specific submission data through one-to-one relationships. `Indicator` stores individual explainable signals connected to a scan through a foreign key.

The models use bounded field lengths, nullable fields for values that are not available at scan creation time, choices for enumerated values, validators for score and point ranges, and SQLite-compatible database check constraints. Frequently queried history/dashboard fields—creation time, scan type, status, and risk level—are indexed. Indicators have a compound index on scan and display order.

### Relationships

```text
Scan 1 ─── 0..1 URLScan
Scan 1 ─── 0..1 EmailScan
Scan 1 ─── many Indicator
```

A completed historical scan stores its score, risk level, verdict, rule version, type-specific input, and indicators. A result page can later load this material directly from the database without invoking a URL analyzer or email analyzer again.

### Persistence models

| Model | Role |
|---|---|
| `Scan` | Common scan status, score, verdict, rule version, timestamps, hash, duration, and error metadata |
| `URLScan` | Original URL and future locally parsed URL components; it contains no network behavior |
| `EmailScan` | Structured sender, domain, Reply-To, subject, body, attachment names, and bounded optional raw email |
| `Indicator` | Explainable code, category, title, severity, points, evidence, explanation, recommendation, and display order |

## Security boundary

Submitted URLs are stored as data only. No model save hook, signal, admin action, or service helper performs DNS resolution, HTTP requests, HTTPS requests, redirect following, crawling, or external reputation checks. Attachment names are text only; binary uploads are not supported.

Django autoescaping and CSRF protection remain enabled. Raw content is bounded at the model layer and is not exposed in admin list views. Future analysis code must continue to truncate evidence before persistence and render all user content safely.

## Planned architecture

Later phases will add pure Python URL and email analyzers, a deterministic risk engine, scan orchestration, result persistence calls, real history, and dashboard statistics. The model layer is intentionally independent from those analyzers so rule changes can be versioned through `rule_version` while historical output remains renderable.

## Phase boundary

Phase 2 does not implement URL detection rules, email detection rules, score calculation, real scan workflow, real history results, real dashboard statistics, external APIs, DNS, HTTP requests, machine learning, uploaded attachments, or authentication.
