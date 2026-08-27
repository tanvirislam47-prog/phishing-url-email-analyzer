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

## URL analysis pipeline

Phase 3 adds a framework-independent URL analyzer in `analysis/url_analyzer.py`. The data flow is:

```text
URL input string → safe input checks → standard-library parser → feature extraction → rule evaluation → structured indicators
```

The analyzer returns a `URLAnalysisResult` containing the original and normalized URL, deterministic technical features, explainable indicators, and metadata confirming that network access was not used. It does not write to Django models and it does not calculate a final score, risk level, or verdict.

The model layer remains intentionally independent from the analyzer. A later scan workflow can persist the returned fields and indicators, while future rule changes can be versioned through the stored `rule_version` without requiring historical results to be recomputed.

## Email analysis pipeline

Phase 4 adds a framework-independent email analyzer in `analysis/email_analyzer.py`. The data flow is:

```text
raw email or structured fields → bounded input checks → stdlib email parser → header/body/MIME extraction → social-engineering rules → URL extraction → Phase 3 URL analyzer → structured indicators
```

The analyzer treats email content as untrusted text. Plain-text and HTML MIME parts are inspected locally; HTML is parsed as inert text and is never rendered or executed. Attachment filenames and declared content types are retained as metadata only. Binary attachment content is never opened, downloaded, unpacked, or executed.

HTTP(S) URLs found in the body or HTML href attributes are passed to the existing Phase 3 URL analyzer. URL detection logic is not duplicated inside the email analyzer, and extracted URLs are never opened or expanded. Nested URL features and indicators remain available in the email result contract.

The email analyzer returns `EmailAnalysisResult` with email features, indicators, extracted URL analysis, attachment metadata, bounded errors, and metadata confirming no network access. It does not write to Django models and does not calculate a final score, risk level, or verdict.

## Centralized risk-engine pipeline

Phase 5 adds the framework-independent risk engine in `analysis/risk_engine.py`. The full analysis pipeline is:

```text
URL Analyzer + Email Analyzer
                ↓
             Indicators
                ↓
           Risk Engine
                ↓
   Score / Risk Level / Verdict
                ↓
       Future persistence layer
```

The engine accepts `IndicatorResult` objects or compatible dictionaries, deduplicates by rule code, applies centralized weights, handles nested email URL context, clamps the score to 0–100, maps the score to the existing `Scan.RiskLevel` choices, and returns a transparent breakdown, summary, recommendations, and `risk-v1` metadata. It remains independent of Django and does not write database records.

## Phase 6 end-to-end workflow

Phase 6 connects the existing forms through a thin Django view and service boundary:

```text
Form
  ↓
View
  ↓
Service
  ↓
Analyzer
  ↓
RiskEngine
  ↓
Persistence
  ↓
Result Page
```

For URL submissions, the service creates a pending `Scan` and `URLScan`, runs the local URL analyzer, sends its indicators to the RiskEngine, persists the score and explainable indicators, and marks the scan completed. Email submissions follow the same sequence with `EmailScan`; nested URL indicators from the Phase 4 email result are passed to the same RiskEngine without duplicating URL logic.

The service layer measures local duration with a monotonic timer and computes a SHA-256 input hash. Successful results persist the RiskEngine score, risk level, verdict, rule version, duration, and applied indicator points. An unexpected exception rolls back type-specific detail and indicator records, then leaves only a safe `FAILED` scan record. Analyzer failures are also represented as failed scans without exposing internal exception details.

The stable result route is `/scans/result/<scan_id>/`. A GET retrieves persisted records and renders them without rerunning any analyzer or the RiskEngine. The result page displays bounded evidence, explanations, recommendations, URL technical details or email context, and a clear local-analysis limitation.

## Planned architecture

Later phases will add real history, dashboard statistics, authentication, and any additional product capabilities. The current URL analyzer, email analyzer, risk engine, and Phase 6 workflow remain local and separate from external reputation services.

## Phase boundary

Phase 6 implements local end-to-end scan orchestration and persisted result rendering in addition to the Phase 3 URL analyzer, Phase 4 email analyzer, and Phase 5 risk engine. It does not implement real history functionality, dashboard statistics, external APIs, DNS, live HTTP requests, machine learning, binary attachment uploads, authentication, or background workers.
