# Architecture

## Project status

The project is a complete local Django application for explainable phishing-indicator analysis. Phases 1–8 delivered the foundation, persistence, deterministic URL and email analyzers, centralized RiskEngine, transactional scan workflow, persisted results, real History and Dashboard read models, security hardening, and adversarial QA. Phase 9 polishes the product UI, accessibility affordances, local branding, portfolio documentation, and screenshot readiness without changing analyzer logic, RiskEngine behavior, database models, or scan orchestration.

Authentication, user-specific isolation, live reputation, DNS, network requests, machine learning, binary attachment scanning, and background workers remain intentionally out of scope.

## Current architecture

The application is a small Django monolith using Django templates, CSS3, minimal vanilla JavaScript, SQLite, and the Django ORM. The logical components are `core`, `scans`, `analysis`, and `dashboard`.

- `core` owns the public Home and About pages.
- `scans` owns forms, persistence models, scan services, result views, History, and admin registration.
- `analysis` contains framework-independent contracts, constants, text helpers, URL analysis, email analysis, and RiskEngine scoring.
- `dashboard` reads persisted scans and presents server-derived aggregate statistics.

The UI uses local static assets, a simple local SVG favicon, system font fallbacks, responsive CSS, and minimal JavaScript for navigation and sample-email field population. No external CDN, font, icon, animation, or JavaScript runtime dependency is used.

## Database layer

The database uses a central `Scan` model for shared metadata and result summaries. `URLScan` and `EmailScan` store type-specific data through one-to-one relationships. `Indicator` stores explainable signals connected to a scan through a foreign key.

Models use bounded field lengths, nullable fields for values unavailable at scan creation, choices for enumerated values, validators for score and point ranges, and SQLite-compatible check constraints. Frequently queried history and dashboard fields—creation time, scan type, status, and risk level—are indexed. Indicators have a compound index on scan and display order.

### Relationships

```text
Scan 1 ─── 0..1 URLScan
Scan 1 ─── 0..1 EmailScan
Scan 1 ─── many Indicator
```

A completed scan stores its score, risk level, verdict, rule version, type-specific input, and indicators. A result page loads this material directly from the database without invoking an analyzer or the RiskEngine again.

### Persistence models

| Model | Role |
|---|---|
| `Scan` | Common scan status, score, verdict, rule version, timestamps, hash, duration, and error metadata |
| `URLScan` | Original URL and locally parsed URL components; it contains no network behavior |
| `EmailScan` | Structured sender, domain, Reply-To, subject, body, attachment names, and bounded optional raw email |
| `Indicator` | Explainable code, category, title, severity, points, evidence, explanation, recommendation, and display order |

## Security boundary

Submitted URLs are stored and analyzed as data only. No model save hook, signal, admin action, service helper, or UI interaction performs DNS resolution, HTTP requests, HTTPS requests, redirect following, crawling, or external reputation checks. Attachment names are text only; binary uploads are not supported.

Django autoescaping and CSRF protection remain enabled. Raw content is bounded at the form, analyzer, and model boundaries. User-controlled content is never rendered with `|safe`; the UI contains no dynamic HTML injection or dynamic code execution. Result failures show a generic static state rather than persisted internal exception text.

## URL analysis pipeline

The framework-independent URL analyzer follows this local pipeline:

```text
URL input string → bounded checks → standard-library parser → feature extraction → rule evaluation → structured indicators
```

It returns a `URLAnalysisResult` containing the original and normalized URL, deterministic technical features, explainable indicators, and metadata confirming that network access was not used. It does not write to Django models and it does not calculate a final score, risk level, or verdict.

## Email analysis pipeline

The framework-independent email analyzer follows this local pipeline:

```text
structured fields or bounded MIME text
        ↓
header/body/MIME extraction
        ↓
social-engineering rules + URL extraction
        ↓
local reuse of the URL analyzer
        ↓
structured email result
```

The analyzer treats email content as untrusted text. Plain-text and HTML MIME parts are inspected locally; HTML is parsed as inert text and is never rendered or executed. Attachment filenames and declared content types are metadata only. Binary attachment content is never opened, downloaded, unpacked, or executed.

HTTP(S) URL strings found in body text or HTML `href` attributes are passed to the URL analyzer. Extracted URLs are never opened or expanded. Nested URL features and indicators remain available in the email result contract.

## Centralized RiskEngine pipeline

The framework-independent RiskEngine accepts structured indicators from either analyzer:

```text
URL Analyzer + Email Analyzer
                ↓
             Indicators
                ↓
           RiskEngine
                ↓
    Score / Risk Level / Verdict
                ↓
              SQLite
```

The engine deduplicates repeated rule codes, applies centralized `risk-v1` weights, handles nested email URL context, clamps the score to 0–100, maps it to the five existing risk bands, and returns a transparent breakdown, summary, recommendations, and metadata. It remains independent of Django and does not write database records.

## End-to-end scan workflow

```text
POST form
   ↓
Django view
   ↓
Scan service
   ↓
Analyzer
   ↓
RiskEngine
   ↓
Transactional persistence
   ↓
Stable persisted result route
```

For URL submissions, the service creates a pending `Scan` and `URLScan`, runs the local URL analyzer, sends indicators to the RiskEngine, persists the score and explainable indicators, and marks the scan completed. Email submissions follow the same sequence with `EmailScan`; nested URL indicators reuse the same local URL analyzer and are not double-counted.

The service measures local duration with a monotonic timer and computes a SHA-256 input hash. Successful results persist the RiskEngine score, risk level, verdict, rule version, duration, and indicator evidence. Unexpected failures roll back type-specific detail and indicators, then retain only a safe failed scan state. Analyzer failures are also represented without exposing internal exception details.

The stable result route is `/scans/result/<scan_id>/`. A GET retrieves persisted records and renders them without rerunning analysis. The result interface presents the numeric score, text risk level, verdict, summary, bounded evidence, explanations, recommendations, technical details, metadata, and local-analysis limitation.

## History and Dashboard read models

History is a read-only database view over persisted `Scan` records. It uses a filtered and ordered ORM queryset, selects useful type-specific detail rows for display, and passes the queryset through Django `Paginator` with 15 records per page. Type, risk, and status filters are normalized from GET parameters. A bounded search covers scan ID, URL hostname/original URL, sender, sender domain, Reply-To, and subject; raw email bodies are excluded.

History pagination preserves active filters through an encoded query string. Each row links to the existing result route. Browsing, filtering, searching, and refreshing History does not invoke an analyzer, invoke the RiskEngine, or create records. Failed scans remain visible with a safe status message and without internal error text.

Dashboard values are calculated server-side from persisted rows. Aggregate `Count`, `Avg`, `Max`, and `Min` queries supply metric cards and completed-score statistics; one grouped query supplies the five-level risk distribution; and one bounded recent-activity query supplies the latest records. CSS bars and tracks visualize those server-derived values, not JavaScript-generated statistics.

Because authentication is not enabled, History and Dashboard are explicitly **all-scans views for the local application database**, not user-specific or “my scans” views. Raw email bodies and unnecessary attachment data are not exposed in list or dashboard views.

## Product UI and accessibility

Phase 9 keeps the dark cybersecurity aesthetic while introducing a concise product identity: **Local, explainable phishing indicator analysis for URLs and email text.** Shared templates provide consistent branding, navigation, active states, skip-link support, focus-visible styling, a local favicon, and a theme-color hint. Forms expose their purpose, accepted text-only input, bounds, local-analysis boundary, validation feedback, and safe sample-email interaction.

The result page treats persisted score and risk text as primary hierarchy, then presents evidence, recommendations, technical details, metadata, and limitations. Dashboard and History preserve their real data behavior while using clearer card, table, empty-state, and responsive layouts. Mobile navigation is progressively disclosed through the existing small vanilla JavaScript toggle, with CSS breakpoints for dashboard cards, forms, result cards, and history overflow.

## Phase boundary

Phase 9 is limited to presentation and portfolio readiness. It does not change analyzer rules, RiskEngine calculations, persistence models, migrations, scan service semantics, URLs, authentication, external services, DNS, live HTTP checks, machine learning, binary uploads, or background workers.
