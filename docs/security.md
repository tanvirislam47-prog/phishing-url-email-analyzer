# Security Model and Hardening

## Scope and security boundary

This application performs local rule-based analysis of submitted URL strings and email text. It does not verify live website reputation or remote content. Submitted URLs are never opened, resolved, crawled, redirected, or requested. No DNS, external API, machine-learning service, background worker, or binary attachment workflow is present.

The threat model treats URL input, email headers, email bodies, HTML fragments, attachment names, extracted URL text, history search terms, GET filters, scan identifiers, and database-derived evidence as untrusted. The application is intentionally an unauthenticated local application; history and dashboard pages represent all records in the local database and do not provide user-level authorization or isolation.

## Input validation and resource bounds

URL form input is bounded to 2,048 characters and must contain a parseable scheme and network location. The analyzer separately bounds hostname, path, query, and fragment components. It treats unsupported schemes, malformed authority syntax, loopback-looking addresses, private-looking addresses, IPv4, IPv6, Unicode, IDN/punycode, encoding, fragments, queries, repeated separators, and deep paths as text-analysis cases; it does not connect to any destination.

Structured email fields are bounded before analysis. Raw email parsing, message bodies, header values, attachment-name text, extracted URLs, attachment metadata, and indicator counts have explicit limits. Attachment names are metadata only. The application does not accept binary attachments, open files, unpack archives, execute content, or write user-controlled filesystem paths.

## Output safety and XSS protection

Django template autoescaping remains enabled throughout the server-rendered UI. No template uses `|safe`, and user-controlled URL, sender, Reply-To, subject, body-derived evidence, attachment names, search terms, or database evidence are rendered as escaped text. HTML email fragments are parsed with standard-library inert parsers; script and style contents are excluded from visible-text extraction. The minimal JavaScript uses class and value APIs only and contains no `innerHTML`, `eval`, `Function`, dynamic script injection, or network fetch.

## CSRF and request method behavior

Analyzer forms use POST and include Django CSRF tokens. CSRF middleware remains enabled, and a POST without a valid token is rejected. Analyzer GET routes render forms only. Result, history, and dashboard GET routes read persisted data and do not run analyzers, score content, or create records.

## SQL injection and identifiers

History search and filters use Django ORM expressions and bounded values. No raw SQL is constructed from user input. Invalid type, risk, status, search, page, and result-ID values fail safely, return an empty or bounded view, or resolve to a safe 404 without exposing SQL or tracebacks.

## Persistence, transactions, and score integrity

The scan service creates a pending record, performs local analysis and risk evaluation, and persists details inside transactional workflow boundaries. Unexpected failures produce a generic FAILED state after rollback; type-specific detail and indicator rows are not left orphaned. Completed scores are written from the centralized RiskEngine and are constrained to 0–100 at the model/database layer. Risk bands remain centralized at Very Low 0–19, Low 20–39, Medium 40–59, High 60–79, and Critical 80–100.

## Security headers and configuration

The local Django configuration enables content-type sniffing protection, clickjacking protection, and a same-origin referrer policy. Debug mode and the development secret are explicit configuration values; non-debug mode rejects the placeholder secret. The environment template contains placeholders only, and the database, environment files, virtual environments, caches, and generated static output are excluded from Git.

External Google Fonts were removed during Phase 8 because they violated the intended offline-first browser boundary. The interface now uses system-local font stacks and the local static stylesheet.

## Residual limitations

The application has no authentication, accounts, authorization, or user isolation. A user with access to the local application can see all stored scans, and SQLite records may contain submitted text required for result rendering. Local heuristic analysis can produce false positives and false negatives; it cannot establish safety, maliciousness, ownership, reputation, or live reachability. These limitations are deliberate and remain outside Phase 8 scope.
