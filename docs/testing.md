# Testing

## Foundation and model checks

The foundation checks cover Django system checks, migration cleanliness, template rendering, route resolution, static-file references, form rendering, CSRF tokens, ORM relationships, constraints, admin registration, and honest empty or planned states.

## Analyzer tests

The Phase 3 URL suite covers safe and suspicious examples, malformed values, URL components, Unicode, length limits, authority syntax, keyword locations, suspicious TLDs, shorteners, ports, encoding, punctuation, path depth, punycode, conservative brand-like structure, deterministic output, and the no-network boundary.

The Phase 4 email suite covers normal and phishing-style content, urgency, threats, account suspension, credentials, passwords, OTPs, payments, banking, suspicious senders, display names, Reply-To mismatches, normal and suspicious URLs, multiple URLs, shorteners, IP-based URLs, HTTP URLs, risky attachments, multipart mail, HTML mail, link-text mismatches, missing headers, malformed MIME, empty input, limits, Unicode, encoded headers, and the no-score contract.

The Phase 5 risk-engine suite covers empty input, indicator dictionaries, weighted URL/email signals, score clamping, exact threshold boundaries, duplicate codes, distinct rules, nested email URL handling, breakdowns, recommendations, summaries, failures, deterministic output, and immutable result contracts.

## Phase 6 workflow tests

The Phase 6 workflow suite verifies URL and email submissions create the correct `Scan` and type-specific detail records, call the existing analyzers and RiskEngine, persist scores and risk fields, persist `risk-v1`, store SHA-256 input hashes, capture non-negative local duration, persist explainable indicators, and preserve nested URL evidence.

The failure tests cover analyzer failures, unexpected exceptions, database write failures, safe error messages, transaction rollback, failed-scan state, and the absence of orphaned URL/email detail records after rollback. View tests cover GET forms, valid POST redirects, invalid input, empty email input, CSRF enforcement, stable result routes, nonexistent-result 404 handling, and the guarantee that result-page GET does not rerun analysis.

## Security regression tests

The project retains tests confirming that user-provided content is escaped, POST requests require CSRF protection, input sizes are bounded, no submitted URL is contacted, no binary attachment is executed, and errors do not expose tracebacks in production mode. The URL, email, and end-to-end workflow tests block DNS, sockets, `urllib.request`, and HTTP-style calls while analysis runs. Production analysis modules contain no network-client imports.

## Manual acceptance path

1. Open Home and confirm the established cybersecurity visual identity remains intact.
2. Open the URL analyzer and submit a safe fictional test value such as `http://192.0.2.10:1234/login/verify`.
3. Confirm the browser redirects to an ID-based result page containing the persisted score, risk level, verdict, indicators, technical URL details, duration, and limitation notice.
4. Refresh the result page and confirm that it loads saved data without creating a second scan or rerunning analysis.
5. Open the email analyzer and submit structured sender, Reply-To, subject, body, and attachment-name values.
6. Confirm the email result displays persisted indicators and sender/URL/attachment counts without rendering trusted HTML or file contents.
7. Submit an obviously invalid URL and confirm validation remains on the form without creating a scan.
8. Open a nonexistent result identifier and confirm a safe styled 404 response does not expose Django debug information.
9. Check the primary layouts at desktop and narrow viewport sizes. The result template includes responsive media-query behavior and does not depend on JavaScript for core content.

## Deferred coverage

History, dashboard statistics, authentication, external APIs, live URL checks, binary attachment scanning, background workers, and future multi-user workflow features remain outside Phase 6.
