# Testing

## Foundation and model checks

The foundation checks cover Django system checks, migration cleanliness, template rendering, route resolution, static-file references, form rendering, CSRF tokens, ORM relationships, constraints, admin registration, and safe empty or planned states.

## Analyzer and risk-engine tests

The Phase 3 URL suite covers safe and suspicious examples, malformed values, URL components, Unicode, length limits, authority syntax, keyword locations, suspicious TLDs, shorteners, ports, encoding, punctuation, path depth, punycode, conservative brand-like structure, deterministic output, and the no-network boundary.

The Phase 4 email suite covers normal and phishing-style content, urgency, threats, account suspension, credentials, passwords, OTPs, payments, banking, suspicious senders, display names, Reply-To mismatches, normal and suspicious URLs, multiple URLs, shorteners, IP-based URLs, HTTP URLs, risky attachments, multipart mail, HTML mail, link-text mismatches, missing headers, malformed MIME, empty input, limits, Unicode, encoded headers, and the no-score contract.

The Phase 5 risk-engine suite covers empty input, indicator dictionaries, weighted URL/email signals, score clamping, exact threshold boundaries, duplicate codes, distinct rules, nested email URL handling, breakdowns, recommendations, summaries, failures, deterministic output, and immutable result contracts.

## Phase 6 workflow tests

The Phase 6 workflow suite verifies URL and email submissions create the correct `Scan` and type-specific detail records, call the existing analyzers and RiskEngine, persist scores and risk fields, persist `risk-v1`, store SHA-256 input hashes, capture non-negative local duration, persist explainable indicators, and preserve nested URL evidence. Failure tests cover analyzer failures, unexpected exceptions, database write failures, safe error messages, transaction rollback, and the absence of orphaned detail records. View tests cover valid POST redirects, invalid input, CSRF enforcement, stable result routes, nonexistent-result handling, and GET result pages that do not rerun analysis.

## Phase 7 history tests

The history suite covers an honest empty state, persisted rows, newest-first ordering, URL filtering, email filtering, every risk-level filter, completed and failed status filters, scan ID search, hostname search, sender search, subject search, 15-item pagination, preservation of filters in pagination links, existing result-route links, failed-scan visibility, safe failure messaging, read-only GET behavior, and a bounded history query count.

History deliberately searches bounded fields only: scan ID, URL hostname/original URL, sender, sender domain, Reply-To, and subject. It does not search unlimited raw email bodies. The history query uses `select_related` for the useful one-to-one URL/email detail rows and `Paginator` for bounded page loading.

## Phase 7 dashboard tests

The dashboard suite covers zero scans, one or more URL scans, one or more email scans, total/type/completed/failed counts, safe-low/high/critical counts, average/highest/lowest completed scores, five-level risk distribution, recent activity limited to eight rows, filtered metric links, dashboard read-only behavior, and equality between displayed context values and database-derived expected values.

A query-count regression test confirms the dashboard uses a bounded number of ORM queries rather than querying once per scan. The implementation uses aggregate `Count`, `Avg`, `Max`, and `Min` queries, one grouped risk-distribution query, and one bounded recent-activity query. Statistics are computed server-side and are not produced in JavaScript.

## Security and privacy regression tests

The project retains tests confirming that user-provided content is escaped, POST requests require CSRF protection, input sizes are bounded, no submitted URL is contacted, no binary attachment is executed, and errors do not expose tracebacks or internal exception text. History and dashboard GET requests cannot create scans, invoke analyzers, or invoke the RiskEngine. Production workflow modules contain no network-client imports or command execution.

History and dashboard explicitly represent all scans stored in the local application database. They do not claim user isolation, do not use “my scans” wording, and do not display full email bodies or raw email content.

## Manual acceptance path

1. Open Home and confirm the established cybersecurity visual identity remains intact.
2. With an empty test database, open Dashboard and History and verify polished zero states with no fabricated statistics or records.
3. Submit a safe fictional URL such as `http://192.0.2.10:1234/login/verify`.
4. Refresh Dashboard and verify total, URL, completed, score, and risk-distribution values update from the persisted scan.
5. Submit a safe fictional structured email and verify the dashboard updates again.
6. Open History and confirm both scans appear newest first with type, risk, score, timestamp, duration, status, and result links.
7. Use URL, Email, risk, status, and search filters; verify query-string state remains visible and no scan is triggered.
8. Create enough safe local test records to verify pagination and filter preservation.
9. Follow View Result from History and confirm it uses the existing result route.
10. Refresh History and Dashboard and verify no duplicate records are created.
11. Check desktop and narrow viewport layouts. On small screens, history remains usable through bounded horizontal table scrolling and dashboard cards stack without losing labels or values.
12. Confirm the all-database privacy limitation is visible and no user-specific history is implied.
