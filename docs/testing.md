# Testing

## Current Phase 1 and Phase 2 checks

The foundation checks cover Django system checks, migration cleanliness, template rendering, route resolution, static-file references, form rendering, CSRF tokens, ORM relationships, constraints, admin registration, and honest empty or planned states.

## Phase 3 URL analyzer tests

Phase 3 adds pure-Python tests for safe and suspicious examples, empty and whitespace input, missing schemes, malformed URLs, invalid ports, IPv4 and IPv6, URL components, Unicode, length limits, authority syntax, keyword locations, suspicious TLDs, shorteners, ports, encoding, punctuation, path depth, punycode, conservative brand-like structure, deterministic output, and the structured result contract.

## Phase 4 email analyzer tests

Phase 4 adds tests for normal and phishing-style email content, urgency, threats, account suspension, credentials, passwords, OTPs, payments, banking, suspicious senders, display names, Reply-To mismatches, normal and suspicious URLs, multiple URLs, shorteners, IP-based URLs, HTTP URLs, risky attachments, multiple attachment names, multipart mail, HTML mail, link-text mismatches, missing headers, malformed MIME, empty input, length limits, Unicode, encoded headers, multiple indicators, the no-score contract, and deterministic output.

## Planned future tests

Later analysis phases should add risk thresholds, duplicate suppression, score bounds, persistence workflow integration, and user-facing result rendering.

## Security regression tests

The project should retain tests confirming that user-provided content is escaped, POST requests require CSRF protection, input sizes are bounded, no submitted URL is contacted, no binary attachment is executed, and errors do not expose tracebacks in production mode. The Phase 3 and Phase 4 analyzer suites block DNS, sockets, `urllib.request`, and HTTP-style calls while analysis runs, proving that URL and email feature extraction remains local. Phase 4 also patches the imported Phase 3 URL analyzer to prove reuse rather than duplicated URL rules.

## Manual acceptance path

1. Open Home.
2. Follow every navigation link.
3. Submit the URL form and verify that no scan result or record is fabricated.
4. Submit the email form and verify the same behavior.
5. Use the sample email control and clear the form.
6. Open the result, history, dashboard, and About pages.
7. Confirm static CSS and JavaScript assets load.
8. Check the primary layouts at desktop and narrow viewport sizes.
