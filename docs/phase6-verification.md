# Phase 6 Verification

## Implemented scope

Phase 6 connects the existing URL and email forms to the local analyzers and centralized RiskEngine through `scans/services.py`. Each submission creates a pending `Scan`, creates its type-specific detail record, runs local analysis, persists the RiskEngine result and explainable indicators, records a SHA-256 input hash and non-negative local duration, marks the scan completed, and redirects to a stable ID-based result page.

Unexpected exceptions roll back type-specific detail and indicator records, then leave a safe failed `Scan` record. Analyzer failures also produce failed scans without exposing internal exception text. GET result pages only retrieve persisted rows and do not rerun analyzers or scoring.

## Persisted result behavior

The real result page displays scan type, score, risk level, verdict, summary, timestamp, duration, rule version, stored indicators, evidence, explanations, recommendations, and safe technical details. URL results show parsed scheme, hostname, domain, subdomain, port, path, and query/fragment presence. Email results show sender, sender domain, Reply-To, subject, extracted URL count, and attachment-name count.

The result page uses escaped Django template output, does not render submitted HTML as trusted content, and includes an explicit limitation that URLs were never opened, resolved, crawled, or connected to.

## Verification results

| Check | Result |
|---|---|
| Phase 6 workflow/view/form tests | **31 passed** |
| Complete project test suite | **149 passed** |
| `python manage.py check` | Passed with no issues |
| `python manage.py migrate --noinput` | Passed; migration `scans.0002` applied |
| Migration drift check | Passed; no changes detected |
| URL browser workflow | Passed; POST redirected to `/scans/result/1/` with persisted score and indicators |
| Email browser workflow | Passed; POST redirected to `/scans/result/2/` with persisted score and indicators |
| Invalid URL browser check | Passed; validation remained on the form |
| Nonexistent result browser check | Passed; styled 404 showed no Django debug details |
| Score visualization | Passed; score ring reflected persisted score |
| Network safety | Passed; workflow tests blocked DNS, sockets, and `urllib.request` |
| Production workflow safety scan | No network, command-execution, or unsafe file-access patterns found in `scans/*.py` |

## Scope confirmation

Phase 6 does not implement real history functionality, dashboard statistics, external APIs, DNS, live HTTP/HTTPS checks, authentication, user accounts, binary attachment uploads, machine learning, background workers, Celery, or asynchronous external scanning.
