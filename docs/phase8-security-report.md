# Phase 8 Security Scan Report

## Executive summary

Phase 8 security hardening and adversarial QA found and corrected three genuine issues: an external browser font dependency that conflicted with the local/offline boundary, direct rendering of persisted failure text that could disclose implementation details, and stale user-facing copy that described implemented functionality as future work. The hardened project passed the full regression suite and the focused Phase 8 suite.

| Verification | Result |
|---|---|
| Focused Phase 8 modules | **28 passed** |
| Full Django regression suite | **187 passed** |
| `python manage.py check` | Passed with no issues |
| `python manage.py makemigrations --check --dry-run` | Passed; no changes detected |
| `git diff --check` | Passed |
| Browser QA | Passed across forms, normal/suspicious scans, results, history, dashboard, filters, pagination edge behavior, validation, 404, and responsive overflow inspection |

## Findings and remediation

| Severity | Affected file | Finding | Fix | Test or verification | Residual risk |
|---|---|---|---|---|---|
| Medium | `templates/base.html`, `static/css/styles.css` | Google Fonts references caused external browser asset requests and undermined the intended offline UI boundary. | Removed remote font links and retained local system font stacks. | Header/HTML assertion, source audit, browser home/form/dashboard QA. | Fonts vary by host system; no remote asset request occurs. |
| Medium | `templates/scans/result.html` | Failed result pages rendered `Scan.error_message` directly, which could expose internal exception text if such data entered persistence. | Replaced the dynamic failure message with static generic copy. | `test_failed_result_never_exposes_persisted_internal_error`; browser 404/result QA. | Database access remains unauthenticated and all local records are visible to anyone with application access. |
| Low | `templates/core/home.html`, `templates/core/about.html` | Several pages described results, history, dashboards, or analysis as future functionality after implementation. | Updated copy to reflect the current Phase 8 implementation and limitations. | Home/About browser QA and full template regression. | Documentation can become stale again if later phases change scope. |
| Informational | `config/settings.py` | Baseline security headers lacked an explicit referrer policy. | Added `SECURE_REFERRER_POLICY = "same-origin"`; retained nosniff and clickjacking protection. | Security-header regression test and Django system check. | HTTPS-only deployment settings remain intentionally outside local Phase 8 scope. |

## Category results

| Category | Result |
|---|---|
| XSS and unsafe template rendering | No issue found after hardening; autoescaping is retained and no `|safe` usage exists. |
| SQL injection | No issue found; history uses Django ORM and adversarial injection-shaped searches are covered. |
| CSRF | No issue found; middleware and form tokens remain active and invalid POST is rejected. |
| Result-ID handling | No issue found; nonexistent IDs use the safe branded 404 and malformed paths use safe route-level 404 behavior. |
| Error disclosure | Fixed; failed result pages now use generic static copy and do not expose internal error text. |
| Transaction/orphan integrity | No issue found; rollback tests cover analyzer, detail creation, risk, and indicator persistence failures. |
| Score/risk integrity | No issue found; database score constraints and exact centralized risk thresholds are covered. |
| Runtime network safety | No issue found; runtime blocking tests observe zero DNS, socket, HTTP, or URL-opening calls. |
| Filesystem and process safety | No issue found; analyzer tests block file opening and process execution paths. |
| Resource bounds | No issue found; hostile URL/email sizes, nested URLs, attachments, HTML, and indicators remain capped. |
| History/dashboard safety | No issue found; GET routes are read-only, filters are bounded, and pagination failures resolve safely. |
| JavaScript safety | No issue found; no `innerHTML`, `eval`, `Function`, fetch, or dynamic script execution is present. |
| Dependency exposure | No issue found; runtime dependency remains Django only. |
| Secret exposure | No issue found; environment files contain placeholders, local secrets/database files are ignored, and no credentials are committed. |

## Scope and residual limitations

The application remains an unauthenticated local/offline analysis aid. It does not provide user accounts or user isolation, verify live website reputation or remote content, perform DNS or HTTP checks, use external APIs or machine learning, accept binary attachments, execute files, or use Celery/background workers. Local rule-based analysis can produce false positives and false negatives and cannot establish safety or maliciousness.
