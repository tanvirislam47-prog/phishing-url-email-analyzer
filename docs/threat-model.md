# Threat Model

## Scope

The Phase 1 application is a local web interface for preparing suspicious URL and email submissions. It does not visit URLs, upload attachments, call external services, or persist scan data.

## Assets

The main assets are user-provided text, future analysis results, Django configuration, and the integrity of the application’s explanations.

## Trust boundaries

User-entered URLs, email text, and attachment names are untrusted input. They must be escaped when rendered, bounded in size, and treated as data rather than executable content. The application must never turn a submitted URL into a network request.

## Primary threats and controls

| Threat | Phase 1 control |
|---|---|
| Cross-site scripting through pasted content | Django autoescaping and escaped template rendering |
| Cross-site request forgery | Django CSRF middleware and tokens on POST forms |
| Accidental network contact | No network client in the project; URL forms are UI-only |
| Secret leakage | Environment-based secret configuration and ignored `.env` files |
| Misleading results | No fake scores or verdicts; placeholder states are labeled |
| Oversized input | Form field maximum lengths |
| Unsafe attachment handling | Attachment names only; no binary upload, preview, unpacking, or execution |

## Future-phase considerations

When persistence and analysis are introduced, the project should add output encoding tests, input-limit tests, a no-network regression test, safe error handling, database privacy decisions, and a documented rule version on every stored result.
