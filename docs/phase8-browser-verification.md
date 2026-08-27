# Phase 8 Browser Verification

## Home and URL form

`http://127.0.0.1:8000/` rendered successfully with local/offline boundary messaging, working primary navigation, and corrected implemented-feature copy. The page no longer claims that results, analysis, or history are future work.

`http://127.0.0.1:8000/scans/url/` rendered the URL analyzer form with a visible local-scan label, bounded URL input, CSRF form support, clear control, and explicit no-DNS/no-HTTP guidance. The refreshed UI used local system font fallbacks rather than external font assets.

## URL validation and inert XSS payload

The browser form accepted the text `javascript:alert(1)` as input but rejected it with the normal scheme/hostname validation message. No scan was created and no script executed; the payload remained visible as text in the form.

## Normal URL workflow

A real safe submission of `https://example.com/account/verify` created persisted scan #3 and redirected to `/scans/result/3/`. The result page rendered the stored Very Low score, indicator evidence, recommendations, technical URL fields, and the explicit no-open/no-resolve/no-connect limitation. The workflow completed without any remote URL request.

## Email form and sample fill

`http://127.0.0.1:8000/scans/email/` rendered only text fields and attachment-name metadata input, with no file upload control. The built-in sample button populated fields locally through ordinary value assignment; it did not perform a network or file operation.

## Suspicious email workflow

A real text-only suspicious email submission created persisted scan #4 and redirected to `/scans/result/4/`. The result displayed the expected critical score, explainable indicators for the sender mismatch, Reply-To, urgency, password request, shortener URL, and macro-enabled attachment name. No file was uploaded or opened, and the nested URL was analyzed locally as text.

## Result refresh and history

Refreshing `/scans/result/4/` reproduced the same persisted critical result without creating another scan. The history page then showed four real persisted records newest-first, including the browser-created Very Low URL and Critical email scans. The page displayed generic metadata and stable result actions without raw email bodies.

## Dashboard and About page

The dashboard refreshed with four genuine persisted scans and accurate server-derived totals, type counts, score statistics, and risk distribution. The About page rendered corrected current-phase copy, the implemented local analysis boundary, and the explicit limitation that authentication and user isolation are not enabled.

## 404 and form recovery

`/scans/result/999999999999/` rendered the branded 404 page with no traceback or database details. Afterward, the email form reopened normally with its text-only controls and local safety guidance.

## Empty-email validation

Submitting the empty email form through the native form path returned the expected non-field validation message, `Enter at least one email field before starting a scan.` The browser remained on the form and no additional scan was created.

## Pagination and dashboard refresh

The browser request `/scans/history/?type=email&status=completed&page=999` safely resolved to page 1 of the two matching persisted email records, preserving the selected filters and returning no error page. A subsequent dashboard refresh remained read-only and continued to show four records with the expected Very Low, Low, Medium, and Critical distribution.

Pagination page-2, last-page, invalid-page, negative-page, and filter-preservation cases are also covered by the automated Phase 8 tests; the browser database was not polluted with artificial pagination fixtures.

## Responsive UI inspection

The rendered dashboard reported no horizontal overflow (`documentWidth` equaled `viewportWidth` at the available browser viewport). The local stylesheet exposed responsive media rules at 950px, 850px, 720px, 540px, and 420px breakpoints. No new client-side content injection was introduced.
