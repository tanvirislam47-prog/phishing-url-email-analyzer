# Phase 7 Browser Verification

## Dashboard

`http://127.0.0.1:8000/dashboard/` rendered a database-backed dashboard from the two persisted local scans: total 2, URL 1, email 1, completed 2, failed 0, average score 40, highest 55, lowest 25, one Low result, one Medium result, and two recent activity rows. Metric cards, type breakdown, risk distribution, recent activity, filtered-history links, and the all-database privacy notice were visible.

## History

`http://127.0.0.1:8000/scans/history/` rendered the two persisted scans newest first. The page showed type, subject/hostname, risk, score, verdict, timestamp, duration, completed status, View result actions, search, type/risk/status filters, reset control, and the all-database limitation. No full email body was exposed.

## URL filter

The history filter form submitted as a GET request at `/scans/history/?q=&type=url&risk=&status=`. The page showed only the persisted URL scan and retained the filter state. No new scan was created.

## Email filter

`/scans/history/?type=email` showed only the persisted email scan and kept the Email selector active. The filter remained a read-only GET operation.

## Risk filter

`/scans/history/?risk=medium` showed only the Medium-risk URL scan and kept the Medium selector active. The filter remained a read-only GET operation.

## Final dashboard and history verification

Refreshing the dashboard confirmed it remains read-only and consistent. The active navigation state correctly highlighted "Dashboard" and "History" when visiting those routes. All filters and search inputs were verified as GET-only operations that do not trigger analysis. The responsive layout was checked at desktop size and remains usable without horizontal overflow on the primary dashboard panels.

## Post-correction metric-link verification

After the dashboard metric correction, the refreshed dashboard displayed separate Safe / low, High risk, and Critical risk cards. The Safe / low card correctly routes to the general history view because its count combines Very Low and Low records; High risk and Critical risk route to their exact risk filters. The history page still showed the two real persisted records newest-first, with stable `View result` links and generic completed-state presentation.

## Status filter and result route

`/scans/history/?status=failed` returned zero records because the local database contains no failed scan, preserved the Failed selector, and displayed the safe empty state without an internal error. Returning to the unfiltered history and selecting the newest `View result` action opened `/scans/result/2/`; the persisted email result rendered its stored score, evidence, recommendations, and limitation notice. The result page was reached without re-running analysis.
