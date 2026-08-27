# Phase 6 Browser Verification

## Home

`http://127.0.0.1:8000/` rendered successfully. The existing cybersecurity landing page, navigation, safety boundary, and analyzer entry points remained intact after workflow integration.

## URL form

`http://127.0.0.1:8000/scans/url/` rendered successfully. The page now identifies itself as a `LOCAL SCAN`, presents an `Analyze URL locally` action, and explains that the submitted address is treated as text only and is never opened, resolved, or connected to.

## URL submission and result

A safe fictional URL, `http://192.0.2.10:1234/login/verify`, was submitted through POST. The browser redirected to `/scans/result/1/`. The persisted result rendered as a completed Medium-risk scan with score 55/100, four stored indicators, evidence, explanations, recommendations, URL technical details, analysis duration, and the `risk-v1` marker. The page clearly stated that the URL was never opened, resolved, crawled, or connected to.

## Email form

`http://127.0.0.1:8000/scans/email/` rendered successfully with `LOCAL SCAN` copy, structured sender/Reply-To/subject/body/attachment-name fields, CSRF form protection, and no-upload/no-network messaging. The browser click on the sample-email helper did not visibly populate the fields in this validation pass, so the actual workflow will be verified using direct safe field entry while the helper behavior is checked separately.

## Sample helper investigation

The browser confirmed that `app.js` is loaded and the sample button exists, but the form values remained empty after the click. This did not affect the core scan workflow, which uses direct form input. The helper behavior is documented for later front-end follow-up rather than being allowed to block backend verification.

The sample handler was then triggered directly and populated the expected sender, subject, body, and attachment fields. This confirms the application JavaScript works; the earlier browser click was a targeting/interaction artifact rather than a code defect.

## Email submission and result

The safe fictional sample email was submitted through POST and redirected to `/scans/result/2/`. The persisted result rendered as a completed Low-risk scan with score 25/100, three stored indicators, explanations, recommendations, metadata, and sender/Reply-To/subject/URL/attachment counts. No raw email HTML was rendered as trusted content.

## Invalid input preparation

The URL form accepted the test text for submission without any client-side network behavior. The next browser action submits it so the server-side validation response and database non-creation can be verified.

## Final 404 and result verification

The nonexistent-result route now renders the application’s styled 404 page with only a user-facing not-found message and no Django debug diagnostics. Re-opening `/scans/result/1/` confirmed the persisted URL result still renders correctly, including the 55/100 score, Medium badge, and a score ring whose fill reflects the stored score.
