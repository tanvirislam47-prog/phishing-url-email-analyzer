# Testing

## Current Phase 1 checks

Phase 1 focuses on foundation verification: Django system checks, template rendering, route resolution, static-file references, form rendering, CSRF tokens, and honest empty or planned states.

## Planned future tests

Later analysis phases should add unit tests for URL feature extraction, email language and header checks, nested URL extraction, attachment-extension checks, risk thresholds, duplicate suppression, and score bounds.

## Security regression tests

The project should retain tests confirming that user-provided content is escaped, POST requests require CSRF protection, input sizes are bounded, no submitted URL is contacted, no binary attachment is executed, and errors do not expose tracebacks in production mode.

## Manual acceptance path

1. Open Home.
2. Follow every navigation link.
3. Submit the URL form and verify that no scan result or record is fabricated.
4. Submit the email form and verify the same behavior.
5. Use the sample email control and clear the form.
6. Open the result, history, dashboard, and About pages.
7. Confirm static CSS and JavaScript assets load.
8. Check the primary layouts at desktop and narrow viewport sizes.
