# URL Analysis Rules

## Phase 3 status

Phase 3 implements a deterministic, local-only URL analyzer. It returns technical features and explainable indicators, but it does **not** calculate a final score, risk level, or verdict. The `points` value on each indicator is metadata reserved for the centralized risk engine planned for a later phase.

## Processing pipeline

```text
submitted URL string
        ↓
input limits and control-character checks
        ↓
standard-library URL parsing
        ↓
local feature extraction
        ↓
rule evaluation
        ↓
structured indicators
```

The analyzer does not resolve hostnames, perform DNS lookups, issue HTTP or HTTPS requests, follow redirects, crawl pages, download content, contact external APIs, expand shorteners, or execute any content.

## Input and parsing rules

| Rule or check | Behavior | False-positive / limitation consideration |
|---|---|---|
| Empty input | Returns an unsuccessful result with no indicators. | An empty submission is an input problem, not a phishing signal. |
| Whitespace | Surrounding whitespace is trimmed; whitespace-only input fails. | The original submitted value is retained in the result contract. |
| Maximum URL length | Values above 2,048 characters fail safely before parsing. | The limit protects bounded execution and storage; long URLs below the limit are only a supporting signal. |
| Control characters | ASCII control characters cause a parse failure. | This prevents ambiguous or unsafe display rather than asserting maliciousness. |
| Missing scheme | Values such as `example.com/login` fail as malformed because no scheme is present. | The analyzer does not silently prepend `https://`. |
| Missing host | A scheme without a parseable network location fails. | Non-web schemes with no host are not treated as valid web destinations. |
| Invalid hostname characters | Whitespace and reserved hostname characters cause a malformed result. | This distinguishes malformed input from suspicious but parseable syntax. |
| Invalid port or bracketed IPv6 | Standard-library parsing failures return a controlled error. | No network validation is attempted. |

## Feature extraction

Successful results expose the original URL, normalized URL, scheme, hostname, registrable-looking domain approximation, subdomain string, port, path, query, fragment, lengths, label counts, path depth, query parameter count, IP status, scheme flags, authority flags, encoding flags, punctuation counts, TLD context, shortener status, and keyword matches.

The domain split is intentionally conservative and does not use a public-suffix database. It should not be interpreted as proof of organizational ownership.

## Detection rules

| Code | Detection and threshold | Severity | Points metadata | Explanation and false-positive control |
|---|---|---:|---:|---|
| `URL_IP_ADDRESS` | Hostname parses as IPv4 or IPv6 using the standard library. | HIGH | 18 | A raw IP can make identity harder to associate with an organization. IP-based services are not automatically malicious. |
| `URL_HTTP` | Scheme is exactly `http`. | MEDIUM | 10 | HTTP does not encrypt traffic in transit and can expose requests or credentials. It does not prove phishing. |
| `URL_UNKNOWN_SCHEME` | Scheme is not `http` or `https`, but a host is parseable. | MEDIUM | 8 | An unexpected scheme may not behave like an ordinary web link. It is a review signal, not a verdict. |
| `URL_LONG` | Total URL length exceeds 180 characters. | LOW | 4 | Long links are harder to inspect. The threshold avoids flagging ordinary short and medium URLs. |
| `URL_LONG_HOSTNAME` | Hostname length exceeds 80 characters. | LOW | 5 | Long hostnames can obscure identity cues. Long organizational domains remain possible. |
| `URL_LONG_PATH` | Path length exceeds 120 characters. | LOW | 4 | Long paths can conceal meaningful destination text. This is not proof of harmful content. |
| `URL_EXCESSIVE_SUBDOMAINS` | More than 3 subdomain levels are present. | MEDIUM | 7 | Multiple levels can be legitimate, but can also make the apparent organization difficult to identify. |
| `URL_EXCESSIVE_HYPHENS` | Hostname contains at least 4 hyphens. | LOW | 4 | Constructed or lookalike domains may use many hyphens; ordinary technical domains can also contain them. |
| `URL_AT_SYMBOL` | `@` occurs in the parsed authority/netloc. | HIGH | 14 | Text before `@` can look like a destination while the actual host follows it. `@` in a query is not flagged by this rule. |
| `URL_AUTHENTICATION_SYNTAX` | Parsed username or password exists in the authority. | MEDIUM | 8 | Embedded user information can make the authority confusing. It is unusual for ordinary user-facing links but not automatically malicious. |
| `URL_SUSPICIOUS_KEYWORD` | Centralized sensitive-action terms occur as bounded words in hostname, path, or query. | LOW | 5 each | Terms such as `login`, `verify`, `password`, `payment`, or `unlock` can occur in legitimate workflows. A keyword alone is not proof. |
| `URL_SUSPICIOUS_TLD` | Final hostname label is in the centralized supporting list. | LOW | 5 | The TLD may be associated with higher-risk registrations and should be assessed with other evidence. The entire TLD is not malicious. |
| `URL_SHORTENER` | Hostname matches a configured common shortener domain. | MEDIUM | 6 | Shorteners hide the final destination. The analyzer does not expand or contact the shortener. |
| `URL_UNUSUAL_PORT` | Explicit port is outside 80, 443, 8080, and 8443. | MEDIUM | 6 | A nonstandard port is an anomaly worth reviewing but does not prove phishing. |
| `URL_PERCENT_ENCODING` | One or more valid percent-encoded bytes occur across hostname, path, query, or fragment. | LOW | 4 | Percent encoding is valid URL syntax; it is surfaced because it can reduce readability. |
| `URL_EXCESSIVE_ENCODING` | At least 2 encoded bytes or a run of at least 12 encoded bytes occurs. | MEDIUM | 8 | Repeated or long encoded sequences can obscure a destination. Decoding remains local and bounded; no decoded content is executed. |
| `URL_SUSPICIOUS_CHARACTERS` | Backslashes, at least 2 repeated separators, or at least 6 unusual punctuation characters occur. | MEDIUM | 4 | The rule focuses on unusual combinations rather than flagging every special character. |
| `URL_EXCESSIVE_PATH_DEPTH` | More than 5 non-empty path segments occur. | LOW | 5 | Deep paths are harder to review. Many legitimate applications use nested routes. |
| `URL_PUNYCODE` | Any hostname label begins with `xn--`. | MEDIUM | 7 | Internationalized domain names can support visual impersonation. Punycode alone does not mean phishing. |
| `URL_BRAND_LIKE_STRUCTURE` | A conservative brand-like term appears in hostname/path and is reinforced by at least one subdomain or two hostname hyphens. | MEDIUM | 7 | This is not a brand database and does not claim domain ownership. Familiar words can occur legitimately. |

## Centralized configuration

Thresholds and lists live in `analysis/constants.py`. The current limits include a 2,048-character URL maximum, 180-character long-URL threshold, 80-character long-hostname threshold, 120-character long-path threshold, more than 3 subdomains, at least 4 hostname hyphens, more than 5 path segments, and the bounded encoding thresholds described above.

The keyword, suspicious-TLD, shortener, common-port, and brand-like lists are centralized so that future rule updates do not require searching through the analyzer implementation. A future risk engine should use the points metadata with deduplication and category controls rather than simply summing every matching keyword.

## Result contract

A successful analysis returns `success`, `original_url`, `normalized_url`, `features`, `indicators`, and `analysis_metadata`. Each indicator contains `code`, `category`, `title`, `severity`, `points`, `evidence`, `explanation`, `recommendation`, and `sort_order`.

A malformed submission returns `success: false`, a bounded error message, no features, and an empty indicator list. Neither successful nor failed Phase 3 results contain a final score, risk level, or verdict.


# Email Analysis Rules

## Phase 4 status

Phase 4 implements a deterministic, offline email analyzer. It returns parsed email features, bounded indicators, extracted URL analyses, and text-only attachment metadata. It does **not** calculate a final score, risk level, or verdict.

## Email processing pipeline

```text
raw email or structured fields
        ↓
bounded input checks
        ↓
Python standard-library email parser
        ↓
header, body, and MIME extraction
        ↓
social-engineering rule evaluation
        ↓
HTTP(S) URL extraction
        ↓
Phase 3 URL analyzer reuse
        ↓
structured email indicators
```

HTML MIME parts are parsed as inert text. Script and style contents are ignored for visible-text extraction. No email content is rendered as trusted HTML, no URL is opened, and no attachment payload is accessed.

## Header and sender rules

| Code | Detection | Severity | Points metadata | False-positive consideration |
|---|---|---:|---:|---|
| `EMAIL_SENDER_MISSING` | From header is absent or empty. | MEDIUM | 5 | Some system-generated messages have unusual headers; absence is a review signal, not proof of phishing. |
| `EMAIL_SENDER_MALFORMED` | From value does not contain a conventional address. | MEDIUM | 8 | Address parsing is intentionally conservative and does not validate domain ownership. |
| `EMAIL_SENDER_DOMAIN_SUSPICIOUS` | Sender domain is a raw IP, contains an `xn--` label, or ends in a configured high-scrutiny TLD. | MEDIUM | 6 | No reputation lookup is performed, and the domain is never declared malicious. |
| `EMAIL_REPLY_TO_MALFORMED` | Reply-To is present but not a conventional address. | MEDIUM | 5 | Some automated mail has nonstandard reply behavior; verify before replying. |
| `EMAIL_REPLY_TO_MISMATCH` | Valid From and Reply-To addresses differ by address or domain. | MEDIUM | 8 | Delegated support systems can legitimately use different reply addresses. |
| `EMAIL_DISPLAY_NAME_DECEPTION` | Familiar organization-like term appears in display name but not in the sender domain. | MEDIUM | 8 | Display names are easy to customize; the rule does not identify the real sender or brand ownership. |

## Subject rules

| Code | Detection | Severity | Points metadata | False-positive consideration |
|---|---|---:|---:|---|
| `EMAIL_SUBJECT_PATTERN` | Centralized phrase families match urgency, suspension, verification, password reset, security alert, payment, invoice, identity, unlock, or reward language. | LOW or MEDIUM | 4 | These phrases also appear in legitimate notifications, so subject language is only contextual evidence. |

Subject matching is case-insensitive, bounded, and phrase-based. The analyzer records an excerpt of the matched context rather than retaining unlimited raw content.

## Body social-engineering rules

| Code | Pattern family | Severity | Points metadata | False-positive consideration |
|---|---|---:|---:|---|
| `EMAIL_URGENCY_LANGUAGE` | Urgent, immediate, deadline, or act-now language. | MEDIUM | 5 | Genuine incident notifications can be urgent; urgency alone is not a verdict. |
| `EMAIL_THREAT_LANGUAGE` | Suspension, closure, legal action, final-warning, or loss-of-access pressure. | HIGH | 8 | Organizations sometimes communicate real consequences; verify independently. |
| `EMAIL_ACCOUNT_SUSPENSION` | Account suspended, locked, disabled, or access-revoked phrases. | HIGH | 8 | Account services may send legitimate notices, so the request context matters. |
| `EMAIL_CREDENTIAL_REQUEST` | Requests for credentials, sign-in, login, or username/password information. | HIGH | 10 | The analyzer does not determine whether the sender is authorized. Do not provide secrets through email. |
| `EMAIL_PASSWORD_REQUEST` | Password, passcode, or security-answer language combined with request context. | HIGH | 10 | Password-management workflows can use these terms; verify through a trusted application. |
| `EMAIL_OTP_REQUEST` | OTP, PIN, one-time password, verification-code, or security-code language combined with request context. | HIGH | 10 | Automated security messages can mention codes without requesting them. |
| `EMAIL_IDENTITY_VERIFICATION` | Identity document or identity-confirmation language. | MEDIUM | 7 | Legitimate compliance workflows exist; use the organization’s known process. |
| `EMAIL_PAYMENT_REQUEST` | Payment, pay-now, or payment-details language combined with request context. | MEDIUM | 8 | Invoices and billing notices can be legitimate; confirm independently. |
| `EMAIL_FINANCIAL_REQUEST` | Bank, card, transfer, wire, or banking-detail language combined with request context. | HIGH | 10 | The rule does not assess transaction legitimacy. Never rely on an email alone for payment changes. |
| `EMAIL_CRYPTO_REQUEST` | Cryptocurrency or wallet-address language combined with request context. | HIGH | 10 | Legitimate crypto communications exist; the message should still be verified independently. |
| `EMAIL_PRIZE_REWARD` | Winner, lottery, prize, or reward language. | MEDIUM | 7 | Promotional messages can use rewards; a request for payment or secrets increases concern. |
| `EMAIL_SECURITY_IMPERSONATION` | Security, fraud, account-protection, or security-team language. | LOW | 5 | Many legitimate security notifications use the same vocabulary. |
| `EMAIL_CALL_TO_ACTION_PRESSURE` | Click, open, download, review-now, or take-action language. | LOW | 4 | Normal newsletters and workflow emails also contain calls to action. |

Sensitive request families require a request-context verb where practical. This reduces false positives from messages that merely mention a password, bank, or OTP without asking the recipient to provide or use it.

## URL extraction and reuse

The analyzer extracts at most 20 unique HTTP(S) URL strings from plain-text body content and HTML href attributes. Trailing sentence punctuation is trimmed, malformed candidates are ignored, and no candidate is opened or expanded.

| Code | Detection | Severity | Points metadata | False-positive consideration |
|---|---|---:|---:|---|
| `EMAIL_CONTAINS_SUSPICIOUS_URL` | At least one extracted URL receives one or more Phase 3 URL indicators. | HIGH | 10 | A nested URL indicator is heuristic evidence; it does not prove that the email or destination is malicious. |
| `EMAIL_LINK_TEXT_MISMATCH` | In HTML, visible URL-like text differs from the HTTP(S) href destination. | HIGH | 8 | HTML formatting can be complex; the rule is applied only to clear URL-like text and href differences. |

The email analyzer imports and calls the existing Phase 3 `analyze_url` function. It does not duplicate URL rules, shortener lists, parsing logic, or scoring behavior. Nested features and indicators remain available under each extracted URL result.

## Attachment-name rules

Only attachment filenames and declared content types are inspected. The implementation accepts no binary upload and never opens, previews, unpacks, executes, downloads, or scans attachment contents.

| Code | Detection | Severity | Points metadata | False-positive consideration |
|---|---|---:|---:|---|
| `EMAIL_RISKY_ATTACHMENT` | Filename ends in a configured executable, script, macro-enabled Office, archive, or disk-image extension. | HIGH | 10 | The filename alone does not establish that the file is malicious. |
| `EMAIL_DOUBLE_EXTENSION` | Filename has multiple extensions and the final extension is in the risky-extension list. | HIGH | 10 | Some legitimate naming conventions use multiple extensions; treat as a caution signal. |

The centralized list includes `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.msi`, JavaScript and VBScript extensions, PowerShell extensions, macro-enabled Office formats, common archives, and disk images.

## MIME, malformed input, and privacy limits

The analyzer supports plain text, multipart messages, HTML messages, and attachment metadata. Missing headers are allowed. Encoded headers are decoded through the Python standard-library parser. Parser defects are returned as bounded low-severity indicators rather than causing a crash.

Raw email input is limited to 50,000 characters, structured bodies to 30,000 characters, header values to 1,000 characters, attachment-name input to 2,000 characters, extracted URLs to 20 items, attachments to 30 items, indicators to 80 items, and evidence excerpts to 240 characters. The public email feature contract intentionally contains body length and flags rather than unlimited raw-body retention.

## No final scoring

Email indicators include points metadata so a later centralized risk engine can combine them with URL indicators. Phase 4 does not aggregate points, calculate a final score, assign a risk level, or produce a verdict.
