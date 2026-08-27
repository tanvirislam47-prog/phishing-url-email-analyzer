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
