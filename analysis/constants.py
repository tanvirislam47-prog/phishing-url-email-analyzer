"""Centralized, documented configuration for the Phase 3 URL analyzer."""

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253
MAX_PATH_LENGTH = 2048
MAX_QUERY_LENGTH = 4096
MAX_FRAGMENT_LENGTH = 2048

# These thresholds are deliberately conservative to reduce false positives.
LONG_URL_THRESHOLD = 180
LONG_HOSTNAME_THRESHOLD = 80
LONG_PATH_THRESHOLD = 120
EXCESSIVE_SUBDOMAIN_THRESHOLD = 3
EXCESSIVE_HYPHEN_THRESHOLD = 4
EXCESSIVE_PUNCTUATION_THRESHOLD = 6
EXCESSIVE_REPEATED_SEPARATOR_THRESHOLD = 2
EXCESSIVE_PATH_DEPTH_THRESHOLD = 5
LONG_ENCODED_SEQUENCE_THRESHOLD = 12
REPEATED_ENCODING_THRESHOLD = 2

# The analyzer checks suffixes locally. A suffix is a supporting signal, not a
# verdict about every domain registered under it.
SUSPICIOUS_TLDS = frozenset(
    {
        "cam",
        "click",
        "cf",
        "country",
        "ga",
        "gq",
        "icu",
        "link",
        "ml",
        "rest",
        "tk",
        "top",
        "work",
        "xyz",
    }
)

URL_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "buff.ly",
        "is.gd",
        "lnkd.in",
        "ow.ly",
        "rb.gy",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
        "trib.al",
    }
)

BRAND_LIKE_KEYWORDS = frozenset(
    {
        "amazon",
        "apple",
        "bank",
        "docusign",
        "google",
        "microsoft",
        "netflix",
        "paypal",
    }
)

SUSPICIOUS_KEYWORDS = {
    "login": "authentication",
    "signin": "authentication",
    "sign-in": "authentication",
    "verify": "verification",
    "verification": "verification",
    "account": "account",
    "password": "credential",
    "credential": "credential",
    "secure": "security",
    "security": "security",
    "update": "account",
    "confirm": "verification",
    "banking": "financial",
    "payment": "financial",
    "wallet": "financial",
    "invoice": "financial",
    "reset": "credential",
    "suspended": "account",
    "unlock": "account",
}

COMMON_WEB_PORTS = frozenset({80, 443, 8080, 8443})

# Points are metadata for the future centralized risk engine. Phase 3 returns
# them on indicators but does not aggregate them into a score or verdict.
INDICATOR_POINTS = {
    "URL_MALFORMED": 0,
    "URL_IP_ADDRESS": 18,
    "URL_HTTP": 10,
    "URL_UNKNOWN_SCHEME": 8,
    "URL_LONG": 4,
    "URL_LONG_HOSTNAME": 5,
    "URL_LONG_PATH": 4,
    "URL_EXCESSIVE_SUBDOMAINS": 7,
    "URL_EXCESSIVE_HYPHENS": 4,
    "URL_AT_SYMBOL": 14,
    "URL_SUSPICIOUS_KEYWORD": 5,
    "URL_SUSPICIOUS_TLD": 5,
    "URL_SHORTENER": 6,
    "URL_UNUSUAL_PORT": 6,
    "URL_PERCENT_ENCODING": 4,
    "URL_EXCESSIVE_ENCODING": 8,
    "URL_SUSPICIOUS_CHARACTERS": 4,
    "URL_EXCESSIVE_PATH_DEPTH": 5,
    "URL_PUNYCODE": 7,
    "URL_AUTHENTICATION_SYNTAX": 8,
    "URL_BRAND_LIKE_STRUCTURE": 7,
}
