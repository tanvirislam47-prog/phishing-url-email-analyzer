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

# Email analysis is bounded both for privacy and to avoid pathological parsing.
MAX_RAW_EMAIL_LENGTH = 50000
MAX_EMAIL_BODY_LENGTH = 30000
MAX_HEADER_VALUE_LENGTH = 1000
MAX_ATTACHMENT_NAMES_LENGTH = 2000
MAX_EXTRACTED_EMAIL_URLS = 20
MAX_EMAIL_ATTACHMENTS = 30
MAX_EMAIL_INDICATORS = 80
MAX_EVIDENCE_LENGTH = 240

EMAIL_SUBJECT_PATTERNS = {
    "urgent_action": ("urgent action", "action required", "act now", "immediately"),
    "account_suspension": ("account suspended", "account will be suspended", "account locked", "suspend your account"),
    "account_verification": ("verify your account", "account verification", "confirm your account"),
    "password_reset": ("reset your password", "password reset", "change your password"),
    "security_alert": ("security alert", "unusual sign-in", "unusual login", "suspicious activity"),
    "payment_required": ("payment required", "payment failed", "failed payment", "payment declined"),
    "invoice": ("invoice", "billing statement", "amount due"),
    "identity_confirmation": ("confirm your identity", "identity verification", "verify your identity"),
    "unlock_account": ("unlock your account", "unlock account"),
    "prize_reward": ("you won", "claim your prize", "reward waiting", "cash prize"),
}

EMAIL_BODY_PATTERNS = {
    "urgency": ("urgent", "immediately", "within 24 hours", "right away", "act now", "without delay"),
    "threat": ("will be suspended", "will be closed", "legal action", "final warning", "lose access", "failure to comply"),
    "account_suspension": ("account suspended", "account will be suspended", "account will be locked", "account has been disabled", "access will be revoked"),
    "credential_request": ("login credentials", "sign in", "log in", "username and password", "credentials"),
    "password_request": ("password", "passcode", "security answer"),
    "otp_request": ("otp", "one-time password", "verification code", "security code", "one time code", "pin"),
    "identity_verification": ("verify your identity", "confirm your identity", "identity document", "validate your identity"),
    "payment_request": ("make a payment", "payment required", "pay now", "send payment", "payment details"),
    "financial_request": ("bank transfer", "bank account", "card details", "credit card", "wire transfer", "banking details"),
    "crypto_request": ("bitcoin", "cryptocurrency", "crypto wallet", "wallet address"),
    "prize_reward": ("you won", "winner", "claim your prize", "reward", "lottery"),
    "security_impersonation": ("security team", "security department", "fraud department", "account protection"),
    "call_to_action": ("click here", "click the link", "review now", "open the link", "download now", "take action"),
}

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe": "executable",
    ".scr": "screen-saver executable",
    ".bat": "batch script",
    ".cmd": "command script",
    ".com": "DOS executable",
    ".msi": "installer package",
    ".js": "JavaScript file",
    ".jse": "encoded JavaScript file",
    ".vbs": "VBScript file",
    ".vbe": "encoded VBScript file",
    ".ps1": "PowerShell script",
    ".psm1": "PowerShell module",
    ".docm": "macro-enabled Word document",
    ".xlsm": "macro-enabled Excel workbook",
    ".pptm": "macro-enabled PowerPoint presentation",
    ".xlam": "macro-enabled Excel add-in",
    ".zip": "archive",
    ".rar": "archive",
    ".7z": "archive",
    ".iso": "disk image",
}

EMAIL_REQUEST_VERBS = (
    "ask",
    "click",
    "confirm",
    "enter",
    "give",
    "make",
    "open",
    "provide",
    "reply",
    "send",
    "share",
    "submit",
    "tell",
    "type",
    "update",
    "verify",
)

EMAIL_DISPLAY_NAME_KEYWORDS = frozenset(
    {
        "account",
        "amazon",
        "apple",
        "bank",
        "billing",
        "google",
        "microsoft",
        "netflix",
        "paypal",
        "security",
        "support",
    }
)

EMAIL_INDICATOR_POINTS = {
    "EMAIL_SENDER_MISSING": 5,
    "EMAIL_SENDER_MALFORMED": 8,
    "EMAIL_SENDER_DOMAIN_SUSPICIOUS": 6,
    "EMAIL_REPLY_TO_MISMATCH": 8,
    "EMAIL_DISPLAY_NAME_DECEPTION": 8,
    "EMAIL_REPLY_TO_MALFORMED": 5,
    "EMAIL_SUBJECT_PATTERN": 4,
    "EMAIL_MALFORMED_MIME": 2,
    "EMAIL_URGENCY_LANGUAGE": 5,
    "EMAIL_THREAT_LANGUAGE": 8,
    "EMAIL_ACCOUNT_SUSPENSION": 8,
    "EMAIL_CREDENTIAL_REQUEST": 10,
    "EMAIL_PASSWORD_REQUEST": 10,
    "EMAIL_OTP_REQUEST": 10,
    "EMAIL_IDENTITY_VERIFICATION": 7,
    "EMAIL_PAYMENT_REQUEST": 8,
    "EMAIL_FINANCIAL_REQUEST": 10,
    "EMAIL_CRYPTO_REQUEST": 10,
    "EMAIL_PRIZE_REWARD": 7,
    "EMAIL_SECURITY_IMPERSONATION": 5,
    "EMAIL_CALL_TO_ACTION_PRESSURE": 4,
    "EMAIL_CONTAINS_SUSPICIOUS_URL": 10,
    "EMAIL_LINK_TEXT_MISMATCH": 8,
    "EMAIL_RISKY_ATTACHMENT": 10,
    "EMAIL_DOUBLE_EXTENSION": 10,
}

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
