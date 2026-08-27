"""Deterministic, offline email analysis.

Email content is untrusted text. This module parses headers and MIME parts
locally, extracts bounded text metadata, reuses the Phase 3 URL analyzer for
HTTP(S) strings, and never sends mail, opens links, accesses attachments, or
contacts external services.
"""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from typing import Any

from .constants import (
    EMAIL_BODY_PATTERNS,
    EMAIL_DISPLAY_NAME_KEYWORDS,
    EMAIL_INDICATOR_POINTS,
    EMAIL_REQUEST_VERBS,
    EMAIL_SUBJECT_PATTERNS,
    MAX_ATTACHMENT_NAMES_LENGTH,
    MAX_EMAIL_ATTACHMENTS,
    MAX_EMAIL_BODY_LENGTH,
    MAX_EMAIL_INDICATORS,
    MAX_EXTRACTED_EMAIL_URLS,
    MAX_HEADER_VALUE_LENGTH,
    MAX_RAW_EMAIL_LENGTH,
    RISKY_ATTACHMENT_EXTENSIONS,
    SUSPICIOUS_TLDS,
)
from .text_features import (
    contains_phrase,
    extract_html_links,
    extract_html_text,
    extract_http_urls,
    find_phrase,
    normalize_text,
    safe_excerpt,
)
from .types import AttachmentInfo, EmailAnalysisResult, EmailFeatures, IndicatorResult
from .url_analyzer import analyze_url

_EMAIL_ADDRESS_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")
_SAFE_ATTACHMENT_RE = re.compile(r"[^\x00-\x1f\x7f]+")


class EmailAnalyzer:
    """Analyze raw or structured email text without network or file access."""

    rule_version = "email-v1"

    def analyze(
        self,
        raw_email: str | None = None,
        *,
        sender: str = "",
        recipient: str = "",
        reply_to: str = "",
        subject: str = "",
        body: str = "",
        attachment_names: str = "",
    ) -> EmailAnalysisResult:
        if raw_email is not None:
            if not isinstance(raw_email, str):
                return self._failure("The raw email must be text.")
            if len(raw_email) > MAX_RAW_EMAIL_LENGTH:
                return self._failure(
                    f"The raw email exceeds the maximum supported length of {MAX_RAW_EMAIL_LENGTH} characters."
                )
            if not raw_email.strip():
                return self._failure("The email is empty.")
            parsed = self._parse_raw_email(raw_email)
            if parsed is None:
                return self._failure("The email could not be parsed as text.")
            extracted = self._extract_message_data(parsed)
            sender = extracted["sender"]
            recipient = extracted["recipient"]
            reply_to = extracted["reply_to"]
            subject = extracted["subject"]
            body = extracted["body"]
            attachment_records = extracted["attachments"]
            html_parts = extracted["html_parts"]
            defects = extracted["defects"]
            has_plain_text = extracted["has_plain_text"]
            has_html = extracted["has_html"]
            is_multipart = extracted["is_multipart"]
            date = extracted["date"]
            raw_mode = True
        else:
            values = (sender, recipient, reply_to, subject, body, attachment_names)
            if not all(isinstance(value, str) for value in values):
                return self._failure("Email fields must be text.")
            if not any(value.strip() for value in values):
                return self._failure("The email is empty.")
            if len(body) > MAX_EMAIL_BODY_LENGTH:
                return self._failure(
                    f"The email body exceeds the maximum supported length of {MAX_EMAIL_BODY_LENGTH} characters."
                )
            if len(attachment_names) > MAX_ATTACHMENT_NAMES_LENGTH:
                return self._failure(
                    f"Attachment names exceed the maximum supported length of {MAX_ATTACHMENT_NAMES_LENGTH} characters."
                )
            body = normalize_text(body)[:MAX_EMAIL_BODY_LENGTH]
            attachment_records = self._attachment_records_from_names(attachment_names)
            html_parts = []
            defects = []
            has_plain_text = bool(body)
            has_html = False
            is_multipart = False
            date = ""
            raw_mode = False

        sender = self._bounded_header(sender)
        recipient = self._bounded_header(recipient)
        reply_to = self._bounded_header(reply_to)
        subject = self._bounded_header(subject)
        date = self._bounded_header(date)
        body = body[:MAX_EMAIL_BODY_LENGTH]

        urls = self._analyze_extracted_urls(body, html_parts)
        indicators = self._evaluate_indicators(
            sender=sender,
            reply_to=reply_to,
            subject=subject,
            body=body,
            attachments=attachment_records,
            defects=defects,
            nested_urls=urls,
            html_parts=html_parts,
        )

        sender_info = self._parse_address_value(sender)
        sender_domain = sender_info["domain"]
        features = EmailFeatures(
            sender=sender_info["address"] or sender,
            sender_domain=sender_domain,
            sender_display_name=sender_info["display_name"],
            recipient=recipient,
            reply_to=self._parse_address_value(reply_to)["address"] or reply_to,
            subject=subject,
            date=date,
            body_length=len(body),
            has_plain_text=has_plain_text,
            has_html=has_html,
            is_multipart=is_multipart,
            attachment_count=len(attachment_records),
            extracted_url_count=len(urls),
            header_count=0 if not raw_mode else extracted["header_count"],
            malformed_parts=tuple(defects),
        )
        return EmailAnalysisResult(
            success=True,
            features=features,
            indicators=tuple(indicators[:MAX_EMAIL_INDICATORS]),
            extracted_urls=tuple(urls),
            attachments=tuple(attachment_records),
            metadata={
                "analyzer": "email",
                "rule_version": self.rule_version,
                "network_access": False,
                "raw_email_parsed": raw_mode,
                "max_raw_email_length": MAX_RAW_EMAIL_LENGTH,
                "max_body_length": MAX_EMAIL_BODY_LENGTH,
                "max_extracted_urls": MAX_EXTRACTED_EMAIL_URLS,
                "max_attachments": MAX_EMAIL_ATTACHMENTS,
            },
        )

    @staticmethod
    def _parse_raw_email(raw_email: str):
        try:
            return Parser(policy=policy.default).parsestr(raw_email, headersonly=False)
        except (TypeError, ValueError, IndexError):
            return None

    def _extract_message_data(self, message) -> dict[str, Any]:
        html_parts: list[str] = []
        plain_parts: list[str] = []
        has_plain_text = False
        attachment_records: list[AttachmentInfo] = []
        parts = list(message.walk()) if message.is_multipart() else [message]
        for part in parts[: MAX_EMAIL_ATTACHMENTS + 30]:
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            if filename or disposition == "attachment":
                if filename:
                    attachment_records.append(
                        self._attachment_info(filename, part.get_content_type())
                    )
                if len(attachment_records) >= MAX_EMAIL_ATTACHMENTS:
                    break
                continue
            content_type = part.get_content_type().casefold()
            payload = self._safe_part_text(part)
            if content_type == "text/html":
                html_parts.append(payload[:MAX_EMAIL_BODY_LENGTH])
                plain_parts.append(extract_html_text(payload))
            elif content_type == "text/plain" or not message.is_multipart():
                plain_parts.append(payload[:MAX_EMAIL_BODY_LENGTH])
                has_plain_text = True

        body = normalize_text("\n".join(plain_parts))[:MAX_EMAIL_BODY_LENGTH]
        defects = [type(defect).__name__ for defect in message.defects]
        return {
            "sender": self._header_value(message, "From"),
            "recipient": self._header_value(message, "To"),
            "reply_to": self._header_value(message, "Reply-To"),
            "subject": self._header_value(message, "Subject"),
            "date": self._header_value(message, "Date"),
            "body": body,
            "html_parts": html_parts,
            "attachments": attachment_records,
            "defects": defects,
            "has_plain_text": has_plain_text,
            "has_html": bool(html_parts),
            "is_multipart": message.is_multipart(),
            "header_count": len(message.items()),
        }

    @staticmethod
    def _safe_part_text(part) -> str:
        try:
            content = part.get_content()
            return content if isinstance(content, str) else str(content)
        except (AttributeError, LookupError, TypeError, UnicodeError):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            return payload if isinstance(payload, str) else ""

    @staticmethod
    def _header_value(message, name: str) -> str:
        value = message.get(name, "")
        return safe_excerpt(str(value), MAX_HEADER_VALUE_LENGTH)

    @staticmethod
    def _bounded_header(value: str) -> str:
        return safe_excerpt(value, MAX_HEADER_VALUE_LENGTH)

    @staticmethod
    def _parse_address_value(value: str) -> dict[str, str | bool]:
        display_name, address = parseaddr(value or "")
        display_name = normalize_text(display_name)
        address = address.strip().casefold()
        valid = bool(_EMAIL_ADDRESS_RE.fullmatch(address))
        domain = address.rsplit("@", 1)[1] if valid else ""
        return {
            "display_name": display_name,
            "address": address if valid else "",
            "domain": domain,
            "valid": valid,
            "provided": bool((value or "").strip()),
        }

    @staticmethod
    def _attachment_info(filename: str, content_type: str = "") -> AttachmentInfo:
        safe_name = _SAFE_ATTACHMENT_RE.match(str(filename).strip())
        bounded_name = safe_excerpt(safe_name.group(0) if safe_name else "", 255)
        lowered = bounded_name.casefold()
        extension = ""
        if "." in lowered:
            extension = "." + lowered.rsplit(".", 1)[1]
        return AttachmentInfo(
            filename=bounded_name,
            extension=extension,
            content_type=safe_excerpt(content_type, 120),
        )

    def _attachment_records_from_names(self, attachment_names: str) -> list[AttachmentInfo]:
        values = [item.strip() for item in attachment_names.split(",") if item.strip()]
        return [self._attachment_info(value) for value in values[:MAX_EMAIL_ATTACHMENTS]]

    def _analyze_extracted_urls(
        self, body: str, html_parts: list[str]
    ) -> list[dict[str, Any]]:
        candidates: list[tuple[str, str]] = [(url, "body") for url in extract_http_urls(body, limit=MAX_EXTRACTED_EMAIL_URLS)]
        for html in html_parts:
            for link in extract_html_links(html, limit=MAX_EXTRACTED_EMAIL_URLS):
                href = link.get("href", "")
                if self._is_http_url(href):
                    candidates.append((href, "html_href"))
        deduplicated: list[dict[str, Any]] = []
        seen: set[str] = set()
        for url, source in candidates:
            if url in seen or len(deduplicated) >= MAX_EXTRACTED_EMAIL_URLS:
                continue
            seen.add(url)
            url_result = analyze_url(url)
            deduplicated.append(
                {
                    "url": url,
                    "source": source,
                    "success": url_result.success,
                    "features": url_result.features.to_dict() if url_result.features else {},
                    "indicators": [item.to_dict() for item in url_result.indicators],
                    "error": url_result.error,
                }
            )
        return deduplicated

    @staticmethod
    def _is_http_url(value: str) -> bool:
        if not isinstance(value, str) or len(value) > 2048:
            return False
        try:
            parsed = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(value)
            return parsed.scheme.casefold() in {"http", "https"} and bool(parsed.netloc)
        except (TypeError, ValueError):
            return False

    def _evaluate_indicators(
        self,
        *,
        sender: str,
        reply_to: str,
        subject: str,
        body: str,
        attachments: list[AttachmentInfo],
        defects: list[str],
        nested_urls: list[dict[str, Any]],
        html_parts: list[str],
    ) -> list[IndicatorResult]:
        indicators: list[IndicatorResult] = []
        order = 1

        def add(
            code: str,
            category: str,
            title: str,
            severity: str,
            evidence: str,
            explanation: str,
            recommendation: str,
        ) -> None:
            nonlocal order
            indicators.append(
                IndicatorResult(
                    code=code,
                    category=category,
                    title=title,
                    severity=severity,
                    points=EMAIL_INDICATOR_POINTS[code],
                    evidence=safe_excerpt(evidence, 240),
                    explanation=explanation,
                    recommendation=recommendation,
                    sort_order=order,
                )
            )
            order += 1

        sender_info = self._parse_address_value(sender)
        reply_info = self._parse_address_value(reply_to)
        if not sender_info["provided"]:
            add(
                "EMAIL_SENDER_MISSING",
                "sender",
                "Sender address is missing",
                "MEDIUM",
                "From header is absent.",
                "The message does not provide a usable sender address for identity review.",
                "Do not trust the visible message context; verify the source through a known channel.",
            )
        elif not sender_info["valid"]:
            add(
                "EMAIL_SENDER_MALFORMED",
                "sender",
                "Sender address is malformed",
                "MEDIUM",
                f"Sender: {sender}",
                "The From value does not contain a conventional email address. This may warrant additional verification, but it does not prove maliciousness.",
                "Treat the message cautiously and verify the sender independently.",
            )
        else:
            domain = str(sender_info["domain"])
            if self._suspicious_domain(domain):
                add(
                    "EMAIL_SENDER_DOMAIN_SUSPICIOUS",
                    "sender",
                    "Sender domain deserves additional scrutiny",
                    "MEDIUM",
                    f"Sender domain: {domain}",
                    "The sender domain has a local structural characteristic such as an IP address, punycode label, or configured high-scrutiny suffix. No reputation lookup was performed.",
                    "Do not infer legitimacy from the display name; verify the domain through an independently known address.",
                )
            display_name = str(sender_info["display_name"])
            if self._display_name_deception(display_name, domain):
                add(
                    "EMAIL_DISPLAY_NAME_DECEPTION",
                    "sender",
                    "Display name and address may not align",
                    "MEDIUM",
                    f"Display name: {display_name}; domain: {domain}",
                    "The display name contains a familiar organization-like term that is not reflected in the sender domain. Display names are easy to alter and should not be treated as identity proof.",
                    "Inspect the actual address and confirm the sender through a trusted channel.",
                )
        if reply_info["provided"] and not reply_info["valid"]:
            add(
                "EMAIL_REPLY_TO_MALFORMED",
                "reply_to",
                "Reply-To address is malformed",
                "MEDIUM",
                f"Reply-To: {reply_to}",
                "The Reply-To value does not contain a conventional email address and may not be suitable for safe reply handling.",
                "Do not reply until the intended recipient is verified independently.",
            )
        if sender_info["valid"] and reply_info["valid"]:
            sender_address = str(sender_info["address"])
            reply_address = str(reply_info["address"])
            if sender_address != reply_address or sender_info["domain"] != reply_info["domain"]:
                add(
                    "EMAIL_REPLY_TO_MISMATCH",
                    "reply_to",
                    "Reply-To differs from sender",
                    "MEDIUM",
                    f"From: {sender_address}; Reply-To: {reply_address}",
                    "Replies may be redirected to a different address or domain. Such mismatches can be legitimate, but they deserve verification when a message requests action.",
                    "Do not reply using the message until the intended recipient is confirmed through an independent channel.",
                )

        for category, phrase_set in EMAIL_SUBJECT_PATTERNS.items():
            match = find_phrase(subject, phrase_set)
            if match:
                severity = "MEDIUM" if category in {"account_suspension", "payment_required", "security_alert"} else "LOW"
                add(
                    "EMAIL_SUBJECT_PATTERN",
                    "subject",
                    "Sensitive-action phrase in subject",
                    severity,
                    f"Matched '{match}' in subject.",
                    "The subject uses language associated with urgency, account access, security, payment, identity, or rewards. These phrases can occur in legitimate mail and require context.",
                    "Pause before acting and verify the request through a trusted channel.",
                )

        for category, phrase_set in EMAIL_BODY_PATTERNS.items():
            match = find_phrase(body, phrase_set)
            if not match:
                continue
            request_context = contains_phrase(body, EMAIL_REQUEST_VERBS)
            if category in {"credential_request", "password_request", "otp_request", "payment_request", "financial_request", "crypto_request"} and not request_context:
                continue
            code, severity = {
                "urgency": ("EMAIL_URGENCY_LANGUAGE", "MEDIUM"),
                "threat": ("EMAIL_THREAT_LANGUAGE", "HIGH"),
                "account_suspension": ("EMAIL_ACCOUNT_SUSPENSION", "HIGH"),
                "credential_request": ("EMAIL_CREDENTIAL_REQUEST", "HIGH"),
                "password_request": ("EMAIL_PASSWORD_REQUEST", "HIGH"),
                "otp_request": ("EMAIL_OTP_REQUEST", "HIGH"),
                "identity_verification": ("EMAIL_IDENTITY_VERIFICATION", "MEDIUM"),
                "payment_request": ("EMAIL_PAYMENT_REQUEST", "MEDIUM"),
                "financial_request": ("EMAIL_FINANCIAL_REQUEST", "HIGH"),
                "crypto_request": ("EMAIL_CRYPTO_REQUEST", "HIGH"),
                "prize_reward": ("EMAIL_PRIZE_REWARD", "MEDIUM"),
                "security_impersonation": ("EMAIL_SECURITY_IMPERSONATION", "LOW"),
                "call_to_action": ("EMAIL_CALL_TO_ACTION_PRESSURE", "LOW"),
            }[category]
            add(
                code,
                "body",
                f"{category.replace('_', ' ').title()} signal",
                severity,
                f"Matched '{match}' in the message body.",
                "The message contains a social-engineering pattern that can be used to pressure recipients. The pattern is a review signal, not proof that the message is malicious.",
                "Do not provide secrets, payment information, or access through the message; verify the request independently.",
            )

        suspicious_nested = [
            item for item in nested_urls if item.get("success") and item.get("indicators")
        ]
        if suspicious_nested:
            urls = ", ".join(str(item["url"]) for item in suspicious_nested[:2])
            add(
                "EMAIL_CONTAINS_SUSPICIOUS_URL",
                "link",
                "Email contains a URL with suspicious characteristics",
                "HIGH",
                f"Nested URL: {urls}",
                "At least one extracted URL triggered a Phase 3 local URL indicator. The URL was analyzed as text only and was not opened or requested.",
                "Do not click the link; navigate through a trusted bookmark or independently known address instead.",
            )
        for html in html_parts:
            for link in extract_html_links(html, limit=MAX_EXTRACTED_EMAIL_URLS):
                visible = safe_excerpt(link.get("visible_text", ""), 180)
                href = link.get("href", "")
                if self._is_http_url(visible) and self._is_http_url(href) and visible.rstrip("/") != href.rstrip("/"):
                    add(
                        "EMAIL_LINK_TEXT_MISMATCH",
                        "link",
                        "Visible link text differs from destination",
                        "HIGH",
                        f"Visible: {visible}; destination: {safe_excerpt(href, 180)}",
                        "The visible URL-like text does not match the HTTP(S) destination in the HTML href. This can make a link appear safer than its actual target.",
                        "Do not click the link; verify the destination using a trusted source.",
                    )
                    break

        for defect in defects[:3]:
            add(
                "EMAIL_MALFORMED_MIME",
                "format",
                "Malformed MIME structure detected",
                "LOW",
                f"Parser defect: {defect}",
                "The standard-library email parser reported an unusual or incomplete MIME structure. This affects parsing confidence but does not establish maliciousness.",
                "Review the message using a trusted mail client and avoid opening links or attachments until verified.",
            )
        for attachment in attachments:
            if attachment.extension in RISKY_ATTACHMENT_EXTENSIONS:
                attachment_kind = RISKY_ATTACHMENT_EXTENSIONS[attachment.extension]
                add(
                    "EMAIL_RISKY_ATTACHMENT",
                    "attachment",
                    "Potentially risky attachment type",
                    "HIGH",
                    f"Attachment: {attachment.filename}",
                    f"The filename ends in a {attachment_kind} extension. This attachment type can be abused to deliver malicious content; the file itself was not opened or scanned.",
                    "Do not open or execute the attachment. Confirm the sender and obtain the file through a trusted process.",
                )
                if self._has_double_extension(attachment.filename):
                    add(
                        "EMAIL_DOUBLE_EXTENSION",
                        "attachment",
                        "Double-extension attachment filename",
                        "HIGH",
                        f"Attachment: {attachment.filename}",
                        "Multiple extensions can make a risky final extension less visible in a filename. The filename alone does not prove that the file is malicious.",
                        "Do not open the attachment; verify it through a trusted channel before handling it.",
                    )
        return indicators[:MAX_EMAIL_INDICATORS]

    @staticmethod
    def _suspicious_domain(domain: str) -> bool:
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            pass
        labels = domain.casefold().split(".")
        return any(label.startswith("xn--") for label in labels) or bool(labels and labels[-1] in SUSPICIOUS_TLDS)

    @staticmethod
    def _display_name_deception(display_name: str, domain: str) -> bool:
        lowered_display = display_name.casefold()
        lowered_domain = domain.casefold()
        return bool(lowered_display) and any(
            keyword in lowered_display and keyword not in lowered_domain
            for keyword in EMAIL_DISPLAY_NAME_KEYWORDS
        )

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        parts = filename.casefold().split(".")
        return len(parts) >= 3 and f".{parts[-1]}" in RISKY_ATTACHMENT_EXTENSIONS

    def _failure(self, error: str) -> EmailAnalysisResult:
        return EmailAnalysisResult(
            success=False,
            features=None,
            indicators=tuple(),
            extracted_urls=tuple(),
            attachments=tuple(),
            error=error,
            metadata={
                "analyzer": "email",
                "rule_version": self.rule_version,
                "network_access": False,
            },
        )


def analyze_email(
    raw_email: str | None = None,
    **fields: str,
) -> EmailAnalysisResult:
    """Convenience function for future scan workflows and direct callers."""

    return EmailAnalyzer().analyze(raw_email, **fields)
