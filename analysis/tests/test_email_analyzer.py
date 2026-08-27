import socket
import unittest
import urllib.request
from unittest.mock import patch

from analysis.email_analyzer import EmailAnalyzer, analyze_email
from analysis.url_analyzer import analyze_url


class EmailAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = EmailAnalyzer()

    @staticmethod
    def codes(result):
        return [indicator.code for indicator in result.indicators]

    @staticmethod
    def raw(headers: str, body: str = "") -> str:
        return f"{headers}\n\n{body}"

    def test_normal_email(self):
        result = self.analyzer.analyze(
            self.raw(
                "From: alerts@example.com\nTo: user@example.com\nSubject: Monthly update\nDate: Thu, 27 Aug 2026 12:00:00 +0000",
                "Your monthly report is available.",
            )
        )
        self.assertTrue(result.success)
        self.assertEqual(result.features.sender_domain, "example.com")
        self.assertEqual(result.features.recipient, "user@example.com")
        self.assertEqual(result.features.subject, "Monthly update")
        self.assertTrue(result.features.has_plain_text)
        self.assertFalse(result.features.has_html)
        self.assertEqual(result.extracted_urls, ())
        self.assertEqual(result.attachments, ())

    def test_structured_fields_are_supported(self):
        result = analyze_email(
            sender="sender@example.com",
            recipient="user@example.com",
            reply_to="sender@example.com",
            subject="Hello",
            body="A plain message.",
            attachment_names="readme.txt",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.features.sender_domain, "example.com")
        self.assertEqual(result.attachments[0].filename, "readme.txt")

    def test_phishing_style_urgency(self):
        result = self.analyzer.analyze(
            self.raw("From: notice@example.com\nSubject: Action required", "Act now and review this message immediately.")
        )
        self.assertIn("EMAIL_SUBJECT_PATTERN", self.codes(result))
        self.assertIn("EMAIL_URGENCY_LANGUAGE", self.codes(result))

    def test_account_suspension_language(self):
        result = self.analyzer.analyze(
            self.raw("From: account@example.com\nSubject: Account alert", "Your account will be suspended if you do not act now.")
        )
        self.assertIn("EMAIL_ACCOUNT_SUSPENSION", self.codes(result))
        self.assertIn("EMAIL_THREAT_LANGUAGE", self.codes(result))

    def test_credential_request(self):
        result = self.analyzer.analyze(
            self.raw("From: support@example.com", "Please send your login credentials to our support team.")
        )
        self.assertIn("EMAIL_CREDENTIAL_REQUEST", self.codes(result))

    def test_password_request(self):
        result = self.analyzer.analyze(
            self.raw("From: support@example.com", "Enter your password to confirm the update.")
        )
        self.assertIn("EMAIL_PASSWORD_REQUEST", self.codes(result))

    def test_otp_security_code_request(self):
        result = self.analyzer.analyze(
            self.raw("From: security@example.com", "Reply with your OTP and verification code immediately.")
        )
        self.assertIn("EMAIL_OTP_REQUEST", self.codes(result))

    def test_payment_request(self):
        result = self.analyzer.analyze(
            self.raw("From: billing@example.com", "Please make a payment now to keep your service active.")
        )
        self.assertIn("EMAIL_PAYMENT_REQUEST", self.codes(result))

    def test_banking_request(self):
        result = self.analyzer.analyze(
            self.raw("From: billing@example.com", "Send your bank account and card details for verification.")
        )
        self.assertIn("EMAIL_FINANCIAL_REQUEST", self.codes(result))

    def test_suspicious_sender_domain(self):
        result = self.analyzer.analyze(
            self.raw("From: security@192.0.2.10", "A normal-looking message.")
        )
        self.assertIn("EMAIL_SENDER_DOMAIN_SUSPICIOUS", self.codes(result))
        self.assertIn("IP address", result.indicators[0].explanation)

    def test_display_name_deception(self):
        result = self.analyzer.analyze(
            self.raw("From: PayPal Security <notice@random.example>", "Please review the notice.")
        )
        self.assertIn("EMAIL_DISPLAY_NAME_DECEPTION", self.codes(result))

    def test_from_reply_to_mismatch(self):
        result = self.analyzer.analyze(
            self.raw(
                "From: billing@company.example\nReply-To: helpdesk@different.example",
                "Please contact us.",
            )
        )
        self.assertIn("EMAIL_REPLY_TO_MISMATCH", self.codes(result))

    def test_malformed_reply_to_is_safe(self):
        result = self.analyzer.analyze(
            self.raw("From: sender@example.com\nReply-To: not-an-email", "Message body.")
        )
        self.assertTrue(result.success)
        self.assertIn("EMAIL_REPLY_TO_MALFORMED", self.codes(result))

    def test_email_with_normal_url(self):
        result = self.analyzer.analyze(
            self.raw("From: sender@example.com", "Read more at https://example.com/about.")
        )
        self.assertEqual(len(result.extracted_urls), 1)
        self.assertTrue(result.extracted_urls[0]["success"])
        self.assertEqual(result.extracted_urls[0]["indicators"], [])
        self.assertNotIn("EMAIL_CONTAINS_SUSPICIOUS_URL", self.codes(result))

    def test_email_with_suspicious_url_reuses_url_analyzer(self):
        result = self.analyzer.analyze(
            self.raw("From: sender@example.com", "Verify here: http://192.0.2.10/login")
        )
        nested = result.extracted_urls[0]
        nested_codes = [item["code"] for item in nested["indicators"]]
        self.assertIn("URL_IP_ADDRESS", nested_codes)
        self.assertIn("URL_HTTP", nested_codes)
        self.assertIn("EMAIL_CONTAINS_SUSPICIOUS_URL", self.codes(result))

    def test_multiple_urls_are_deduplicated_and_bounded(self):
        body = " ".join(
            [
                "https://example.com/one",
                "https://example.com/two",
                "https://example.com/one",
                "http://192.0.2.10/login",
            ]
        )
        result = self.analyzer.analyze(self.raw("From: sender@example.com", body))
        self.assertEqual(len(result.extracted_urls), 3)
        self.assertEqual(len({item["url"] for item in result.extracted_urls}), 3)

    def test_url_shortener_inside_email_uses_phase_three_rule(self):
        result = self.analyzer.analyze(self.raw("From: sender@example.com", "Open https://bit.ly/example"))
        nested_codes = [item["code"] for item in result.extracted_urls[0]["indicators"]]
        self.assertIn("URL_SHORTENER", nested_codes)

    def test_ip_based_url_inside_email_uses_phase_three_rule(self):
        result = self.analyzer.analyze(self.raw("From: sender@example.com", "Open http://192.0.2.10/login"))
        self.assertIn("URL_IP_ADDRESS", [item["code"] for item in result.extracted_urls[0]["indicators"]])

    def test_http_url_inside_email_uses_phase_three_rule(self):
        result = self.analyzer.analyze(self.raw("From: sender@example.com", "Open http://example.com/login"))
        self.assertIn("URL_HTTP", [item["code"] for item in result.extracted_urls[0]["indicators"]])

    def test_suspicious_attachment_filename(self):
        result = self.analyzer.analyze(
            sender="sender@example.com",
            body="Please review the file.",
            attachment_names="invoice.exe",
        )
        self.assertIn("EMAIL_RISKY_ATTACHMENT", self.codes(result))
        self.assertEqual(result.attachments[0].extension, ".exe")

    def test_multiple_attachment_names_are_stored_as_metadata_only(self):
        result = self.analyzer.analyze(
            sender="sender@example.com",
            body="See the attached documents.",
            attachment_names="invoice.pdf, policy.docm, archive.zip",
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.attachments), 3)
        self.assertEqual([item.extension for item in result.attachments], [".pdf", ".docm", ".zip"])
        self.assertNotIn("content", result.to_dict()["attachments"][0])

    def test_multipart_email_and_attachment_are_parsed(self):
        raw = """From: sender@example.com
To: user@example.com
Subject: Multipart notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary42"

--boundary42
Content-Type: text/plain; charset="utf-8"

Please review the attached invoice.
--boundary42
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"

not-file-content
--boundary42--
"""
        result = self.analyzer.analyze(raw)
        self.assertTrue(result.success)
        self.assertTrue(result.features.is_multipart)
        self.assertEqual(result.features.attachment_count, 1)
        self.assertEqual(result.attachments[0].filename, "invoice.pdf")
        self.assertGreater(result.features.body_length, 0)

    def test_html_email_is_parsed_as_inert_text(self):
        raw = """From: sender@example.com
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>Please <a href="https://suspicious.example.test/login">https://example.com</a> verify now.</p><script>do_not_execute()</script></body></html>
"""
        result = self.analyzer.analyze(raw)
        self.assertTrue(result.success)
        self.assertTrue(result.features.has_html)
        self.assertFalse(result.features.has_plain_text)
        self.assertNotIn("do_not_execute", result.features.subject)
        self.assertIn("EMAIL_LINK_TEXT_MISMATCH", self.codes(result))
        self.assertIn("https://suspicious.example.test/login", {item["url"] for item in result.extracted_urls})

    def test_link_text_mismatch_is_not_generated_for_matching_link(self):
        raw = self.raw(
            "From: sender@example.com\nContent-Type: text/html",
            '<a href="https://example.com/about">https://example.com/about</a>',
        )
        result = self.analyzer.analyze(raw)
        self.assertNotIn("EMAIL_LINK_TEXT_MISMATCH", self.codes(result))

    def test_missing_from_is_an_indicator_not_a_crash(self):
        result = self.analyzer.analyze(self.raw("Subject: Notice", "A message without a sender header."))
        self.assertTrue(result.success)
        self.assertIn("EMAIL_SENDER_MISSING", self.codes(result))

    def test_missing_subject_is_allowed(self):
        result = self.analyzer.analyze(self.raw("From: sender@example.com", "A message without a subject."))
        self.assertTrue(result.success)
        self.assertEqual(result.features.subject, "")

    def test_malformed_email_is_handled_gracefully(self):
        result = self.analyzer.analyze("From: sender@example.com\nContent-Type: multipart/mixed; boundary=missing\n\n--different\n")
        self.assertTrue(result.success)
        self.assertIsInstance(result.features.malformed_parts, tuple)

    def test_empty_email_fails_without_indicators(self):
        result = self.analyzer.analyze("")
        self.assertFalse(result.success)
        self.assertEqual(result.indicators, ())
        self.assertEqual(result.extracted_urls, ())
        self.assertEqual(result.attachments, ())

    def test_extremely_long_email_is_bounded(self):
        result = self.analyzer.analyze("From: sender@example.com\n\n" + ("x" * 50001))
        self.assertFalse(result.success)
        self.assertIn("maximum supported length", result.error)

    def test_extremely_long_structured_body_is_bounded(self):
        result = self.analyzer.analyze(sender="sender@example.com", body="x" * 30001)
        self.assertFalse(result.success)
        self.assertIn("body exceeds", result.error)

    def test_unicode_email_content_is_supported(self):
        result = self.analyzer.analyze(
            self.raw("From: José <sender@example.com>\nSubject: Vérification", "こんにちは。確認してください。")
        )
        self.assertTrue(result.success)
        self.assertIn("Vérification", result.features.subject)

    def test_encoded_headers_are_decoded_by_stdlib_parser(self):
        result = self.analyzer.analyze(
            self.raw("From: =?utf-8?b?Sm9zw6k=?= <sender@example.com>\nSubject: =?utf-8?b?VGVzdA==?=", "Body")
        )
        self.assertTrue(result.success)
        self.assertEqual(result.features.subject, "Test")
        self.assertEqual(result.features.sender_display_name, "José")

    def test_multiple_indicators_are_structured_and_ordered(self):
        result = self.analyzer.analyze(
            self.raw(
                "From: PayPal Security <notice@192.0.2.10>\nReply-To: help@different.example\nSubject: Urgent action required",
                "Act now. Enter your password and OTP to avoid account suspension. Open http://192.0.2.10/login.",
            ),
            attachment_names="invoice.exe, update.docm",
        )
        self.assertGreater(len(result.indicators), 5)
        self.assertEqual(
            [item.sort_order for item in result.indicators],
            list(range(1, len(result.indicators) + 1)),
        )
        for indicator in result.indicators:
            self.assertTrue(indicator.code)
            self.assertTrue(indicator.explanation)
            self.assertTrue(indicator.recommendation)

    def test_result_contract_has_no_final_score_or_verdict(self):
        result = self.analyzer.analyze(self.raw("From: sender@example.com", "Please verify your account."))
        data = result.to_dict()
        self.assertIn("features", data)
        self.assertIn("indicators", data)
        self.assertIn("extracted_urls", data)
        self.assertIn("attachments", data)
        self.assertNotIn("score", data)
        self.assertNotIn("risk_level", data)
        self.assertNotIn("verdict", data)

    def test_phase_three_url_analyzer_is_called_for_each_extracted_url(self):
        with patch("analysis.email_analyzer.analyze_url", wraps=analyze_url) as mocked:
            result = self.analyzer.analyze(
                self.raw("From: sender@example.com", "https://example.com/a https://example.com/b")
            )
        self.assertTrue(result.success)
        self.assertEqual(mocked.call_count, 2)

    def test_network_functions_are_not_used(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")), patch.object(
            socket, "gethostbyname", side_effect=AssertionError("DNS called")
        ), patch.object(socket, "socket", side_effect=AssertionError("socket called")), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP called")
        ):
            result = self.analyzer.analyze(
                self.raw("From: sender@example.com", "Please click http://192.0.2.10/login")
            )
        self.assertTrue(result.success)
        self.assertFalse(result.metadata["network_access"])


if __name__ == "__main__":
    unittest.main()
