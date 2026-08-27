from django.test import SimpleTestCase

from scans.forms import EmailScanForm, URLScanForm


class PhaseOneFormTests(SimpleTestCase):
    def test_url_form_has_text_input(self):
        form = URLScanForm()
        self.assertIn('name="url"', str(form))
        self.assertIn("Submit the address as text", str(form))

    def test_email_form_has_required_phase_one_fields(self):
        rendered = str(EmailScanForm())
        for field_name in ("sender", "reply_to", "subject", "body", "attachment_names"):
            self.assertIn(f'name="{field_name}"', rendered)

    def test_url_form_rejects_values_longer_than_limit(self):
        form = URLScanForm({"url": "x" * 2049})
        self.assertFalse(form.is_valid())

    def test_email_form_accepts_optional_structured_fields(self):
        form = EmailScanForm(
            {
                "sender": "sender@example.com",
                "reply_to": "reply@example.com",
                "subject": "Subject",
                "body": "Body",
                "attachment_names": "invoice.pdf",
            }
        )
        self.assertTrue(form.is_valid())
