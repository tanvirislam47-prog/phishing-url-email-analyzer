from django.test import TestCase
from django.urls import reverse


class PhaseOneViewTests(TestCase):
    def test_navigation_pages_render(self):
        for name in (
            "core:home",
            "core:about",
            "scans:url",
            "scans:email",
            "scans:result",
            "scans:history",
            "dashboard:index",
        ):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200, name)

    def test_url_post_does_not_claim_to_have_analyzed(self):
        response = self.client.post(
            reverse("scans:url"),
            {"url": "https://example.com/account/verify"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No URL analysis was performed")
        self.assertNotContains(response, "Risk score: 87")

    def test_email_post_does_not_claim_to_have_analyzed(self):
        response = self.client.post(
            reverse("scans:email"),
            {
                "sender": "sender@example.com",
                "reply_to": "reply@example.com",
                "subject": "Please review",
                "body": "Message body",
                "attachment_names": "notice.pdf",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No email analysis was performed")

    def test_forms_include_csrf_protection(self):
        self.assertContains(self.client.get(reverse("scans:url")), "csrfmiddlewaretoken")
        self.assertContains(self.client.get(reverse("scans:email")), "csrfmiddlewaretoken")

    def test_dashboard_is_an_honest_zero_state(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertContains(response, "Total scans")
        self.assertContains(response, ">0<")
        self.assertContains(response, "No analyses recorded")
