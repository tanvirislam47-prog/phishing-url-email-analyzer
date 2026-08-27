import socket
import unittest
import urllib.request
from unittest.mock import patch

from analysis.url_analyzer import URLAnalyzer, analyze_url


class URLAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = URLAnalyzer()

    @staticmethod
    def codes(result):
        return [indicator.code for indicator in result.indicators]

    def test_safe_ordinary_https_url(self):
        result = self.analyzer.analyze("https://example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.features.hostname, "example.com")
        self.assertEqual(result.features.domain, "example.com")
        self.assertEqual(result.features.subdomain, "")
        self.assertTrue(result.features.uses_https)
        self.assertFalse(result.features.uses_http)
        self.assertNotIn("URL_HTTP", self.codes(result))

    def test_safe_url_with_path_query_and_fragment(self):
        result = analyze_url("https://www.example.com/products?id=10#reviews")
        self.assertTrue(result.success)
        self.assertEqual(result.features.domain, "example.com")
        self.assertEqual(result.features.subdomain, "www")
        self.assertEqual(result.features.path, "/products")
        self.assertEqual(result.features.query, "id=10")
        self.assertEqual(result.features.fragment, "reviews")
        self.assertEqual(result.features.query_parameter_count, 1)

    def test_empty_and_whitespace_inputs_fail_without_indicators(self):
        for value in ("", "   ", "\t\n"):
            result = self.analyzer.analyze(value)
            self.assertFalse(result.success)
            self.assertEqual(result.indicators, ())
            self.assertTrue(result.error)

    def test_missing_scheme_is_reported_as_malformed_input(self):
        result = self.analyzer.analyze("example.com/login")
        self.assertFalse(result.success)
        self.assertIn("missing a scheme", result.error)

    def test_invalid_hostname_character_is_reported_as_malformed_input(self):
        result = self.analyzer.analyze("https://exa mple.com/login")
        self.assertFalse(result.success)
        self.assertIn("invalid hostname", result.error)

    def test_malformed_bracketed_ipv6_is_handled(self):
        result = self.analyzer.analyze("https://[2001:db8::1/login")
        self.assertFalse(result.success)
        self.assertIn("malformed", result.error)

    def test_invalid_port_is_handled(self):
        result = self.analyzer.analyze("https://example.com:notaport/")
        self.assertFalse(result.success)
        self.assertIn("malformed", result.error)

    def test_extremely_long_url_is_bounded(self):
        result = self.analyzer.analyze("https://example.com/" + ("a" * 2048))
        self.assertFalse(result.success)
        self.assertIn("maximum supported length", result.error)

    def test_control_character_is_rejected(self):
        result = self.analyzer.analyze("https://example.com/\x00login")
        self.assertFalse(result.success)
        self.assertIn("control characters", result.error)

    def test_ipv4_hostname_is_detected(self):
        result = self.analyzer.analyze("http://192.0.2.10/login")
        self.assertTrue(result.success)
        self.assertTrue(result.features.uses_ip)
        self.assertEqual(result.features.ip_version, 4)
        self.assertEqual(result.features.domain, "192.0.2.10")
        self.assertIn("URL_IP_ADDRESS", self.codes(result))

    def test_ipv6_hostname_is_detected(self):
        result = self.analyzer.analyze("https://[2001:db8::10]/account")
        self.assertTrue(result.success)
        self.assertTrue(result.features.uses_ip)
        self.assertEqual(result.features.ip_version, 6)
        self.assertIn("URL_IP_ADDRESS", self.codes(result))

    def test_http_is_a_medium_transport_signal(self):
        result = self.analyzer.analyze("http://example.com/login")
        indicator = next(item for item in result.indicators if item.code == "URL_HTTP")
        self.assertEqual(indicator.severity, "MEDIUM")
        self.assertEqual(indicator.points, 10)
        self.assertIn("does not encrypt", indicator.explanation.lower())

    def test_https_does_not_create_http_signal_or_safety_verdict(self):
        result = self.analyzer.analyze("https://example.com")
        self.assertNotIn("URL_HTTP", self.codes(result))
        self.assertNotIn("score", result.to_dict())
        self.assertNotIn("verdict", result.to_dict())

    def test_unknown_scheme_is_reported_without_network_assumptions(self):
        result = self.analyzer.analyze("ftp://example.com/file")
        self.assertTrue(result.success)
        self.assertIn("URL_UNKNOWN_SCHEME", self.codes(result))

    def test_long_url_hostname_and_path_thresholds(self):
        long_host = "a" * 81 + ".example"
        long_path = "/" + ("segment/" * 16) + ("x" * 5)
        result = self.analyzer.analyze(f"https://{long_host}{long_path}")
        codes = self.codes(result)
        self.assertIn("URL_LONG_HOSTNAME", codes)
        self.assertIn("URL_LONG_PATH", codes)
        self.assertIn("URL_LONG", codes)

    def test_excessive_subdomains_are_a_supporting_signal(self):
        result = self.analyzer.analyze("https://a.b.c.d.example.test/account")
        self.assertEqual(result.features.subdomain_count, 4)
        self.assertIn("URL_EXCESSIVE_SUBDOMAINS", self.codes(result))

    def test_excessive_hyphens_are_detected_conservatively(self):
        result = self.analyzer.analyze("https://secure-account-login-confirm-verify.example.com/")
        self.assertIn("URL_EXCESSIVE_HYPHENS", self.codes(result))

    def test_at_symbol_in_authority_is_detected(self):
        result = self.analyzer.analyze("http://example.test@evil.example/login")
        self.assertTrue(result.features.has_at_symbol)
        self.assertTrue(result.features.has_authentication_syntax)
        self.assertEqual(result.features.hostname, "evil.example")
        self.assertIn("URL_AT_SYMBOL", self.codes(result))
        self.assertIn("URL_AUTHENTICATION_SYNTAX", self.codes(result))

    def test_at_symbol_in_query_is_not_misclassified_as_authority(self):
        result = self.analyzer.analyze("https://example.com/contact?email=a%40b.example")
        self.assertFalse(result.features.has_at_symbol)
        self.assertNotIn("URL_AT_SYMBOL", self.codes(result))

    def test_suspicious_keyword_contains_match_and_location(self):
        result = self.analyzer.analyze("https://example.com/account/verify-login")
        matches = result.features.suspicious_keyword_matches
        self.assertTrue(any(item["keyword"] == "verify" and item["location"] == "path" for item in matches))
        self.assertTrue(any(item["keyword"] == "login" for item in matches))
        self.assertIn("URL_SUSPICIOUS_KEYWORD", self.codes(result))

    def test_suspicious_tld_is_not_a_verdict(self):
        result = self.analyzer.analyze("https://example.top/account")
        self.assertTrue(result.features.has_suspicious_tld)
        indicator = next(item for item in result.indicators if item.code == "URL_SUSPICIOUS_TLD")
        self.assertEqual(indicator.severity, "LOW")
        self.assertIn("does not establish", indicator.explanation)
        self.assertNotIn("verdict", result.to_dict())

    def test_shortener_is_detected_without_expansion(self):
        result = self.analyzer.analyze("https://bit.ly/abc123")
        self.assertTrue(result.features.uses_shortener)
        self.assertIn("URL_SHORTENER", self.codes(result))

    def test_common_ports_are_not_flagged_as_unusual(self):
        for url in ("http://example.com:80/", "https://example.com:443/", "https://example.com:8080/"):
            result = self.analyzer.analyze(url)
            self.assertNotIn("URL_UNUSUAL_PORT", self.codes(result), url)

    def test_unusual_port_is_detected(self):
        result = self.analyzer.analyze("https://example.com:9000/login")
        self.assertEqual(result.features.port, 9000)
        self.assertIn("URL_UNUSUAL_PORT", self.codes(result))

    def test_percent_encoding_and_excessive_encoding(self):
        encoded = "%41" * 12
        result = self.analyzer.analyze(f"https://example.com/{encoded}")
        self.assertTrue(result.features.has_percent_encoding)
        self.assertTrue(result.features.has_repeated_percent_encoding)
        self.assertTrue(result.features.has_long_encoded_sequence)
        self.assertIn("URL_PERCENT_ENCODING", self.codes(result))
        self.assertIn("URL_EXCESSIVE_ENCODING", self.codes(result))

    def test_unusual_characters_and_repeated_separators_are_detected(self):
        result = self.analyzer.analyze("https://example.com\\\\login////verify")
        self.assertTrue(result.features.has_backslash)
        self.assertGreaterEqual(result.features.repeated_separator_count, 2)
        self.assertIn("URL_SUSPICIOUS_CHARACTERS", self.codes(result))

    def test_path_depth_is_detected(self):
        result = self.analyzer.analyze("https://example.com/a/b/c/d/e/f")
        self.assertEqual(result.features.path_depth, 6)
        self.assertIn("URL_EXCESSIVE_PATH_DEPTH", self.codes(result))

    def test_punycode_is_detected_as_a_review_signal(self):
        result = self.analyzer.analyze("https://xn--pple-43d.example/verify")
        self.assertTrue(result.features.has_punycode)
        self.assertIn("URL_PUNYCODE", self.codes(result))

    def test_unicode_input_is_handled_locally(self):
        result = self.analyzer.analyze("https://例子.测试/登录")
        self.assertTrue(result.success)
        self.assertEqual(result.features.hostname, "例子.测试")

    def test_brand_like_structure_requires_reinforcing_structure(self):
        ordinary = self.analyzer.analyze("https://paypal.example/")
        unusual = self.analyzer.analyze("https://paypal.account.example.test/verify")
        self.assertNotIn("URL_BRAND_LIKE_STRUCTURE", self.codes(ordinary))
        self.assertIn("URL_BRAND_LIKE_STRUCTURE", self.codes(unusual))

    def test_indicator_contract_and_order_are_stable(self):
        result = self.analyzer.analyze("http://192.0.2.10:9000/a/b/c/d/e/f/login")
        self.assertTrue(result.success)
        self.assertEqual(result.indicators, tuple(sorted(result.indicators, key=lambda item: item.sort_order)))
        self.assertEqual([item.sort_order for item in result.indicators], list(range(1, len(result.indicators) + 1)))
        for indicator in result.indicators:
            self.assertTrue(indicator.code)
            self.assertTrue(indicator.category)
            self.assertTrue(indicator.title)
            self.assertTrue(indicator.severity)
            self.assertIsInstance(indicator.points, int)
            self.assertTrue(indicator.explanation)
            self.assertTrue(indicator.recommendation)

    def test_result_contract_serializes_features_and_indicators(self):
        result = self.analyzer.analyze("https://example.com/login?next=%2Faccount#top")
        data = result.to_dict()
        self.assertTrue(data["success"])
        self.assertEqual(data["features"]["scheme"], "https")
        self.assertIsInstance(data["indicators"], list)
        self.assertFalse(any(key in data for key in ("score", "risk_level", "verdict")))

    def test_analysis_is_deterministic(self):
        url = "https://a.b.c.example.top:9000/account/verify?next=%252Flogin"
        first = self.analyzer.analyze(url).to_dict()
        second = self.analyzer.analyze(url).to_dict()
        self.assertEqual(first, second)

    def test_analyzer_does_not_call_network_functions(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")), patch.object(
            socket, "gethostbyname", side_effect=AssertionError("DNS called")
        ), patch.object(socket, "socket", side_effect=AssertionError("socket called")), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP called")
        ), patch.object(urllib.request, "Request", side_effect=AssertionError("HTTP called")):
            result = self.analyzer.analyze("http://192.0.2.10:8080/login")
        self.assertTrue(result.success)
        self.assertIn("URL_IP_ADDRESS", self.codes(result))


if __name__ == "__main__":
    unittest.main()
