"""
Unit tests for analyzer.py.
Run with: python -m unittest discover tests -v
"""

import os
import sys
import unittest
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
import io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analyzer import (  # noqa: E402
    extract_domain,
    analyze_headers,
    analyze_sender_domain,
    analyze_urls,
    analyze_content,
    score_email,
)


def make_msg(from_header, subject="Test", body_text="", body_html=None,
             reply_to=None, extra_headers=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = "recipient@example.com"
    if reply_to:
        msg["Reply-To"] = reply_to
    if extra_headers:
        for k, v in extra_headers.items():
            msg[k] = v
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    # round-trip through bytes to get a "real" parsed message like the analyzer receives
    raw = bytes(msg)
    return BytesParser(policy=policy.default).parse(io.BytesIO(raw))


class TestDomainExtraction(unittest.TestCase):
    def test_extract_domain_basic(self):
        self.assertEqual(extract_domain("user@example.com"), "example.com")

    def test_extract_domain_with_display_name(self):
        self.assertEqual(extract_domain('"Someone" <someone@sub.example.com>'), "sub.example.com")

    def test_extract_domain_empty(self):
        self.assertEqual(extract_domain(""), "")


class TestHeaderAnalysis(unittest.TestCase):
    def test_reply_to_mismatch_flagged(self):
        msg = make_msg(
            from_header='"Support" <support@example.com>',
            reply_to="attacker@evil.com",
        )
        findings = analyze_headers(msg)
        messages = [f["message"] for f in findings]
        self.assertTrue(any("Reply-To domain" in m for m in messages))

    def test_no_auth_results_flagged(self):
        msg = make_msg(from_header="user@example.com")
        findings = analyze_headers(msg)
        self.assertTrue(any("Authentication-Results" in f["message"] for f in findings))

    def test_spf_fail_flagged(self):
        msg = make_msg(
            from_header="user@example.com",
            extra_headers={"Authentication-Results": "mx.example.com; spf=fail"},
        )
        findings = analyze_headers(msg)
        self.assertTrue(any("SPF" in f["message"] for f in findings))

    def test_clean_headers_no_findings(self):
        msg = make_msg(
            from_header='"Support" <support@example.com>',
            reply_to="support@example.com",
            extra_headers={"Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"},
        )
        findings = analyze_headers(msg)
        self.assertEqual(len(findings), 0)


class TestSenderDomainAnalysis(unittest.TestCase):
    def test_brand_impersonation_flagged(self):
        msg = make_msg(from_header='"PayPal Security" <security@account-alert-center.net>')
        findings = analyze_sender_domain(msg)
        self.assertTrue(any("paypal" in f["message"].lower() for f in findings))

    def test_lookalike_domain_flagged(self):
        msg = make_msg(from_header='"Account Team" <security@paypa1.com>')
        findings = analyze_sender_domain(msg)
        self.assertTrue(any("lookalike" in f["message"] for f in findings))

    def test_free_mail_impersonating_support_flagged(self):
        msg = make_msg(from_header='"IT Support" <it-support@gmail.com>')
        findings = analyze_sender_domain(msg)
        self.assertTrue(any("free consumer mail domain" in f["message"] for f in findings))

    def test_legitimate_sender_no_findings(self):
        msg = make_msg(from_header='"Darren Otieno" <darren@example.com>')
        findings = analyze_sender_domain(msg)
        self.assertEqual(len(findings), 0)


class TestUrlAnalysis(unittest.TestCase):
    def test_ip_based_url_flagged(self):
        msg = make_msg(from_header="a@example.com", body_text="Click http://185.220.101.47/login")
        findings = analyze_urls(msg)
        self.assertTrue(any("raw IP address" in f["message"] for f in findings))

    def test_shortener_flagged(self):
        msg = make_msg(from_header="a@example.com", body_text="Click http://bit.ly/abcd")
        findings = analyze_urls(msg)
        self.assertTrue(any("shortener" in f["message"] for f in findings))

    def test_anchor_mismatch_flagged(self):
        html = '<a href="http://evil.com/login">http://paypal.com/login</a>'
        msg = make_msg(from_header="a@example.com", body_text="see link", body_html=html)
        findings = analyze_urls(msg)
        self.assertTrue(any("does not match" in f["message"] for f in findings))

    def test_normal_url_no_findings(self):
        msg = make_msg(from_header="a@example.com", body_text="Visit https://example.com/blog")
        findings = analyze_urls(msg)
        self.assertEqual(len(findings), 0)


class TestContentAnalysis(unittest.TestCase):
    def test_urgency_language_flagged(self):
        msg = make_msg(
            from_header="a@example.com",
            body_text="Your account will be suspended immediately unless you act now.",
        )
        findings = analyze_content(msg)
        self.assertTrue(any("urgency" in f["message"] for f in findings))

    def test_credential_request_flagged(self):
        msg = make_msg(from_header="a@example.com", body_text="Please click here to verify your details.")
        findings = analyze_content(msg)
        self.assertTrue(any("credential" in f["message"].lower() or "payment details" in f["message"] for f in findings))

    def test_generic_greeting_flagged(self):
        msg = make_msg(from_header="a@example.com", body_text="Dear Customer, thank you for your business.")
        findings = analyze_content(msg)
        self.assertTrue(any("generic greeting" in f["message"] for f in findings))

    def test_normal_email_no_findings(self):
        msg = make_msg(from_header="a@example.com", body_text="Hi Papi, the meeting is at 3pm tomorrow.")
        findings = analyze_content(msg)
        self.assertEqual(len(findings), 0)


class TestScoring(unittest.TestCase):
    def test_clean_email_scores_zero(self):
        msg = make_msg(
            from_header='"Darren" <darren@example.com>',
            body_text="Hi, the sprint review is at 3pm tomorrow.",
            extra_headers={"Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"},
        )
        result = score_email(msg)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "No Indicators Found")

    def test_obvious_phishing_scores_high(self):
        msg = make_msg(
            from_header='"PayPal Security" <security@paypa1-verify.com>',
            body_text="Dear Customer, your account will be suspended immediately. "
                       "Click here to verify your account: http://185.220.101.47/login",
        )
        result = score_email(msg)
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["verdict"], "Likely Phishing")

    def test_score_capped_at_100(self):
        msg = make_msg(
            from_header='"PayPal Security Amazon Apple" <security@paypa1-secure-verify-login.net>',
            reply_to="attacker@evil.com",
            body_text="Dear Customer, urgent, act now, suspended, verify your account, "
                       "confirm your identity, unusual activity, unauthorized access, expire, "
                       "final notice, failure to comply, restricted, will be closed, will be deleted. "
                       "Click here to verify your password: http://185.220.101.47/login "
                       "http://bit.ly/xyz",
        )
        result = score_email(msg)
        self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
