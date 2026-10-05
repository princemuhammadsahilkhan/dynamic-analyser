import unittest
import json
import time
from dynamic_analysis.rules import InsecureHttpFormSubmissionRule
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestInsecureHttpFormSubmissionRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpFormSubmissionRule()
        self.session = AnalysisSession(package_name="com.example.app", apk_path="/tmp/test.apk")
        self.timestamp = time.time()

    def _create_http_evidence(self, content: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=content,
            timestamp=self.timestamp,
            source="mitmproxy",
            serial="serial1"
        )

    def _create_https_evidence(self, content: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=content,
            timestamp=self.timestamp,
            source="mitmproxy",
            serial="serial1"
        )

    def test_json_password_field_http(self):
        content = json.dumps({
            "url": "http://example.com/login",
            "request_content": '{"username":"alice", "password":"secret123"}'
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        
        found_password = False
        found_username = False
        for f in result.findings:
            if "password" in f.title.lower():
                found_password = True
                self.assertIn("sec...<redacted>", f.description)
                self.assertNotIn("secret123", f.description)
            if "username" in f.title.lower():
                found_username = True
        
        self.assertTrue(found_password)
        self.assertTrue(found_username)

    def test_urlencoded_email_http(self):
        content = json.dumps({
            "url": "http://example.com/signup",
            "request_content": "email=user%40example.com&phone=555-1234"
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        
        found_email = False
        for f in result.findings:
            if "email" in f.title.lower():
                found_email = True
                self.assertIn("use...<redacted>", f.description)
        self.assertTrue(found_email)

    def test_ssn_credit_card_cvv_http(self):
        content = json.dumps({
            "url": "http://example.com/checkout",
            "request_content": '{"credit_card":"4111111111111111", "cvv":"123", "ssn":"000-00-0000"}'
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 3)

    def test_access_token_api_key_http(self):
        content = json.dumps({
            "url": "http://example.com/api",
            "request_content": "access_token=xyz789&api_key=abc456"
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)

    def test_https_ignored(self):
        content = json.dumps({
            "url": "https://example.com/login",
            "request_content": '{"password":"secret123"}'
        })
        result = self.rule.evaluate(self.session, [self._create_https_evidence(content)])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_generic_words_ignored(self):
        content = json.dumps({
            "url": "http://example.com/info",
            "request_content": "Here is a password field and a user login or email form"
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_empty_values_ignored(self):
        content = json.dumps({
            "url": "http://example.com/login",
            "request_content": "username=&password="
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertFalse(result.triggered)

    def test_missing_request_content(self):
        content = json.dumps({
            "url": "http://example.com/login"
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertFalse(result.triggered)

    def test_malformed_json_evidence_ignored(self):
        content = "this is not json { url: bad"
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertFalse(result.triggered)

    def test_case_insensitive_field_handling(self):
        content = json.dumps({
            "url": "http://example.com/login",
            "request_content": "PassWord=secret123&USERname=alice"
        })
        result = self.rule.evaluate(self.session, [self._create_http_evidence(content)])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)

    def test_deterministic_deduplication(self):
        content = json.dumps({
            "url": "http://example.com/login",
            "request_content": "password=secret123"
        })
        result = self.rule.evaluate(self.session, [
            self._create_http_evidence(content),
            self._create_http_evidence(content)
        ])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

if __name__ == '__main__':
    unittest.main()
