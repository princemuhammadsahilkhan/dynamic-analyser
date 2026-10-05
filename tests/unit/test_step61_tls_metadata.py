import unittest
import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from dynamic_analysis.proxy import ProxyManager, TrafficObservation
from dynamic_analysis.rules import WeakTLSRule
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.session import AnalysisSession

class TestStep61TLSMetadata(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="fake.apk")
        self.rule = WeakTLSRule()
        self.proxy_manager = ProxyManager(binary_path="mitmdump")

    def create_mock_flow(self, scheme, tls_est=True, tls_ver=None, cipher=None, sni=None, alpn=None):
        req = MagicMock()
        req.scheme = scheme
        req.host = "example.com"
        req.port = 443
        req.method = "GET"
        req.url = f"{scheme}://example.com/"
        req.http_version = "HTTP/2.0"
        req.content = b"test"

        resp = MagicMock()
        resp.status_code = 200

        server_conn = MagicMock()
        server_conn.tls_established = tls_est
        if tls_ver is not None:
            server_conn.tls_version = tls_ver
        else:
            del server_conn.tls_version
        
        if cipher is not None:
            server_conn.cipher = cipher
        else:
            del server_conn.cipher
            
        if sni is not None:
            server_conn.sni = sni
        else:
            del server_conn.sni
            
        if alpn is not None:
            server_conn.alpn_proto_negotiated = alpn
        else:
            del server_conn.alpn_proto_negotiated
            del server_conn.alpn

        flow = MagicMock()
        flow.request = req
        flow.response = resp
        flow.error = None
        flow.server_conn = server_conn
        
        if scheme != "https" or not tls_est:
            flow.server_conn = server_conn if tls_est else None
            
        return flow

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_metadata_extracted(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(
            scheme="https", tls_est=True, tls_ver="TLSv1.2", cipher="TLS_AES_128_GCM_SHA256", sni="example.com", alpn=b"h2"
        )
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            self.assertEqual(len(obs_list), 1)
            obs = obs_list[0]
            self.assertTrue(obs.tls_established)
            self.assertEqual(obs.raw_metadata.get("tls_version"), "TLSv1.2")
            self.assertEqual(obs.raw_metadata.get("cipher_suite"), "TLS_AES_128_GCM_SHA256")
            self.assertEqual(obs.raw_metadata.get("sni"), "example.com")
            
            # Since ALPN might be bytes, JSON serialization might fail later, but extracting handles bytes by default
            # However, json serialization doesn't support bytes by default, so we might need to handle it in proxy.py
            # Since ALPN might be bytes, proxy.py decodes it to a string.
            self.assertEqual(obs.raw_metadata.get("alpn"), "h2")
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_1_0_extraction_and_rule(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True, tls_ver="TLSv1.0")
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertEqual(obs.raw_metadata.get("tls_version"), "TLSv1.0")
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertTrue(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_1_1_extraction_and_rule(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True, tls_ver="TLSv1.1")
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertEqual(obs.raw_metadata.get("tls_version"), "TLSv1.1")
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertTrue(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_1_2_extraction(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True, tls_ver="TLSv1.2")
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertEqual(obs.raw_metadata.get("tls_version"), "TLSv1.2")
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertFalse(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_1_3_extraction(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True, tls_ver="TLSv1.3")
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertEqual(obs.raw_metadata.get("tls_version"), "TLSv1.3")
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertFalse(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_missing_tls_metadata(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True)
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertTrue(obs.tls_established)
            self.assertIsNone(obs.raw_metadata.get("tls_version"))
            self.assertIsNone(obs.raw_metadata.get("cipher_suite"))
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertFalse(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_tls_handshake_failure(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=False)
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertFalse(obs.tls_established)
            self.assertNotIn("tls_version", obs.raw_metadata)
            
            ev = EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                timestamp="123",
                source="proxy",
                serial="test",
                content=json.dumps(obs.__dict__)
            )
            res = self.rule.evaluate(self.session, [ev])
            self.assertFalse(res.triggered)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_malformed_flow(self, mock_open, mock_reader_class):
        mock_flow = MagicMock()
        del mock_flow.request # no request attr
        
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            self.assertEqual(len(obs_list), 0)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_json_serialization(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="https", tls_est=True, alpn="h2")
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            content = json.dumps(obs.__dict__)
            self.assertIn("alpn", content)
        finally:
            os.unlink(temp_path)

    @patch("mitmproxy.io.FlowReader")
    @patch("builtins.open")
    def test_backward_compatibility(self, mock_open, mock_reader_class):
        mock_flow = self.create_mock_flow(scheme="http", tls_est=False)
        mock_reader = MagicMock()
        mock_reader.stream.return_value = [mock_flow]
        mock_reader_class.return_value = mock_reader
        
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_path = tf.name
            
        try:
            obs_list = self.proxy_manager.parse_flow_file(temp_path)
            obs = obs_list[0]
            self.assertEqual(obs.scheme, "http")
            self.assertFalse(obs.tls_established)
            self.assertNotIn("tls_version", obs.raw_metadata)
            self.assertIn("http_version", obs.raw_metadata)
        finally:
            os.unlink(temp_path)

if __name__ == "__main__":
    unittest.main()
