import json
import pytest
from typing import List

from dynamic_analysis.rules import (
    SensitiveLogcatDataRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
    AnalysisSession
)

@pytest.fixture
def session():
    return AnalysisSession(
        apk_path="fake.apk",
        base_output_dir="/tmp/fake",
        package_name="com.example.app"
    )

@pytest.fixture
def rule():
    return SensitiveLogcatDataRule()

def create_logcat_evidence(content: str, timestamp: float = 12345.0, source: str = "proxy", serial: str = "test_serial") -> EvidenceItem:
    return EvidenceItem(
        evidence_type=EvidenceType.LOGCAT.value,
        content=content,
        timestamp=timestamp,
        source=source,
        serial=serial
    )

def test_rule_metadata(rule):
    assert rule.rule_id == "RULE-019"
    assert rule.name == "Sensitive Data Observed in Logcat"
    assert rule.category == FindingCategory.MISC
    assert rule.severity == FindingSeverity.MEDIUM

def test_evaluate_triggers_on_password(rule, session):
    content = "10-25 12:34:56.789  1234  5678 D MyApp: User login password: SuperSecret123!"
    ev = create_logcat_evidence(content)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert "Password" in result.findings[0].description
    # Assert redaction
    assert "Sup...<redacted>" in result.findings[0].description
    assert "SuperSecret123!" not in result.findings[0].description

def test_evaluate_triggers_on_api_key(rule, session):
    content = "API_KEY = \"AIzaSyB-1234567890abcdefghijklmnopqrstuvwxyz\""
    ev = create_logcat_evidence(content)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert "API Key / Token" in result.findings[0].description
    assert "AIz...<redacted>" in result.findings[0].description
    assert "AIzaSyB-1234567890abcdefghijklmnopqrstuvwxyz" not in result.findings[0].description

def test_evaluate_triggers_on_authorization_header(rule, session):
    content = "Sending request with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ev = create_logcat_evidence(content)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert "Authorization Header" in result.findings[0].description
    assert "eyJ...<redacted>" in result.findings[0].description
    
def test_evaluate_ignores_generic_words(rule, session):
    content = "We need a key or a password to access this token."
    ev = create_logcat_evidence(content)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_ignores_non_logcat(rule, session):
    ev = EvidenceItem(
        evidence_type=EvidenceType.HTTP_TRAFFIC.value,
        content="API_KEY = \"AIzaSyB-1234567890abcdefghijklmnopqrstuvwxyz\"",
        timestamp=123.0,
        source="proxy",
        serial="test_serial"
    )
    result = rule.evaluate(session, [ev])
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_deduplicates(rule, session):
    content = "Password: SuperSecret123!"
    ev1 = create_logcat_evidence(content)
    ev2 = create_logcat_evidence(content)
    result = rule.evaluate(session, [ev1, ev2])
    
    assert result.triggered is True
    assert len(result.findings) == 1
