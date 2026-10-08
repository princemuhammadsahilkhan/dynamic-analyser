import json
from typing import List
try:
    import pytest
except ModuleNotFoundError:  # pragma: no cover - compatibility for unittest-only environments
    class _PytestCompat:
        @staticmethod
        def fixture(func):
            return func

    pytest = _PytestCompat()

from dynamic_analysis.rules import (
    MissingPermissionsPolicyRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
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
    return MissingPermissionsPolicyRule()

def create_evidence(headers: dict, host: str = "example.com", evidence_type: EvidenceType = EvidenceType.HTTP_TRAFFIC) -> EvidenceItem:
    content = {
        "host": host,
        "request": {"host": host},
        "raw_metadata": {
            "response_headers": headers
        }
    }
    return EvidenceItem(
        evidence_type=evidence_type.value,
        content=json.dumps(content),
        timestamp=12345.0,
        source="proxy",
        serial="test_serial"
    )

def test_rule_metadata(rule):
    assert rule.rule_id == "RULE-018"
    assert rule.name == "Missing Permissions-Policy Header Observed"
    assert rule.category == FindingCategory.NETWORK
    assert rule.severity == FindingSeverity.LOW

def test_evaluate_triggers_when_missing(rule, session):
    headers = {
        "Server": "nginx",
        "Content-Type": "text/html"
    }
    ev = create_evidence(headers)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert result.findings[0].title == "[RULE-018] Missing Permissions-Policy Header Observed - example.com"
    assert "without a 'Permissions-Policy' header" in result.findings[0].description
    assert result.findings[0].severity == FindingSeverity.LOW
    assert result.findings[0].category == FindingCategory.NETWORK

def test_evaluate_does_not_trigger_when_present(rule, session):
    headers = {
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Content-Type": "text/html"
    }
    ev = create_evidence(headers)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_does_not_trigger_when_present_case_insensitive(rule, session):
    headers = {
        "permissions-POLICY": "geolocation=()",
        "Content-Type": "text/html"
    }
    ev = create_evidence(headers)
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_ignores_missing_metadata(rule, session):
    content = {
        "host": "example.com",
        "request": {"host": "example.com"}
    }
    ev = EvidenceItem(
        evidence_type=EvidenceType.HTTP_TRAFFIC.value,
        content=json.dumps(content),
        timestamp=12345.0,
        source="proxy",
        serial="test_serial"
    )
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_ignores_malformed_json(rule, session):
    ev = EvidenceItem(
        evidence_type=EvidenceType.HTTP_TRAFFIC.value,
        content="invalid json",
        timestamp=12345.0,
        source="proxy",
        serial="test_serial"
    )
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is False

def test_evaluate_deduplicates_by_host(rule, session):
    headers = {
        "Server": "nginx"
    }
    ev1 = create_evidence(headers, host="api.example.com")
    ev2 = create_evidence(headers, host="api.example.com")
    
    result = rule.evaluate(session, [ev1, ev2])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert len(result.evidence_references) == 1
    assert result.findings[0].title == "[RULE-018] Missing Permissions-Policy Header Observed - api.example.com"
