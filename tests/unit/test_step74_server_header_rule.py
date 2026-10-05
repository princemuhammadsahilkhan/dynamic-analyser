import json
import pytest
from typing import List

from dynamic_analysis.rules import (
    ServerHeaderDisclosureRule,
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
    return ServerHeaderDisclosureRule()

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
    assert rule.rule_id == "RULE-017"
    assert rule.name == "Server Header Information Disclosure Observed"
    assert rule.category == FindingCategory.NETWORK
    assert rule.severity == FindingSeverity.INFO

def test_evaluate_triggers_on_server(rule, session):
    headers = {
        "Server": "Apache/2.4.1 (Unix)",
        "Content-Type": "text/html"
    }
    ev = create_evidence(headers, host="example.com")
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert result.findings[0].title == "[RULE-017] Server Header Information Disclosure Observed (Server) - example.com"
    assert "Apache/2.4.1 (Unix)" in result.findings[0].description
    assert "Server" in result.findings[0].description

def test_evaluate_triggers_on_x_powered_by(rule, session):
    headers = {
        "x-powered-by": "PHP/5.3.0",
        "Content-Type": "text/html"
    }
    ev = create_evidence(headers, host="example.org")
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 1
    assert "PHP/5.3.0" in result.findings[0].description
    assert "x-powered-by" in result.findings[0].description
    assert result.findings[0].title == "[RULE-017] Server Header Information Disclosure Observed (x-powered-by) - example.org"

def test_evaluate_triggers_on_both(rule, session):
    headers = {
        "Server": "nginx",
        "X-Powered-By": ["Express", "ASP.NET"]
    }
    ev = create_evidence(headers, host="api.example.com")
    result = rule.evaluate(session, [ev])
    
    assert result.triggered is True
    assert len(result.findings) == 2
    titles = [f.title for f in result.findings]
    assert "[RULE-017] Server Header Information Disclosure Observed (Server) - api.example.com" in titles
    assert "[RULE-017] Server Header Information Disclosure Observed (X-Powered-By) - api.example.com" in titles
    
def test_evaluate_ignores_missing_headers(rule, session):
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    }
    ev = create_evidence(headers)
    result = rule.evaluate(session, [ev])
    assert result.triggered is False
    assert len(result.findings) == 0

def test_evaluate_ignores_malformed_evidence(rule, session):
    ev1 = EvidenceItem(
        evidence_type=EvidenceType.HTTP_TRAFFIC.value,
        content="{invalid json",
        timestamp=123.0,
        source="proxy",
        serial="test_serial"
    )
    ev2 = EvidenceItem(
        evidence_type=EvidenceType.HTTP_TRAFFIC.value,
        content=json.dumps({"host": "foo.com"}), # missing raw_metadata
        timestamp=124.0,
        source="proxy",
        serial="test_serial"
    )
    result = rule.evaluate(session, [ev1, ev2])
    assert result.triggered is False

def test_evaluate_deduplicates(rule, session):
    headers = {"Server": "nginx"}
    ev1 = create_evidence(headers, host="test.com")
    ev2 = create_evidence(headers, host="test.com")
    result = rule.evaluate(session, [ev1, ev2])
    
    assert result.triggered is True
    assert len(result.findings) == 1
