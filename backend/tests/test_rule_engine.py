import pytest
from app.engines.rule_engine import RuleEngine


@pytest.fixture
def rule_engine():
    return RuleEngine()


def test_urgency_detection_english(rule_engine):
    text = "Dear user, action required immediately! Your account expires today."
    score, evidence, hits = rule_engine.analyze(text)
    assert score > 30
    assert hits["urgency"] > 0
    assert any(e.type == "urgency" for e in evidence)


def test_threat_detection_tamil(rule_engine):
    text = "உங்கள் கணக்கு முடக்கப்படும். உடனடியாக அணுகவும்."
    score, evidence, hits = rule_engine.analyze(text)
    assert score > 40
    assert hits["threats"] > 0


def test_credential_harvesting_hindi(rule_engine):
    text = "कृपया अपना ओटीपी शेयर करें और केवाईसी अपडेट करें।"
    score, evidence, hits = rule_engine.analyze(text)
    assert score > 50
    assert hits["credential_harvesting"] > 0


def test_transliterated_mixed_language(rule_engine):
    text = "Aapka account band ho jayega. Udane OTP share karo."
    score, evidence, hits = rule_engine.analyze(text)
    assert score >= 70
    assert any(e.type == "compound_tactic" for e in evidence)


def test_clean_message_low_score(rule_engine):
    text = "Hi Rahul, let us meet for lunch at 1 PM today."
    score, evidence, hits = rule_engine.analyze(text)
    assert score == 0.0
    assert len(evidence) == 0
