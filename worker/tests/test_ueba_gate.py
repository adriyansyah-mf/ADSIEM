import pytest

def _should_ai_investigate(risk: float, severity: str) -> bool:
    if severity == "critical":
        return True
    if risk >= 60:
        return True
    if severity == "high" and risk >= 40:
        return True
    return False

def test_critical_always_passes():
    assert _should_ai_investigate(0.0, "critical") is True

def test_high_risk_passes():
    assert _should_ai_investigate(65.0, "medium") is True

def test_high_severity_medium_risk_passes():
    assert _should_ai_investigate(45.0, "high") is True

def test_low_risk_low_severity_blocked():
    assert _should_ai_investigate(30.0, "low")    is False
    assert _should_ai_investigate(30.0, "medium") is False
    assert _should_ai_investigate(39.0, "high")   is False
