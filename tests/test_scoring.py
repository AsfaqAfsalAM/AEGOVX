"""
tests/test_scoring.py
~~~~~~~~~~~~~~~~~~~~~
Tests for risk scoring, confidence, and classification models.
"""

from services.scoring import calculate_risk_assessment


def test_clean_safe_scoring():
    ti = {"score": 0, "has_confirmed_threat": False, "sources": [{"configured": True}]}
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "is_valid": True, "indicators": []}
    redir = {"score": 0, "indicators": []}
    headers = {"score": 0, "scored_headers": [{"name": "CSP", "status": "pass"}]}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] == 0
    assert res["confidence"] == "HIGH"
    assert len(res["findings"]) == 0


def test_confirmed_threat_override():
    # Even if other scores are 0, confirmed threat must force MALICIOUS and score >= 90
    ti = {
        "score": 50,
        "has_confirmed_threat": True,
        "sources": [{"configured": True}],
        "indicators": [{
            "id": "ti_threat",
            "title": "Malware detected",
            "severity": "Critical",
            "category": "Threat Intelligence",
            "points": 50,
        }],
    }
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "is_valid": True, "indicators": []}
    redir = {"score": 0, "indicators": []}
    headers = {"score": 0, "scored_headers": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] == "MALICIOUS"
    assert res["risk_label"] == "KNOWN THREAT"
    assert res["risk_score"] >= 90
    assert res["finding_counts"]["critical"] >= 1


def test_unknown_state_when_unreachable():
    ti = {"score": 0, "has_confirmed_threat": False, "sources": []}
    heur = {"score": 0, "indicators": []}
    domain = {"score": 10, "status": "unresolved", "indicators": []}
    tls = {"score": 0, "status": "error", "indicators": []}
    redir = {"score": 0, "indicators": []}
    headers = {"score": 3, "scored_headers": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers, unreachable=True)
    assert res["risk_level"] == "UNKNOWN"
    assert res["confidence"] == "LOW"


def test_breakdown_category_bounds():
    ti = {"score": 50, "has_confirmed_threat": False, "sources": []}
    heur = {"score": 15, "indicators": []}
    domain = {"score": 10, "status": "resolved", "indicators": []}
    tls = {"score": 10, "status": "expired", "indicators": []}
    redir = {"score": 5, "indicators": []}
    headers = {"score": 10, "scored_headers": [{"status": "fail"}]}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_score"] == 100
    assert res["risk_level"] == "MALICIOUS"
    bd = res["breakdown"]
    assert bd["threat_intelligence"]["max"] == 50
    assert bd["url_heuristics"]["max"] == 15
    assert bd["domain_signals"]["max"] == 10
    assert bd["tls_https"]["max"] == 10
    assert bd["redirects"]["max"] == 5
    assert bd["security_configuration"]["max"] == 10
    assert res["security_score"] == 0
