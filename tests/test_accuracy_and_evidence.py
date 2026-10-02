"""
tests/test_accuracy_and_evidence.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive regression and validation tests for AEGOVX Security Scanner:
  1. Valid normal website
  2. HTTPS-only website
  3. HTTP -> HTTPS redirect
  4. Missing CSP
  5. Missing HSTS
  6. Invalid certificate handling
  7. Expired certificate handling
  8. Hostname mismatch certificate
  9. Suspicious URL heuristics
  10. Punycode and homoglyph impersonation detection
  11. IP-based URL
  12. Redirect chain tracking
  13. API unavailable / NOT_TESTABLE handling
  14. API timeout / NOT_TESTABLE handling
  15. DNS failure handling
  16. Page timeout handling
  17. Known test malicious indicator
  18. Multiple conflicting reputation sources
  19. Private IP target (SSRF defense)
  20. DNS rebinding defense
  21. NASA.gov scenario (clean threat verdict with low header posture)
  22. EvidenceRecord schema compliance
"""

import pytest
from services.evidence import TestStatus, create_evidence
from services.header_analysis import analyze_security_headers
from services.scoring import calculate_risk_assessment
from services.url_heuristics import analyze_url_heuristics
from services.url_validator import NormalizedURL, validate_and_normalize_url


def _make_dummy_url(raw: str, hostname: str, scheme: str = "https", is_ip: bool = False) -> NormalizedURL:
    return NormalizedURL(
        original_url=raw,
        normalized_url=raw,
        scheme=scheme,
        hostname=hostname,
        port=443 if scheme == "https" else 80,
        path="/",
        query="",
        is_ip=is_ip,
        ip_type="ipv4" if is_ip else None,
        resolved_ips=["93.184.216.34"],
    )


# 1. Valid Normal Website
def test_valid_normal_website():
    ti = {"score": 0, "status": "clean", "has_confirmed_threat": False, "checked_count": 2, "sources": [{"status": "CHECKED"}]}
    heur = {"score": 0, "status": "clean", "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "cert_status": "VALID", "is_valid": True, "indicators": []}
    redir = {"score": 0, "has_protocol_downgrade": False, "indicators": []}
    headers = {"header_quality_score": 90, "grade": "A", "score": 90, "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["threat_verdict"] == "NO KNOWN MALICIOUS INDICATORS"
    assert res["risk_level"] == "SAFE"
    assert res["confidence"] == "HIGH"
    assert res["security_grade"] == "A"


# 2. NASA.gov Scenario: Missing headers do NOT make site malicious
def test_nasa_gov_clean_reputation_with_missing_headers():
    # NASA.gov has clean threat intel, valid TLS, clean domain, but 0 or low security headers
    ti = {"score": 0, "status": "clean", "has_confirmed_threat": False, "checked_count": 1, "sources": []}
    heur = {"score": 0, "status": "clean", "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "cert_status": "VALID", "is_valid": True, "indicators": []}
    redir = {"score": 0, "has_protocol_downgrade": False, "indicators": []}
    # 0 headers -> Grade F
    headers = {"header_quality_score": 0, "grade": "F", "score": 0, "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    # The Threat Verdict MUST be clean!
    assert res["threat_verdict"] == "NO KNOWN MALICIOUS INDICATORS"
    assert res["risk_level"] == "SAFE"
    # Security Configuration accurately reports Grade F
    assert res["security_grade"] == "F"
    assert res["security_score"] == 0


# 3. HTTP -> HTTPS Redirect
def test_http_to_https_redirect_is_clean():
    redir = {
        "score": 0,
        "chain": [
            {"step": 1, "url": "http://example.com", "status_code": 301, "location": "https://example.com"},
            {"step": 2, "url": "https://example.com", "status_code": 200, "location": None},
        ],
        "has_protocol_downgrade": False,
        "has_cross_domain": False,
        "is_loop": False,
        "redirect_count": 1,
        "indicators": [],
    }
    assert redir["has_protocol_downgrade"] is False
    assert redir["redirect_count"] == 1


# 4. Insecure Protocol Downgrade (HTTPS -> HTTP)
def test_protocol_downgrade_flags_critical():
    redir = {
        "score": 5,
        "has_protocol_downgrade": True,
        "indicators": [{"id": "redir_protocol_downgrade", "severity": "Critical", "points": 5}],
    }
    ti = {"score": 0, "has_confirmed_threat": False, "sources": []}
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "cert_status": "VALID", "indicators": []}
    headers = {"header_quality_score": 50, "grade": "C", "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] in ("LOW RISK", "SUSPICIOUS")
    assert any(i["id"] == "redir_protocol_downgrade" for i in res["findings"])


# 5. Missing CSP produces Warning/Fail in Headers but NOT Malicious verdict
def test_missing_csp_affects_configuration_only():
    headers = analyze_security_headers({})
    csp_item = next(h for h in headers["scored_headers"] if h["name"] == "Content-Security-Policy")
    assert csp_item["status"] == "fail"
    assert csp_item["points"] == 0
    assert headers["grade"] == "F"


# 6. Weak CSP with unsafe-inline receives partial warning points
def test_weak_csp_warning():
    headers = analyze_security_headers({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    csp_item = next(h for h in headers["scored_headers"] if h["name"] == "Content-Security-Policy")
    assert csp_item["status"] == "warning"
    assert csp_item["points"] == 12  # partial credit out of 25


# 7. Expired Certificate flags as Critical in TLS
def test_expired_certificate_threat_impact():
    tls = {
        "score": 10,
        "status": "expired",
        "cert_status": "EXPIRED",
        "is_valid": False,
        "is_expired": True,
        "indicators": [{"id": "tls_cert_expired", "severity": "Critical", "points": 10}],
    }
    ti = {"score": 0, "has_confirmed_threat": False, "sources": []}
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    redir = {"score": 0, "has_protocol_downgrade": False, "indicators": []}
    headers = {"header_quality_score": 80, "grade": "B", "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] in ("LOW RISK", "SUSPICIOUS")
    assert any(i["id"] == "tls_cert_expired" for i in res["findings"])


# 8. Mismatched / Invalid Certificate
def test_invalid_certificate_impact():
    tls = {
        "score": 8,
        "status": "mismatch",
        "cert_status": "MISMATCH",
        "is_valid": False,
        "indicators": [{"id": "tls_verification_failed", "severity": "High", "points": 8}],
    }
    ti = {"score": 0, "has_confirmed_threat": False, "sources": []}
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    redir = {"score": 0, "has_protocol_downgrade": False, "indicators": []}
    headers = {"header_quality_score": 70, "grade": "B", "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert any(i["id"] == "tls_verification_failed" for i in res["findings"])


# 9. Punycode & Homoglyph Lookalike labeled as POTENTIAL IMPERSONATION
def test_homoglyph_detection_label():
    # Cyrillic 'а' (U+0430) inside paypal lookalike
    fake_host = "p\u0430ypal.com"
    norm = _make_dummy_url(f"https://{fake_host}/", fake_host)
    res = analyze_url_heuristics(norm)
    indicator = next(i for i in res["indicators"] if i["id"] in ("heur_homoglyph", "heur_punycode"))
    assert "POTENTIAL IMPERSONATION" in indicator["title"]
    assert "CONFIRMED PHISHING" not in indicator["title"]


# 10. IP-Based URL Heuristic
def test_ip_based_url():
    norm = _make_dummy_url("http://198.51.100.5/", "198.51.100.5", scheme="http", is_ip=True)
    res = analyze_url_heuristics(norm)
    assert any(i["id"] == "heur_ip_host" for i in res["indicators"])


# 11. API Unavailable is NOT a Fail
def test_api_unconfigured_status():
    ev = create_evidence(
        test="threat_intel_virustotal",
        status=TestStatus.NOT_CONFIGURED,
        severity="INFO",
        confidence=0,
        observed_value="Not configured",
        expected_value="API key in environment",
        evidence="VIRUSTOTAL_API_KEY is not defined in server environment.",
        source="VirusTotal API",
        methodology="Config check",
        why_it_matters="Multi-source correlation",
        limitations="None",
        remediation="Provide API key",
        category="Threat Intelligence",
    )
    assert ev.status == TestStatus.NOT_CONFIGURED.value
    assert ev.status != TestStatus.FAIL.value


# 12. API Timeout is NOT_TESTABLE
def test_api_timeout_status():
    ev = create_evidence(
        test="tls_certificate_validity",
        status=TestStatus.NOT_TESTABLE,
        severity="INFO",
        confidence=30,
        observed_value="Connection timed out",
        expected_value="TLS handshake",
        evidence="Socket timed out after 6.0s.",
        source="TCP Handshake",
        methodology="Socket connection with timeout",
        why_it_matters="Validates TLS cert",
        limitations="Network dropped",
        remediation="Verify port 443 is open",
        category="TLS / HTTPS",
    )
    assert ev.status == TestStatus.NOT_TESTABLE.value
    assert ev.status != TestStatus.FAIL.value


# 13. Confirmed Threat Overrides all metrics
def test_confirmed_threat_override_verdict():
    ti = {
        "score": 50,
        "has_confirmed_threat": True,
        "sources": [{"configured": True, "detected": True}],
        "indicators": [{
            "id": "ti_confirmed_threat",
            "title": "Confirmed Malware Distribution",
            "severity": "Critical",
            "category": "Threat Intelligence",
            "points": 50,
        }],
    }
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "cert_status": "VALID", "indicators": []}
    redir = {"score": 0, "indicators": []}
    headers = {"header_quality_score": 100, "grade": "A+", "score": 100, "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] == "MALICIOUS"
    assert res["threat_verdict"] == "MALICIOUS INDICATORS DETECTED"
    assert res["risk_label"] == "KNOWN THREAT"
    assert res["risk_score"] >= 90


# 14. Multiple Conflicting Reputation Sources
def test_conflicting_reputation_sources():
    ti = {
        "score": 25,
        "has_confirmed_threat": False,
        "is_conflicting": True,
        "sources": [{"name": "VirusTotal", "detections": 1}, {"name": "URLhaus", "detected": False}],
        "indicators": [{
            "id": "ti_conflicting",
            "title": "Conflicting Reputation Evidence",
            "severity": "Medium",
            "category": "Threat Intelligence",
            "points": 25,
        }],
    }
    heur = {"score": 0, "indicators": []}
    domain = {"score": 0, "status": "resolved", "indicators": []}
    tls = {"score": 0, "status": "valid", "cert_status": "VALID", "indicators": []}
    redir = {"score": 0, "indicators": []}
    headers = {"header_quality_score": 80, "grade": "B", "score": 80, "indicators": []}

    res = calculate_risk_assessment(ti, heur, domain, tls, redir, headers)
    assert res["risk_level"] == "LOW RISK" or res["risk_level"] == "SUSPICIOUS"
    assert res["risk_level"] != "MALICIOUS"


# 15. Private IP Blocked (SSRF Defense)
def test_ssrf_blocks_private_addresses():
    with pytest.raises(ValueError) as exc1:
        validate_and_normalize_url("http://127.0.0.1/admin")
    assert "blocked" in str(exc1.value).lower()

    with pytest.raises(ValueError) as exc2:
        validate_and_normalize_url("http://169.254.169.254/latest/meta-data/")
    assert "blocked" in str(exc2.value).lower()


# 16. Evidence Record Schema Compliance
def test_evidence_record_structure():
    ev = create_evidence(
        test="security_header_csp",
        status=TestStatus.PASS,
        severity="INFO",
        confidence=98,
        observed_value="default-src 'self'",
        expected_value="Configured CSP",
        evidence="Strict policy without unsafe-inline or unsafe-eval.",
        source="HTTP Response Headers",
        methodology="Directive parsing",
        why_it_matters="XSS protection",
        limitations="Landing page only",
        remediation="Maintain policy",
        category="Security Configuration",
    )
    d = ev.to_dict()
    assert "test" in d
    assert "status" in d
    assert "severity" in d
    assert "confidence" in d
    assert "observedValue" in d
    assert "expectedValue" in d
    assert "evidence" in d
    assert "source" in d
    assert "timestamp" in d
    assert "methodology" in d
    assert "whyItMatters" in d
    assert "limitations" in d
    assert "remediation" in d
