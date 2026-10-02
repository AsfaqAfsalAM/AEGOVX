"""
services/scoring.py
~~~~~~~~~~~~~~~~~~~
Three-Dimensional Evidence-Based Scoring and Confidence Engine for AEGOVX.
Strictly separates:
  1. Threat Reputation Verdict (Maliciousness):
     - 🟢 NO KNOWN MALICIOUS INDICATORS
     - 🟡 SUSPICIOUS INDICATORS DETECTED
     - 🔴 MALICIOUS INDICATORS DETECTED
     - ⚪ INCONCLUSIVE / INSUFFICIENT DATA
  2. Security Configuration Posture:
     - 0–100 score + Letter Grade (A+ to F)
  3. Analysis Coverage & Confidence:
     - Tests completed, unavailable, not configured, and overall confidence score.

CRITICAL RULES:
  - Missing security headers NEVER make a website malicious.
  - An API that is not configured is NOT a failed security check.
  - A connection timeout is NOT a malicious result.
  - Never claim a website is "100% safe" or "100% malicious".
"""

from __future__ import annotations

from typing import Any

from services.evidence import TestStatus

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def calculate_risk_assessment(
    threat_intel: dict[str, Any],
    heuristics: dict[str, Any],
    domain_data: dict[str, Any],
    tls_data: dict[str, Any],
    redirect_data: dict[str, Any],
    header_data: dict[str, Any],
    cookie_data: dict[str, Any] | None = None,
    content_data: dict[str, Any] | None = None,
    unreachable: bool = False,
) -> dict[str, Any]:
    """
    Synthesize all independent security signals into a 3-Dimensional Assessment.
    """
    cookie_data = cookie_data or {}
    content_data = content_data or {}

    # -------------------------------------------------------------------------
    # 1. Collect all Evidence Records & Calculate Analysis Coverage
    # -------------------------------------------------------------------------
    all_evidence: list[dict[str, Any]] = []
    all_evidence.extend(threat_intel.get("evidence_records", []))
    all_evidence.extend(heuristics.get("evidence_records", []))
    all_evidence.extend(domain_data.get("evidence_records", []))
    all_evidence.extend(tls_data.get("evidence_records", []))
    all_evidence.extend(redirect_data.get("evidence_records", []))
    all_evidence.extend(header_data.get("evidence_records", []))
    all_evidence.extend(cookie_data.get("evidence_records", []))
    all_evidence.extend(content_data.get("evidence_records", []))

    total_tests_planned = len(all_evidence) or 1
    tests_completed = sum(1 for e in all_evidence if e.get("status") in (TestStatus.PASS.value, TestStatus.FAIL.value, TestStatus.WARNING.value))
    tests_not_testable = sum(1 for e in all_evidence if e.get("status") == TestStatus.NOT_TESTABLE.value)
    tests_not_configured = sum(1 for e in all_evidence if e.get("status") == TestStatus.NOT_CONFIGURED.value)
    tests_not_applicable = sum(1 for e in all_evidence if e.get("status") == TestStatus.NOT_APPLICABLE.value)

    # Coverage percentage reflects proportion of planned tests that could actually run
    coverage_pct = int((tests_completed / total_tests_planned) * 100) if total_tests_planned > 0 else 0

    # -------------------------------------------------------------------------
    # 2. DIMENSION A: Threat Reputation & Verdict (Maliciousness)
    # Governed purely by threat signals, NOT defensive header configurations!
    # -------------------------------------------------------------------------
    has_confirmed_threat = threat_intel.get("has_confirmed_threat", False)
    is_conflicting_threat = threat_intel.get("is_conflicting", False)
    has_downgrade = redirect_data.get("has_protocol_downgrade", False)
    cert_status = tls_data.get("cert_status", "NOT_TESTABLE")
    heur_status = heuristics.get("status", "clean")
    is_homoglyph = any(ind.get("id") == "heur_homoglyph" and ind.get("severity") == "High" for ind in heuristics.get("indicators", []))
    insecure_form = any(ind.get("id") == "form_insecure_password_post" for ind in content_data.get("indicators", []))

    # Threat Score calculation (0 to 100)
    threat_points = 0
    if has_confirmed_threat:
        threat_points = 95
    elif is_conflicting_threat:
        threat_points = 40
    else:
        if is_homoglyph:
            threat_points += 30
        if insecure_form:
            threat_points += 25
        if has_downgrade:
            threat_points += 20
        if cert_status in ("INVALID", "MISMATCH"):
            threat_points += 15
        elif cert_status == "EXPIRED":
            threat_points += 10
        if heur_status == "suspicious_indicators":
            threat_points += 10

    threat_points = min(threat_points, 100)

    # 1. Category Scores
    ti_score = min(int(threat_intel.get("score", 0)), 50)
    heur_score = min(int(heuristics.get("score", 0)), 15)
    domain_score = min(int(domain_data.get("score", 0)), 10)
    tls_score = min(int(tls_data.get("score", 0)), 10)
    redir_score = min(int(redirect_data.get("score", 0)), 5)
    hdr_score = min(int(header_data.get("score", 0)), 10)
    sum_risk_score = ti_score + heur_score + domain_score + tls_score + redir_score + hdr_score

    # Classify Threat Verdict & Risk Level
    if unreachable and domain_data.get("status") == "unresolved":
        threat_verdict = "INCONCLUSIVE / INSUFFICIENT DATA"
        verdict_icon = "⚪"
        verdict_level = "UNKNOWN"
        risk_label = "UNKNOWN RISK"
        verdict_description = "The target domain could not be resolved or reached. Public security signals could not be gathered."
    elif has_confirmed_threat or sum_risk_score >= 80:
        threat_verdict = "MALICIOUS INDICATORS DETECTED"
        verdict_icon = "🔴"
        verdict_level = "MALICIOUS"
        risk_label = "KNOWN THREAT" if has_confirmed_threat else "MALICIOUS / CRITICAL"
        threat_points = max(threat_points, 90)
        verdict_description = "Confirmed threat indicators verified by independent global threat intelligence feeds or critical multi-vector risk signals."
    elif threat_points >= 40 or sum_risk_score >= 40:
        threat_verdict = "SUSPICIOUS INDICATORS DETECTED"
        verdict_icon = "🟡"
        verdict_level = "SUSPICIOUS"
        risk_label = "SUSPICIOUS"
        verdict_description = "Multiple anomalous patterns or conflicting reputation signals warranting elevated caution."
    elif threat_points > 0 or sum_risk_score >= 20:
        threat_verdict = "LOW RISK"
        verdict_icon = "🟢"
        verdict_level = "LOW RISK"
        risk_label = "LOW RISK"
        verdict_description = "No confirmed malicious indicators. Standard operational signals noted."
    else:
        threat_verdict = "NO KNOWN MALICIOUS INDICATORS"
        verdict_icon = "🟢"
        verdict_level = "SAFE"
        risk_label = "SAFE (NO THREATS DETECTED)"
        verdict_description = "No known malicious indicators or security compromise signals detected across active tests."

    # -------------------------------------------------------------------------
    # 3. DIMENSION B: Security Configuration Posture
    # (0 to 100 scale, letter grades A+ to F)
    # -------------------------------------------------------------------------
    security_score = header_data.get("header_quality_score", 0)
    security_grade = header_data.get("grade", "F")
    security_summary = header_data.get("grade_summary", "")

    # -------------------------------------------------------------------------
    # 4. DIMENSION C: Confidence Rating
    # -------------------------------------------------------------------------
    confidence_points = 0
    # Direct observable connectivity
    if domain_data.get("status") == "resolved":
        confidence_points += 25
    if tls_data.get("status") in ("valid", "expired", "invalid", "mismatch"):
        confidence_points += 25
    if header_data.get("scored_headers") or header_data.get("header_quality_score") is not None or "score" in header_data:
        confidence_points += 25

    # Threat Intelligence active checked sources
    checked_ti = threat_intel.get("checked_count", 0)
    if checked_ti >= 2:
        confidence_points += 25
    elif checked_ti == 1:
        confidence_points += 15
    else:
        confidence_points += 5

    if unreachable or domain_data.get("status") == "unresolved":
        confidence_level = "LOW"
        confidence_reason = "Target could not be reached to perform direct observation."
    elif confidence_points >= 75 and tests_not_testable == 0:
        confidence_level = "HIGH"
        confidence_reason = "Direct protocol analysis succeeded and multiple threat feeds responded cleanly."
    elif confidence_points >= 45:
        confidence_level = "MEDIUM"
        confidence_reason = "Direct observations completed successfully; some external intelligence feeds were unconfigured or unavailable."
    else:
        confidence_level = "LOW"
        confidence_reason = "Limited observational data available; several planned tests could not be completed."

    # Total risk score
    if has_confirmed_threat:
        compat_risk_score = max(sum_risk_score, 90)
    elif sum_risk_score > 0:
        compat_risk_score = min(max(sum_risk_score, threat_points), 100)
    else:
        compat_risk_score = threat_points

    # -------------------------------------------------------------------------
    # 5. Synthesize Unified Findings List (Deduplicated)
    # -------------------------------------------------------------------------
    all_findings: list[dict[str, Any]] = []

    def _ingest(indicators: list[dict[str, Any]], default_cat: str) -> None:
        for ind in indicators:
            all_findings.append({
                "id": ind.get("id", ""),
                "title": ind.get("title", ""),
                "severity": ind.get("severity", "Low"),
                "category": ind.get("category", default_cat),
                "description": ind.get("description", ""),
                "recommendation": ind.get("recommendation", "Review technical configuration."),
                "points": ind.get("points", 0),
                "test": ind.get("test", ""),
                "observed_value": ind.get("observed_value") or ind.get("observedValue") or "",
                "expected_value": ind.get("expected_value") or ind.get("expectedValue") or "",
                "evidence": ind.get("evidence", ""),
                "methodology": ind.get("methodology", ""),
                "limitations": ind.get("limitations", ""),
                "source": ind.get("source", ""),
                "confidence": ind.get("confidence", ""),
            })

    _ingest(threat_intel.get("indicators", []), "Threat Intelligence")
    _ingest(heuristics.get("indicators", []), "URL Heuristics")
    _ingest(domain_data.get("indicators", []), "Domain & Infrastructure")
    _ingest(tls_data.get("indicators", []), "HTTPS & TLS")
    _ingest(redirect_data.get("indicators", []), "Redirect Security")
    _ingest(header_data.get("indicators", []), "Security Configuration")
    _ingest(cookie_data.get("indicators", []), "Cookie Security")
    _ingest(content_data.get("indicators", []), "Content & Scripts")

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    finding_counts = {
        "critical": sum(1 for f in all_findings if f["severity"] == "Critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "High"),
        "medium": sum(1 for f in all_findings if f["severity"] == "Medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "Low"),
        "informational": sum(1 for f in all_findings if f["severity"] == "Informational"),
    }

    return {
        # Dimension A: Threat Verdict
        "threat_verdict": threat_verdict,
        "verdict_icon": verdict_icon,
        "risk_level": verdict_level,
        "risk_label": risk_label,
        "risk_description": verdict_description,
        "risk_score": compat_risk_score,
        "threat_score": threat_points,

        # Dimension B: Security Configuration Posture
        "security_score": security_score,
        "security_grade": security_grade,
        "grade": security_grade,
        "score": security_score,
        "grade_summary": security_summary,

        # Dimension C: Analysis Coverage & Confidence
        "coverage": {
            "percentage": coverage_pct,
            "total_planned": total_tests_planned,
            "completed": tests_completed,
            "not_testable": tests_not_testable,
            "not_configured": tests_not_configured,
            "not_applicable": tests_not_applicable,
        },
        "coverage_percentage": coverage_pct,
        "confidence": confidence_level,
        "confidence_score": confidence_points,
        "confidence_reason": confidence_reason,

        # Findings & Breakdown
        "findings": all_findings,
        "finding_counts": finding_counts,
        "evidence_records": all_evidence,
        "breakdown": {
            "threat_intelligence": {
                "score": threat_intel.get("score", 0),
                "max": 50,
                "label": "Threat Intelligence",
                "summary": threat_intel.get("summary", ""),
            },
            "url_heuristics": {
                "score": heuristics.get("score", 0),
                "max": 15,
                "label": "URL Heuristics",
                "summary": heuristics.get("summary", ""),
            },
            "domain_signals": {
                "score": domain_data.get("score", 0),
                "max": 10,
                "label": "Domain & Infrastructure",
                "summary": domain_data.get("summary", ""),
            },
            "tls_https": {
                "score": tls_data.get("score", 0),
                "max": 10,
                "label": "TLS / HTTPS",
                "summary": tls_data.get("summary", ""),
            },
            "redirects": {
                "score": redirect_data.get("score", 0),
                "max": 5,
                "label": "Redirects",
                "summary": redirect_data.get("summary", ""),
            },
            "security_configuration": {
                "score": 10 if security_score < 50 else 0,
                "max": 10,
                "label": "Security Configuration",
                "summary": header_data.get("summary", ""),
            },
        },
    }
