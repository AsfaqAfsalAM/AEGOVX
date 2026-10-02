"""
services/threat_intelligence.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Multi-Source Threat Intelligence Aggregation and Correlation Engine.
Correlates independent reputation sources (VirusTotal, Google Safe Browsing,
and abuse.ch URLhaus) with zero fabricated results.
Deduplicates findings, calculates feed consensus, and produces structured evidence chains.
"""

from __future__ import annotations

import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from services.evidence import FindingSeverity, TestStatus, create_evidence
from services.google_web_risk import check_google_safe_browsing
from services.url_validator import NormalizedURL
from services.urlhaus import check_urlhaus
from services.virustotal import check_virustotal


def aggregate_threat_intelligence(url_info: NormalizedURL) -> dict[str, Any]:
    """
    Query all threat intelligence providers concurrently, correlate independent findings,
    and output evidence-first telemetry.
    """
    target_url = url_info.normalized_url
    hostname = url_info.hostname

    sources: list[dict[str, Any]] = []
    all_evidence: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []

    # Run providers in parallel (VT, Google, URLhaus)
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_vt = executor.submit(check_virustotal, target_url)
        future_gsb = executor.submit(check_google_safe_browsing, target_url)
        future_uh = executor.submit(check_urlhaus, target_url, hostname)

        try:
            vt_result = future_vt.result(timeout=7.0)
        except Exception as e:
            vt_result = {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": target_url,
                "status": "NOT_TESTABLE",
                "configured": False,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "detections": 0,
                "total_engines": 0,
                "confidence": "LOW",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "summary": "Check unavailable.",
                "details": str(e),
                "evidence_records": [],
            }

        try:
            gsb_result = future_gsb.result(timeout=7.0)
        except Exception as e:
            gsb_result = {
                "name": "Google Safe Browsing",
                "provider": "Google Safe Browsing v4",
                "query": target_url,
                "status": "NOT_TESTABLE",
                "configured": False,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "threat_types": [],
                "confidence": "LOW",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "summary": "Check unavailable.",
                "details": str(e),
                "evidence_records": [],
            }

        try:
            uh_result = future_uh.result(timeout=7.0)
        except Exception as e:
            uh_result = {
                "name": "URLhaus (abuse.ch)",
                "provider": "URLhaus (abuse.ch)",
                "query": target_url,
                "status": "NOT_TESTABLE",
                "configured": True,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "confidence": "LOW",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "summary": "Check unavailable.",
                "details": str(e),
                "evidence_records": [],
            }

    sources.extend([vt_result, gsb_result, uh_result])
    for s in sources:
        all_evidence.extend(s.get("evidence_records", []))

    # Evaluate correlation across independent sources
    checked_sources = [s for s in sources if s.get("status") == "CHECKED"]
    detected_sources: list[dict[str, Any]] = [s for s in sources if s.get("detected")]
    unconfigured_sources = [s for s in sources if s.get("status") == "NOT_CONFIGURED"]
    untestable_sources = [s for s in sources if s.get("status") == "NOT_TESTABLE"]

    has_confirmed_threat = False
    is_conflicting = False
    reputation_score = 0  # 0 to 50 max

    # Correlation Analysis
    if len(detected_sources) >= 2:
        # Multi-source confirmation!
        has_confirmed_threat = True
        reputation_score = 50
        prov_names = [s.get("name") for s in detected_sources]
        indicators.append({
            "id": "ti_multi_source_threat",
            "title": f"Confirmed Threat: Verified by {len(detected_sources)} independent intelligence feeds ({', '.join(prov_names)})",
            "severity": "Critical",
            "points": 50,
            "description": (
                f"Multiple independent threat reputation authorities ({', '.join(prov_names)}) "
                "concur that this URL hosts active malware, phishing, or malicious infrastructure. "
                "Multi-engine agreement provides maximum confidence of active hostility."
            ),
            "recommendation": "Block or avoid navigating to this destination immediately.",
            "sources": prov_names,
        })
    elif len(detected_sources) == 1:
        # Single source detection -> Check detection strength
        det = detected_sources[0]
        prov_name = det.get("name")
        if prov_name == "VirusTotal":
            vt_detections = det.get("detections", 0)
            if vt_detections >= 3:
                has_confirmed_threat = True
                reputation_score = 50
                indicators.append({
                    "id": "ti_virustotal_threat",
                    "title": f"VirusTotal Threat Consensus: {vt_detections} antivirus engines flagged this target",
                    "severity": "Critical",
                    "points": 50,
                    "description": f"VirusTotal reported {vt_detections} independent antivirus engines classifying this URL as malicious.",
                    "recommendation": "Block access to this destination.",
                    "sources": ["VirusTotal"],
                })
            elif vt_detections in (1, 2):
                # Conflicting / low-consensus detection
                is_conflicting = True
                reputation_score = 25
                indicators.append({
                    "id": "ti_conflicting_reputation",
                    "title": f"Conflicting Reputation Evidence: {vt_detections} engine(s) flagged while other feeds are clean",
                    "severity": "Medium",
                    "points": 25,
                    "description": (
                        f"A minimal number of scanning engines ({vt_detections}) flagged this target on VirusTotal, "
                        "while other independent intelligence feeds reported no detections. "
                        "This indicates either a newly emerging threat or an isolated false positive."
                    ),
                    "recommendation": "Exercise caution; verify destination legitimacy before entering sensitive credentials.",
                    "sources": ["VirusTotal"],
                })
        else:
            # GSB or URLhaus listing
            has_confirmed_threat = True
            reputation_score = 50
            indicators.append({
                "id": f"ti_{prov_name.lower().replace(' ', '_')}_threat",
                "title": f"Threat Confirmed by {prov_name}",
                "severity": "Critical",
                "points": 50,
                "description": f"Verified listing on {prov_name}: {det.get('summary')}.",
                "recommendation": "Remediate threat or avoid navigating to this destination.",
                "sources": [prov_name],
            })
    elif any(s.get("status") == "suspicious" for s in sources):
        reputation_score = 15
        indicators.append({
            "id": "ti_suspicious_flags",
            "title": "Minor Suspicious Indicators Noted in Threat Feeds",
            "severity": "Low",
            "points": 15,
            "description": "Reputation scanners noted non-standard behavioral characteristics without classifying the URL as outright malware.",
            "recommendation": "Standard caution recommended.",
            "sources": ["Threat Feeds"],
        })

    # Summary Generation
    if has_confirmed_threat:
        status = "threat_detected"
        summary = f"Confirmed malicious threat detected across active feeds."
    elif is_conflicting:
        status = "conflicting"
        summary = f"Conflicting / limited reputation signals detected across feeds."
    elif len(checked_sources) > 0:
        status = "clean"
        summary = f"No malicious detections reported across {len(checked_sources)} checked threat intelligence provider(s)."
    elif len(unconfigured_sources) == len(sources):
        status = "unconfigured"
        summary = "No threat intelligence API keys currently configured in server environment."
    else:
        status = "unavailable"
        summary = "Threat intelligence queries could not be completed (network timeout or upstream error)."

    return {
        "status": status,
        "has_confirmed_threat": has_confirmed_threat,
        "is_conflicting": is_conflicting,
        "score": reputation_score,
        "max_score": 50,
        "sources": sources,
        "checked_count": len(checked_sources),
        "unconfigured_count": len(unconfigured_sources),
        "untestable_count": len(untestable_sources),
        "indicators": indicators,
        "evidence_records": all_evidence,
        "summary": summary,
    }
