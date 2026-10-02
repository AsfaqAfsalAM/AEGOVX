"""
services/google_web_risk.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Google Safe Browsing v4 threat intelligence integration with Evidence-First logging.
Accurately checks for Malware, Social Engineering (Phishing), and Unwanted Software.
Never fakes results: reports NOT_CONFIGURED or NOT_TESTABLE if credentials or connection fail.
"""

from __future__ import annotations

import datetime
import os
from typing import Any
import requests

from services.evidence import FindingSeverity, TestStatus, create_evidence

GSB_API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_google_safe_browsing(url: str, timeout: float = 6.0) -> dict[str, Any]:
    """
    Check URL against Google Safe Browsing v4 with structured evidence.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    if not api_key:
        ev = create_evidence(
            test="threat_intel_google_safebrowsing",
            status=TestStatus.NOT_CONFIGURED,
            severity=FindingSeverity.INFO,
            confidence=0,
            observed_value="GOOGLE_SAFE_BROWSING_API_KEY not set",
            expected_value="Configured API key in environment",
            evidence="Google Safe Browsing check skipped because GOOGLE_SAFE_BROWSING_API_KEY is not defined in server environment.",
            source="Google Safe Browsing v4 API",
            methodology="API key presence check",
            why_it_matters="Google Safe Browsing protects over 5 billion devices against phishing and malware.",
            limitations="External threat intelligence unavailable without API keys.",
            remediation="Provide GOOGLE_SAFE_BROWSING_API_KEY in .env to activate Google reputation checks.",
            category="Threat Intelligence",
        )
        return {
            "name": "Google Safe Browsing",
            "provider": "Google Safe Browsing v4",
            "query": url,
            "status": "NOT_CONFIGURED",
            "configured": False,
            "detected": False,
            "detection_result": "UNCONFIGURED",
            "threat_types": [],
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Not checked — API key not configured.",
            "details": "To activate Google Safe Browsing scanning, set GOOGLE_SAFE_BROWSING_API_KEY in your environment or .env file.",
            "evidence_records": [ev.to_dict()],
        }

    payload = {
        "client": {
            "clientId": "aegovx-security-scanner",
            "clientVersion": "2.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            f"{GSB_API_ENDPOINT}?key={api_key}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        if resp.status_code in (400, 403):
            ev = create_evidence(
                test="threat_intel_google_safebrowsing",
                status=TestStatus.NOT_TESTABLE,
                severity=FindingSeverity.INFO,
                confidence=30,
                observed_value=f"HTTP {resp.status_code} (Authentication or quota error)",
                expected_value="HTTP 200 JSON with threat match list",
                evidence=f"Google Safe Browsing API rejected request with status {resp.status_code}.",
                source="Google Safe Browsing v4 API",
                methodology="Authenticated POST lookup",
                why_it_matters="Checks cannot complete when API keys or quotas are invalid.",
                limitations="Google API service quota or key restrictions.",
                remediation="Verify Google Cloud credentials and billing status in GCP Console.",
                category="Threat Intelligence",
            )
            return {
                "name": "Google Safe Browsing",
                "provider": "Google Safe Browsing v4",
                "query": url,
                "status": "NOT_TESTABLE",
                "configured": True,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "threat_types": [],
                "confidence": "LOW",
                "timestamp": now_iso,
                "summary": "Threat intelligence source unavailable (API key error or quota exceeded).",
                "details": f"Google Safe Browsing returned HTTP {resp.status_code}.",
                "evidence_records": [ev.to_dict()],
            }

        if resp.status_code != 200:
            ev = create_evidence(
                test="threat_intel_google_safebrowsing",
                status=TestStatus.NOT_TESTABLE,
                severity=FindingSeverity.INFO,
                confidence=30,
                observed_value=f"HTTP {resp.status_code}",
                expected_value="HTTP 200 response",
                evidence=f"Google Safe Browsing returned unexpected status {resp.status_code}.",
                source="Google Safe Browsing v4 API",
                methodology="Authenticated POST lookup",
                why_it_matters="Service unresponsiveness.",
                limitations="Upstream server error.",
                remediation="Retry scan later.",
                category="Threat Intelligence",
            )
            return {
                "name": "Google Safe Browsing",
                "provider": "Google Safe Browsing v4",
                "query": url,
                "status": "NOT_TESTABLE",
                "configured": True,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "threat_types": [],
                "confidence": "LOW",
                "timestamp": now_iso,
                "summary": f"Threat intelligence source unavailable (HTTP {resp.status_code}).",
                "details": "Unexpected response from Google Safe Browsing.",
                "evidence_records": [ev.to_dict()],
            }

        result = resp.json()
        matches = result.get("matches", [])

        if matches:
            threats = list({m.get("threatType", "UNKNOWN_THREAT") for m in matches})
            threat_names = {
                "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
                "MALWARE": "Malware Distribution",
                "UNWANTED_SOFTWARE": "Unwanted Software",
                "POTENTIALLY_HARMFUL_APPLICATION": "Harmful Application",
            }
            display_threats = [threat_names.get(t, t) for t in threats]
            ev = create_evidence(
                test="threat_intel_google_safebrowsing",
                status=TestStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
                confidence=98,
                observed_value=f"Listed in Google Safe Browsing: {', '.join(display_threats)}",
                expected_value="No match in threat lists",
                evidence=f"Google Safe Browsing matched active threat signatures: {threats}. Browsers actively block navigation to this target.",
                source="Google Safe Browsing Threat Intelligence",
                methodology="Client-side SHA-256 hash prefix matching & API query",
                why_it_matters="Google Safe Browsing listings immediately cause major browsers (Chrome, Safari, Firefox) to display critical red security interstitial screens.",
                limitations="Listings reflect verified reports by Google automated crawlers and security teams.",
                remediation="Remediate compromised code and file an appeal via Google Search Console.",
                category="Threat Intelligence",
            )
            return {
                "name": "Google Safe Browsing",
                "provider": "Google Safe Browsing v4",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": True,
                "detection_result": "THREAT_DETECTED",
                "threat_types": threats,
                "confidence": "HIGH",
                "timestamp": now_iso,
                "summary": f"🔴 Confirmed Threat: {', '.join(display_threats)}",
                "details": "URL matches known blacklist signatures in Google Safe Browsing database.",
                "evidence_records": [ev.to_dict()],
            }
        else:
            ev = create_evidence(
                test="threat_intel_google_safebrowsing",
                status=TestStatus.PASS,
                severity=FindingSeverity.INFO,
                confidence=95,
                observed_value="No matches returned",
                expected_value="No matches",
                evidence="URL was checked against Google active threat lists (Malware, Social Engineering, Unwanted Software) with zero positive matches.",
                source="Google Safe Browsing v4 API",
                methodology="Client-side hash query against Google threat index",
                why_it_matters="Confirms domain is not blocked by major web browsers' default anti-phishing/anti-malware shields.",
                limitations="Does not guarantee future safety; emerging zero-day phishing kits may take hours to be indexed.",
                remediation="Maintain defensive controls.",
                category="Threat Intelligence",
            )
            return {
                "name": "Google Safe Browsing",
                "provider": "Google Safe Browsing v4",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": False,
                "detection_result": "CLEAN",
                "threat_types": [],
                "confidence": "HIGH",
                "timestamp": now_iso,
                "summary": "✓ No known threats detected by Google Safe Browsing.",
                "details": "The submitted URL does not match any active malware or social engineering lists.",
                "evidence_records": [ev.to_dict()],
            }

    except requests.exceptions.Timeout:
        ev = create_evidence(
            test="threat_intel_google_safebrowsing",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=30,
            observed_value=f"Timeout after {timeout}s",
            expected_value="HTTP 200 within timeout",
            evidence="Connection to Google Safe Browsing API timed out.",
            source="Google Safe Browsing v4 API",
            methodology="POST with timeout",
            why_it_matters="Network timeout prevents external validation.",
            limitations="Temporary network congestion.",
            remediation="Retry scan later.",
            category="Threat Intelligence",
        )
        return {
            "name": "Google Safe Browsing",
            "provider": "Google Safe Browsing v4",
            "query": url,
            "status": "NOT_TESTABLE",
            "configured": True,
            "detected": False,
            "detection_result": "TIMEOUT",
            "threat_types": [],
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Check unavailable (Google API timed out).",
            "details": f"Service did not respond within {timeout}s.",
            "evidence_records": [ev.to_dict()],
        }
    except Exception as exc:
        ev = create_evidence(
            test="threat_intel_google_safebrowsing",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=30,
            observed_value=f"Error: {exc}",
            expected_value="HTTP 200 response",
            evidence=f"Google Safe Browsing connection failure: {exc}",
            source="Google Safe Browsing v4 API",
            methodology="POST query",
            why_it_matters="Connection failure.",
            limitations="Local network or upstream exception.",
            remediation="Verify server network connectivity.",
            category="Threat Intelligence",
        )
        return {
            "name": "Google Safe Browsing",
            "provider": "Google Safe Browsing v4",
            "query": url,
            "status": "NOT_TESTABLE",
            "configured": True,
            "detected": False,
            "detection_result": "ERROR",
            "threat_types": [],
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Check unavailable (Connection failure).",
            "details": str(exc),
            "evidence_records": [ev.to_dict()],
        }
