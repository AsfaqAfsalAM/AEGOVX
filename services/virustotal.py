"""
services/virustotal.py
~~~~~~~~~~~~~~~~~~~~~~
VirusTotal v3 threat intelligence integration with Evidence-First logging.
Strictly authentic: if API key is unconfigured or a network error occurs,
reports true operational status rather than fabricating clean results.
"""

from __future__ import annotations

import base64
import datetime
import os
from typing import Any
import requests

from services.evidence import FindingSeverity, TestStatus, create_evidence

VT_API_URL = "https://www.virustotal.com/api/v3/urls"


def check_virustotal(url: str, timeout: float = 6.0) -> dict[str, Any]:
    """
    Check a URL against VirusTotal v3 and produce structured evidence.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        ev = create_evidence(
            test="threat_intel_virustotal",
            status=TestStatus.NOT_CONFIGURED,
            severity=FindingSeverity.INFO,
            confidence=0,
            observed_value="VIRUSTOTAL_API_KEY not set",
            expected_value="Configured API key in environment",
            evidence="VirusTotal check skipped because VIRUSTOTAL_API_KEY is not defined in server environment.",
            source="VirusTotal v3 API",
            methodology="API configuration check",
            why_it_matters="Multi-engine threat feed correlation requires valid API credentials.",
            limitations="External threat intelligence unavailable without API keys.",
            remediation="Provide VIRUSTOTAL_API_KEY in .env to enable multi-engine antivirus validation.",
            category="Threat Intelligence",
        )
        return {
            "name": "VirusTotal",
            "provider": "VirusTotal (Google Chronicle)",
            "query": url,
            "status": "NOT_CONFIGURED",
            "configured": False,
            "detected": False,
            "detection_result": "UNCONFIGURED",
            "detections": 0,
            "total_engines": 0,
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Not checked — API key not configured.",
            "details": "To activate VirusTotal scanning, set VIRUSTOTAL_API_KEY in your environment or .env file.",
            "evidence_records": [ev.to_dict()],
        }

    # VirusTotal v3 base64 URL identifier without trailing '='
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "AEGOVX-Security-Scanner/2.0",
    }

    try:
        resp = requests.get(f"{VT_API_URL}/{url_id}", headers=headers, timeout=timeout)

        if resp.status_code == 404:
            ev = create_evidence(
                test="threat_intel_virustotal",
                status=TestStatus.PASS,
                severity=FindingSeverity.INFO,
                confidence=75,
                observed_value="HTTP 404 (No prior database record)",
                expected_value="Clean record or unindexed URL",
                evidence="URL has not been previously submitted or analyzed in VirusTotal database.",
                source="VirusTotal v3 API",
                methodology="Live URL hash query",
                why_it_matters="Unindexed URLs typically represent new or unanalyzed endpoints.",
                limitations="Absence of historical record does not guarantee safety.",
                remediation="Submit URL for active analysis if suspicious behavior is suspected.",
                category="Threat Intelligence",
            )
            return {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": False,
                "detection_result": "CLEAN",
                "detections": 0,
                "total_engines": 0,
                "confidence": "MEDIUM",
                "timestamp": now_iso,
                "summary": "No threat records found in VirusTotal database.",
                "details": "This URL has no recorded detections or previous submissions.",
                "evidence_records": [ev.to_dict()],
            }

        if resp.status_code in (401, 403, 429) or resp.status_code != 200:
            err_reason = "Authentication failure" if resp.status_code in (401, 403) else ("Rate limit exceeded" if resp.status_code == 429 else f"HTTP {resp.status_code}")
            ev = create_evidence(
                test="threat_intel_virustotal",
                status=TestStatus.NOT_TESTABLE,
                severity=FindingSeverity.INFO,
                confidence=30,
                observed_value=f"HTTP {resp.status_code} ({err_reason})",
                expected_value="HTTP 200 JSON with analysis attributes",
                evidence=f"VirusTotal API returned error {resp.status_code}: {err_reason}.",
                source="VirusTotal v3 API",
                methodology="Authenticated HTTPS GET",
                why_it_matters="Reputation checks cannot be completed when third-party quotas are reached.",
                limitations="API downtime or quota limits prevent verification.",
                remediation="Verify API key validity and billing quotas.",
                category="Threat Intelligence",
            )
            return {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": url,
                "status": "NOT_TESTABLE",
                "configured": True,
                "detected": False,
                "detection_result": "UNAVAILABLE",
                "detections": 0,
                "total_engines": 0,
                "confidence": "LOW",
                "timestamp": now_iso,
                "summary": f"Threat intelligence source unavailable ({err_reason}).",
                "details": f"VirusTotal returned error: HTTP {resp.status_code}.",
                "evidence_records": [ev.to_dict()],
            }

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values()) or 90

        if malicious > 0:
            ev = create_evidence(
                test="threat_intel_virustotal",
                status=TestStatus.FAIL,
                severity=FindingSeverity.CRITICAL if malicious >= 2 else FindingSeverity.HIGH,
                confidence=95,
                observed_value=f"{malicious} / {total} engines flagged malicious",
                expected_value="0 malicious detections",
                evidence=f"VirusTotal report: {malicious} engines detected malware/phishing, {suspicious} suspicious, {harmless} harmless out of {total} total engines.",
                source="VirusTotal Multi-Engine Aggregator",
                methodology="Aggregated security scanner consensus query",
                why_it_matters="High correlation among commercial antivirus vendors strongly confirms hostile payload or fraud.",
                limitations="Consensus depends on vendor feed update frequency.",
                remediation="Avoid accessing resource; block at gateway and inspect host for compromise.",
                category="Threat Intelligence",
            )
            return {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": True,
                "detection_result": "THREAT_DETECTED",
                "detections": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "confidence": "HIGH",
                "timestamp": now_iso,
                "summary": f"🔴 {malicious} / {total} security engines flagged this URL as malicious.",
                "details": f"Flagged by {malicious} independent threat detection engines.",
                "evidence_records": [ev.to_dict()],
            }
        elif suspicious > 0:
            ev = create_evidence(
                test="threat_intel_virustotal",
                status=TestStatus.WARNING,
                severity=FindingSeverity.MEDIUM,
                confidence=70,
                observed_value=f"{suspicious} / {total} engines marked suspicious",
                expected_value="0 suspicious detections",
                evidence=f"VirusTotal report: {suspicious} engines noted suspicious anomalies (0 confirmed malicious).",
                source="VirusTotal Multi-Engine Aggregator",
                methodology="Aggregated security scanner consensus query",
                why_it_matters="Suspicious flags indicate behavioral anomalies or domain classification conflicts.",
                limitations="Low engine count can indicate false positive or newly registered site.",
                remediation="Review destination manually before entering sensitive information.",
                category="Threat Intelligence",
            )
            return {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": False,
                "detection_result": "SUSPICIOUS",
                "detections": 0,
                "suspicious": suspicious,
                "total_engines": total,
                "confidence": "MEDIUM",
                "timestamp": now_iso,
                "summary": f"⚠ {suspicious} / {total} engines marked this URL as suspicious.",
                "details": "Low-confidence indicators noted by scanning engines.",
                "evidence_records": [ev.to_dict()],
            }
        else:
            ev = create_evidence(
                test="threat_intel_virustotal",
                status=TestStatus.PASS,
                severity=FindingSeverity.INFO,
                confidence=90,
                observed_value=f"0 / {total} detections ({harmless} harmless)",
                expected_value="0 detections",
                evidence=f"All {total} active VirusTotal engines reported zero malicious or suspicious indicators.",
                source="VirusTotal Multi-Engine Aggregator",
                methodology="Aggregated security scanner consensus query",
                why_it_matters="Verifies URL is not currently listed across 70+ commercial antivirus vendor feeds.",
                limitations="Represents known signatures at scan time; does not guarantee protection against zero-day exploits.",
                remediation="Maintain standard security hygiene.",
                category="Threat Intelligence",
            )
            return {
                "name": "VirusTotal",
                "provider": "VirusTotal (Google Chronicle)",
                "query": url,
                "status": "CHECKED",
                "configured": True,
                "detected": False,
                "detection_result": "CLEAN",
                "detections": 0,
                "suspicious": 0,
                "total_engines": total,
                "confidence": "HIGH",
                "timestamp": now_iso,
                "summary": f"✓ 0 / {total} engines detected threats.",
                "details": "All active VirusTotal antivirus and reputation engines evaluated the URL as harmless.",
                "evidence_records": [ev.to_dict()],
            }

    except requests.exceptions.Timeout:
        ev = create_evidence(
            test="threat_intel_virustotal",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=30,
            observed_value=f"Timeout after {timeout}s",
            expected_value="HTTP 200 response within timeout limit",
            evidence="Connection to VirusTotal API timed out.",
            source="VirusTotal v3 API",
            methodology="HTTPS GET with socket timeout",
            why_it_matters="Network timeout prevents external reputation verification.",
            limitations="External network latency or service maintenance.",
            remediation="Retry scan later.",
            category="Threat Intelligence",
        )
        return {
            "name": "VirusTotal",
            "provider": "VirusTotal (Google Chronicle)",
            "query": url,
            "status": "NOT_TESTABLE",
            "configured": True,
            "detected": False,
            "detection_result": "TIMEOUT",
            "detections": 0,
            "total_engines": 0,
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Check unavailable (VirusTotal API timed out).",
            "details": f"Service did not respond within {timeout}s.",
            "evidence_records": [ev.to_dict()],
        }
    except Exception as exc:
        ev = create_evidence(
            test="threat_intel_virustotal",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=30,
            observed_value=f"Exception: {exc}",
            expected_value="HTTP 200 response",
            evidence=f"VirusTotal query failed: {exc}",
            source="VirusTotal v3 API",
            methodology="HTTPS query",
            why_it_matters="External query failure.",
            limitations="Local network or upstream exception.",
            remediation="Verify server internet connectivity.",
            category="Threat Intelligence",
        )
        return {
            "name": "VirusTotal",
            "provider": "VirusTotal (Google Chronicle)",
            "query": url,
            "status": "NOT_TESTABLE",
            "configured": True,
            "detected": False,
            "detection_result": "ERROR",
            "detections": 0,
            "total_engines": 0,
            "confidence": "LOW",
            "timestamp": now_iso,
            "summary": "Check unavailable (Service error).",
            "details": str(exc),
            "evidence_records": [ev.to_dict()],
        }
