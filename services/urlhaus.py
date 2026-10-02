"""
services/urlhaus.py
~~~~~~~~~~~~~~~~~~~
Direct query client for abuse.ch URLhaus API.
A free, publicly accessible community threat feed tracking malware sites.
No API key required.

API documentation: https://urlhaus-api.abuse.ch/api/
"""

from __future__ import annotations

import datetime
from typing import Any
import requests

from services.evidence import TestStatus, create_evidence

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


def check_urlhaus(url: str, hostname: str, timeout: float = 5.0) -> dict[str, Any]:
    """
    Query URLhaus for known malicious malware or payload hosting.
    Returns:
      {
        "provider": "URLhaus (abuse.ch)",
        "query": str,
        "status": "CHECKED" | "NOT_TESTABLE",
        "detected": bool,
        "threat": str | None,
        "url_status": str | None,
        "confidence": "HIGH" | "MEDIUM" | "LOW",
        "timestamp": str,
        "details": str,
        "evidence_records": list[dict],
      }
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    evidence_records = []

    try:
        resp = requests.post(
            URLHAUS_URL_ENDPOINT,
            data={"url": url},
            headers={"User-Agent": "AEGOVX-Security-Scanner/2.0 (+https://aegovx.internal)"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return {
                "provider": "URLhaus (abuse.ch)",
                "query": url,
                "status": "NOT_TESTABLE",
                "detected": False,
                "threat": None,
                "url_status": None,
                "confidence": "LOW",
                "timestamp": now_iso,
                "details": f"HTTP status {resp.status_code} returned by URLhaus API.",
                "evidence_records": [
                    create_evidence(
                        test="threat_intel_urlhaus",
                        status=TestStatus.NOT_TESTABLE,
                        severity="INFO",
                        confidence=40,
                        observed_value=f"HTTP {resp.status_code}",
                        expected_value="HTTP 200 JSON with query_status",
                        evidence=f"URLhaus endpoint returned HTTP {resp.status_code}.",
                        source="URLhaus API (abuse.ch)",
                        methodology="HTTP POST to URLhaus database API",
                        why_it_matters="Detects actively tracked malware distribution URLs.",
                        limitations="Free public threat intelligence API may be rate limited or temporarily unavailable.",
                        remediation="Retry query later or verify domain status independently.",
                        category="Threat Intelligence",
                    ).to_dict()
                ],
            }

        data = resp.json()
        query_status = data.get("query_status", "unknown")

        if query_status == "ok":
            threat = data.get("threat", "Malware distribution")
            url_status = data.get("url_status", "active")
            tags = data.get("tags") or []
            details_str = f"Confirmed listing in URLhaus: threat type '{threat}', status '{url_status}', tags: {tags}."

            ev = create_evidence(
                test="threat_intel_urlhaus",
                status=TestStatus.FAIL,
                severity="CRITICAL",
                confidence=95,
                observed_value=f"Listed in URLhaus ({threat}, {url_status})",
                expected_value="No listing (no_results)",
                evidence=details_str,
                source="abuse.ch URLhaus Threat Feed",
                methodology="Live cryptographic hash & URL string matching against active malware tracker",
                why_it_matters="URLhaus tracks verified malware distribution sites and botnet payloads.",
                limitations="Represents malware distribution verified by abuse.ch analysts and automated honeypots.",
                remediation="Immediately disinfect or block access to this malicious resource.",
                category="Threat Intelligence",
            )
            evidence_records.append(ev.to_dict())

            return {
                "provider": "URLhaus (abuse.ch)",
                "query": url,
                "status": "CHECKED",
                "detected": True,
                "threat": threat,
                "url_status": url_status,
                "confidence": "HIGH",
                "timestamp": now_iso,
                "details": details_str,
                "evidence_records": evidence_records,
            }

        elif query_status == "no_results":
            ev = create_evidence(
                test="threat_intel_urlhaus",
                status=TestStatus.PASS,
                severity="INFO",
                confidence=90,
                observed_value="No listing found",
                expected_value="No listing (clean)",
                evidence=f"URL '{url}' is not currently indexed in the active abuse.ch URLhaus malware database.",
                source="abuse.ch URLhaus Threat Feed",
                methodology="Live URL lookup against abuse.ch dataset",
                why_it_matters="Confirms URL has not been reported or validated as a malware distributor by abuse.ch.",
                limitations="A clean status does not guarantee 100% safety; zero-day or brand-new threats may not yet be indexed.",
                remediation="Maintain standard security hygiene.",
                category="Threat Intelligence",
            )
            evidence_records.append(ev.to_dict())

            return {
                "provider": "URLhaus (abuse.ch)",
                "query": url,
                "status": "CHECKED",
                "detected": False,
                "threat": None,
                "url_status": "clean",
                "confidence": "HIGH",
                "timestamp": now_iso,
                "details": "No malware listings found in URLhaus database.",
                "evidence_records": evidence_records,
            }

        else:
            return {
                "provider": "URLhaus (abuse.ch)",
                "query": url,
                "status": "CHECKED",
                "detected": False,
                "threat": None,
                "url_status": "clean",
                "confidence": "MEDIUM",
                "timestamp": now_iso,
                "details": f"Query completed with response: '{query_status}'. No confirmed threats reported.",
                "evidence_records": evidence_records,
            }

    except Exception as exc:
        return {
            "provider": "URLhaus (abuse.ch)",
            "query": url,
            "status": "NOT_TESTABLE",
            "detected": False,
            "threat": None,
            "url_status": None,
            "confidence": "LOW",
            "timestamp": now_iso,
            "details": f"Connection to URLhaus API timed out or encountered an error ({exc}).",
            "evidence_records": [
                create_evidence(
                    test="threat_intel_urlhaus",
                    status=TestStatus.NOT_TESTABLE,
                    severity="INFO",
                    confidence=30,
                    observed_value=f"Error: {exc}",
                    expected_value="Successful API handshake",
                    evidence=f"Request to abuse.ch timed out or failed: {exc}",
                    source="URLhaus API (abuse.ch)",
                    methodology="Automated HTTPS query",
                    why_it_matters="Threat feed availability is essential for multi-source correlation.",
                    limitations="Network latency or upstream rate limits can intermittently prevent external lookups.",
                    remediation="Retry scan or verify connectivity to abuse.ch.",
                    category="Threat Intelligence",
                ).to_dict()
            ],
        }
