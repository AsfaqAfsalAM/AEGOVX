"""
services/scanner.py
~~~~~~~~~~~~~~~~~~~
AEGOVX Security Scanner Orchestrator.
Orchestrates multi-vector scans across independent analysis modules concurrently
with strict timeouts and error isolation.
Produces complete Evidence Chains and Technical Evidence Telemetry.
"""

from __future__ import annotations

import datetime
import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from services.cookie_analysis import analyze_cookies
from services.dns_analysis import analyze_dns_and_domain
from services.header_analysis import analyze_security_headers
from services.page_content import analyze_page_content
from services.redirect_analysis import analyze_redirects
from services.scoring import calculate_risk_assessment
from services.threat_intelligence import aggregate_threat_intelligence
from services.tls_analysis import analyze_tls_certificate
from services.url_heuristics import analyze_url_heuristics
from services.url_validator import NormalizedURL, validate_and_normalize_url

AEGOVX_DISCLAIMER = (
    "AEGOVX reports publicly observable technical evidence at scan time. "
    "A clean result does not guarantee that a website is 100% safe. "
    "Results represent verifiable signals only; defense-in-depth is always recommended. "
    "Only scan websites you own or have authorization to test."
)


def generate_scan_id() -> str:
    """Generate a unique human-friendly Scan ID: SCAN-YYYY-MM-DD-XXXXXX."""
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    suffix = secrets.token_hex(3).upper()
    return f"SCAN-{today}-{suffix}"


def run_full_scan(raw_url: str) -> dict[str, Any]:
    """
    Perform a complete, multi-vector evidence-first security scan of the given URL.
    """
    # 1. URL Validation & SSRF defense
    url_info: NormalizedURL = validate_and_normalize_url(raw_url)

    scan_id = generate_scan_id()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 2. Run heuristic analysis (purely local / instant)
    heuristics_result = analyze_url_heuristics(url_info)

    # 3. Concurrently execute independent network checks
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_dns = executor.submit(analyze_dns_and_domain, url_info)
        future_tls = executor.submit(analyze_tls_certificate, url_info)
        future_redir = executor.submit(analyze_redirects, url_info)
        future_ti = executor.submit(aggregate_threat_intelligence, url_info)

        try:
            dns_result = future_dns.result(timeout=10.0)
        except Exception as e:
            dns_result = {
                "status": "error",
                "hostname": url_info.hostname,
                "score": 0,
                "summary": "DNS inspection failed.",
                "indicators": [],
                "evidence_records": [],
            }

        try:
            tls_result = future_tls.result(timeout=10.0)
        except Exception as e:
            tls_result = {
                "status": "not_testable",
                "cert_status": "NOT_TESTABLE",
                "https_enabled": False,
                "is_valid": False,
                "score": 0,
                "summary": "TLS analysis failed.",
                "indicators": [],
                "evidence_records": [],
            }

        try:
            redir_result = future_redir.result(timeout=12.0)
        except Exception as e:
            redir_result = {
                "chain": [],
                "final_url": url_info.normalized_url,
                "final_status_code": 0,
                "final_headers": {},
                "final_content": "",
                "redirect_count": 0,
                "score": 0,
                "summary": "Redirect analysis encountered a network error.",
                "indicators": [],
                "evidence_records": [],
            }

        try:
            ti_result = future_ti.result(timeout=10.0)
        except Exception as e:
            ti_result = {
                "status": "unavailable",
                "has_confirmed_threat": False,
                "score": 0,
                "sources": [],
                "summary": "Threat intelligence unavailable.",
                "indicators": [],
                "evidence_records": [],
            }

    # 4. Analyze security headers, cookies, and page content from the final destination
    final_headers = redir_result.get("final_headers", {})
    final_content = redir_result.get("final_content", "")
    final_url = redir_result.get("final_url", url_info.normalized_url)

    header_result = analyze_security_headers(final_headers)
    cookie_result = analyze_cookies(final_headers, is_https=final_url.startswith("https://"))
    content_result = analyze_page_content(final_content, base_url=final_url)

    # 5. Calculate 3-Dimensional Assessment
    unreachable = (redir_result.get("final_status_code") == 0 and dns_result.get("status") == "unresolved")
    assessment = calculate_risk_assessment(
        threat_intel=ti_result,
        heuristics=heuristics_result,
        domain_data=dns_result,
        tls_data=tls_result,
        redirect_data=redir_result,
        header_data=header_result,
        cookie_data=cookie_result,
        content_data=content_result,
        unreachable=unreachable,
    )

    # 6. Technical Evidence Telemetry Package (sanitized, non-sensitive)
    technical_evidence = {
        "http_transaction": {
            "status_code": redir_result.get("final_status_code", 0),
            "final_url": final_url,
            "latency_ms": redir_result.get("total_latency_ms", 0),
            "redirect_count": redir_result.get("redirect_count", 0),
        },
        "raw_headers": final_headers,
        "redirect_chain": redir_result.get("chain", []),
        "tls_certificate": {
            "status": tls_result.get("cert_status", "NOT_TESTABLE"),
            "protocol": tls_result.get("tls_version"),
            "cipher": tls_result.get("cipher_name"),
            "issuer": tls_result.get("issuer"),
            "subject": tls_result.get("subject_cn"),
            "sans": tls_result.get("subject_alt_names", []),
            "days_remaining": tls_result.get("days_remaining"),
            "expiry_date": tls_result.get("expiry_date"),
        },
        "dns_records": {
            "ipv4": dns_result.get("ipv4", []),
            "ipv6": dns_result.get("ipv6", []),
            "ptr": dns_result.get("ptr_records", []),
            "hosting_provider": dns_result.get("hosting_provider"),
            "mx": dns_result.get("mx_records", []),
            "ns": dns_result.get("ns_records", []),
            "txt": dns_result.get("txt_records", []),
            "caa": dns_result.get("caa_records", []),
            "rdap": dns_result.get("rdap_info", {}),
        },
        "cookies": cookie_result.get("cookies", []),
        "page_analysis": {
            "forms_count": content_result.get("forms_count", 0),
            "scripts_count": content_result.get("scripts_count", 0),
            "iframes_count": content_result.get("iframes_count", 0),
            "external_script_origins": content_result.get("external_script_domains", []),
        },
        "threat_intelligence_sources": ti_result.get("sources", []),
    }

    # Return unified scan payload
    return {
        "scan_id": scan_id,
        "scanner_name": "AEGOVX",
        "scanner_tagline": "EVIDENCE BEFORE TRUST",
        "timestamp": now_iso,
        "original_url": raw_url,
        "normalized_url": url_info.normalized_url,
        "final_url": final_url,
        "status_code": redir_result.get("final_status_code", 200),

        # Dimension A: Threat Verdict
        "threat_verdict": assessment["threat_verdict"],
        "verdict_icon": assessment["verdict_icon"],
        "risk_level": assessment["risk_level"],
        "risk_label": assessment["risk_label"],
        "risk_description": assessment["risk_description"],
        "risk_score": assessment["risk_score"],
        "threat_score": assessment["threat_score"],

        # Dimension B: Security Configuration Posture
        "security_score": assessment["security_score"],
        "security_grade": assessment["security_grade"],
        "score": assessment["security_score"],
        "grade": assessment["security_grade"],
        "grade_summary": assessment["grade_summary"],

        # Dimension C: Analysis Coverage & Confidence
        "coverage": assessment["coverage"],
        "coverage_percentage": assessment["coverage_percentage"],
        "confidence": assessment["confidence"],
        "confidence_score": assessment["confidence_score"],
        "confidence_reason": assessment["confidence_reason"],

        # Findings, Breakdowns & Evidence
        "findings": assessment["findings"],
        "finding_counts": assessment["finding_counts"],
        "breakdown": assessment["breakdown"],
        "evidence_records": assessment["evidence_records"],
        "technical_evidence": technical_evidence,

        # Detail Category Sub-Objects
        "threat_intelligence": ti_result,
        "url_heuristics": heuristics_result,
        "domain_analysis": dns_result,
        "tls_analysis": tls_result,
        "redirect_analysis": redir_result,
        "security_headers": header_result,
        "cookie_analysis": cookie_result,
        "page_content": content_result,

        # Backward compatibility fields for legacy UI components
        "scored_headers": header_result.get("scored_headers", []),
        "info_headers": header_result.get("info_headers", []),
        "disclaimer": AEGOVX_DISCLAIMER,
    }
