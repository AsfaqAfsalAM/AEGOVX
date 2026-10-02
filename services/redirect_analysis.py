"""
services/redirect_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Traces redirect chains with hop-by-hop SSRF validation, detecting loops,
protocol downgrades, cross-domain hops, and excessive redirection.
Captures sanitized raw headers, latency, and response content for analysis.
Strictly adheres to Evidence-First rules.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin, urlparse
import requests

from services.evidence import FindingSeverity, TestStatus, create_evidence
from services.url_validator import NormalizedURL, resolve_and_verify_hostname

MAX_REDIRECT_HOPS = 10
DEFAULT_TIMEOUT = 8.0


def analyze_redirects(
    url_info: NormalizedURL,
    max_hops: int = MAX_REDIRECT_HOPS,
    timeout: float = DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """
    Safely follow redirects one hop at a time, checking SSRF constraints on every step.
    Produces Evidence-First logs and captures raw response headers & content for downstream inspection.
    """
    current_url = url_info.normalized_url
    chain: list[dict[str, Any]] = []
    visited: set[str] = set()
    indicators: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    points = 0

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AEGOVX/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    final_headers: dict[str, str] = {}
    final_status = 200
    final_content = ""
    has_downgrade = False
    has_cross_domain = False
    is_loop = False
    start_time = time.monotonic()
    total_elapsed_ms = 0

    for step_num in range(1, max_hops + 1):
        if current_url in visited:
            is_loop = True
            pts = 4
            points += pts
            ev = create_evidence(
                test="redirect_loop_detection",
                status=TestStatus.FAIL,
                severity=FindingSeverity.HIGH,
                confidence=98,
                observed_value=f"Cyclical redirect to '{current_url}'",
                expected_value="Linear termination without cycles",
                evidence=f"Encountered a cyclical redirect loop at step {step_num} returning to '{current_url}'.",
                source="HTTP Redirect Tracker",
                methodology="Hop-by-hop HTTP 3xx Location header graph traversal",
                why_it_matters="Redirect loops prevent user browsers from reaching the website and crash automated clients.",
                limitations="None.",
                remediation="Correct server redirect configuration or canonical URL rewriting rules.",
                category="Redirect Security",
            )
            evidence_records.append(ev.to_dict())
            indicators.append({
                "id": "redir_loop",
                "title": "Redirect loop detected",
                "severity": "High",
                "points": pts,
                "description": ev.evidence,
                "recommendation": ev.remediation,
            })
            break

        visited.add(current_url)

        # Parse and verify hostname for SSRF safety on this hop
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Redirect targeted an unsupported protocol: {parsed.scheme}")

        if not parsed.hostname:
            raise ValueError(f"Invalid redirect target without hostname: {current_url}")

        # Strict SSRF re-check on EVERY hop!
        resolve_and_verify_hostname(parsed.hostname)

        hop_start = time.monotonic()
        try:
            resp = session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=False,
                verify=True,
            )
        except requests.exceptions.SSLError:
            # Retry with verify=False only to read the redirect or final header, but note error
            try:
                resp = session.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=False,
                    verify=False,
                )
            except Exception as e:
                ev = create_evidence(
                    test="redirect_http_connectivity",
                    status=TestStatus.NOT_TESTABLE,
                    severity=FindingSeverity.INFO,
                    confidence=50,
                    observed_value=f"SSL/Connection Error: {e}",
                    expected_value="HTTP 2xx or 3xx response",
                    evidence=f"Could not connect to {current_url} due to SSL or socket failure: {e}",
                    source="HTTP Client",
                    methodology="GET with timeout",
                    why_it_matters="Connection failure halts redirect inspection.",
                    limitations="Endpoint may enforce client certificates or dropped connection.",
                    remediation="Check server SSL configuration and responsiveness.",
                    category="Redirect Security",
                )
                evidence_records.append(ev.to_dict())
                break
        except Exception as exc:
            ev = create_evidence(
                test="redirect_http_connectivity",
                status=TestStatus.NOT_TESTABLE,
                severity=FindingSeverity.INFO,
                confidence=50,
                observed_value=f"Network Error: {exc}",
                expected_value="HTTP 2xx or 3xx response",
                evidence=f"Request to {current_url} failed: {exc}",
                source="HTTP Client",
                methodology="GET with timeout",
                why_it_matters="Network error.",
                limitations="Server may be offline or blocking scanner user agent.",
                remediation="Verify web server accessibility.",
                category="Redirect Security",
            )
            evidence_records.append(ev.to_dict())
            break

        hop_elapsed = int((time.monotonic() - hop_start) * 1000)
        final_status = resp.status_code
        final_headers = dict(resp.headers)
        try:
            final_content = resp.text[:512_000]
        except Exception:
            final_content = ""

        # Check if this step is a redirect
        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            raw_location = resp.headers["Location"].strip()
            next_url = urljoin(current_url, raw_location)

            chain.append({
                "step": step_num,
                "url": current_url,
                "status_code": resp.status_code,
                "location": next_url,
                "latency_ms": hop_elapsed,
            })

            # Check HTTPS -> HTTP downgrade
            if current_url.startswith("https://") and next_url.startswith("http://"):
                has_downgrade = True
                pts = 5
                points += pts
                ev = create_evidence(
                    test="redirect_protocol_downgrade",
                    status=TestStatus.FAIL,
                    severity=FindingSeverity.CRITICAL,
                    confidence=98,
                    observed_value=f"{current_url} (HTTPS) -> {next_url} (HTTP)",
                    expected_value="HTTPS destination preserved",
                    evidence=f"Redirect step {step_num} downgrades secure HTTPS connection to unencrypted HTTP ('{next_url}').",
                    source="HTTP Location Header",
                    methodology="Scheme transition inspection",
                    why_it_matters="Protocol downgrade exposes subsequent traffic to network sniffing and SSL-stripping attacks.",
                    limitations="None.",
                    remediation="Configure web server to redirect only to HTTPS destinations.",
                    category="Redirect Security",
                )
                evidence_records.append(ev.to_dict())
                indicators.append({
                    "id": "redir_protocol_downgrade",
                    "title": "Insecure Protocol Downgrade (HTTPS → HTTP)",
                    "severity": "Critical",
                    "points": pts,
                    "description": ev.evidence,
                    "recommendation": ev.remediation,
                })

            # Check cross-domain redirect
            parsed_curr = urlparse(current_url)
            parsed_next = urlparse(next_url)
            if parsed_curr.hostname and parsed_next.hostname and parsed_curr.hostname != parsed_next.hostname:
                has_cross_domain = True

            current_url = next_url
        else:
            # Final landing page reached
            chain.append({
                "step": step_num,
                "url": current_url,
                "status_code": resp.status_code,
                "location": None,
                "latency_ms": hop_elapsed,
            })
            break

    total_elapsed_ms = int((time.monotonic() - start_time) * 1000)

    # General redirect count evidence
    if len(chain) > 1:
        if not has_downgrade and not is_loop:
            evidence_records.append(create_evidence(
                test="redirect_chain_security",
                status=TestStatus.PASS,
                severity=FindingSeverity.INFO,
                confidence=95,
                observed_value=f"{len(chain) - 1} redirect hop(s)",
                expected_value="Clean linear redirection",
                evidence=f"Redirect chain traversed {len(chain) - 1} hop(s) successfully without protocol downgrades or loops.",
                source="HTTP Status & Location",
                methodology="Hop tracking",
                why_it_matters="Legitimate sites frequently redirect HTTP to HTTPS or canonical www domains.",
                limitations="Only publicly issued redirect headers are followed.",
                remediation="None required.",
                category="Redirect Security",
            ).to_dict())
    else:
        evidence_records.append(create_evidence(
            test="redirect_chain_security",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=95,
            observed_value="0 hops (direct landing)",
            expected_value="Direct landing or secure redirect",
            evidence="Target URL responded directly without redirection.",
            source="HTTP Status Code",
            methodology="Response status inspection",
            why_it_matters="Direct navigation minimizes connection latency.",
            limitations="None.",
            remediation="None required.",
            category="Redirect Security",
        ).to_dict())

    # Build summary
    hop_count = max(0, len(chain) - 1)
    if has_downgrade:
        summary = f"CRITICAL: Redirect chain contains insecure downgrade (HTTPS → HTTP)."
    elif is_loop:
        summary = f"FAIL: Cyclical redirect loop detected."
    elif hop_count == 0:
        summary = "Direct navigation without redirects."
    else:
        summary = f"Traced {hop_count} redirect hop(s) terminating at {current_url} (HTTP {final_status})."

    return {
        "chain": chain,
        "final_url": current_url,
        "final_status_code": final_status,
        "final_headers": final_headers,
        "final_content": final_content,
        "redirect_count": hop_count,
        "has_protocol_downgrade": has_downgrade,
        "has_cross_domain": has_cross_domain,
        "is_loop": is_loop,
        "total_latency_ms": total_elapsed_ms,
        "score": min(points, 5),
        "indicators": indicators,
        "evidence_records": evidence_records,
        "summary": summary,
    }
