"""
services/url_heuristics.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Analyzes URL structure, patterns, encoding, entropy, homoglyphs, and lookalikes.
Adheres strictly to Evidence-First Architecture:
  - Each heuristic check produces a structured EvidenceRecord.
  - Potential lookalikes are labeled as 'POTENTIAL IMPERSONATION', never 'CONFIRMED PHISHING'.
  - One heuristic alone never determines the overall verdict.
"""

from __future__ import annotations

import datetime
import math
import re
import unicodedata
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from services.evidence import FindingSeverity, TestStatus, create_evidence
from services.url_validator import NormalizedURL

# Well-known brands often targeted by phishing / impersonation
_PHISH_TARGET_KEYWORDS = {
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
    "apple", "icloud", "appleid", "microsoft", "office365", "outlook",
    "google", "gmail", "facebook", "instagram", "netflix", "amazon",
    "binance", "coinbase", "metamask", "ledger", "trezor", "steam",
}

# Suspicious action keywords
_SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "authenticate", "secure-account", "wallet-connect", "update-billing",
    "confirm-identity", "password-reset", "claim-reward", "2fa-recovery",
}

_COMMON_PORTS = {80, 443, 8080, 8443}

# Cyrillic and Greek homoglyphs commonly confused with Latin letters
_HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u03bf': 'o', '\u03c1': 'p',
}


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _detect_homoglyphs(hostname: str) -> tuple[bool, str, list[str]]:
    """
    Detect non-ASCII characters or Cyrillic/Greek homoglyphs that mimic Latin characters.
    Returns (has_homoglyphs, normalized_latin_equivalent, list_of_confusables).
    """
    confusables_found = []
    normalized_chars = []
    for ch in hostname:
        if ch in _HOMOGLYPH_MAP:
            confusables_found.append(f"'{ch}' (U+{ord(ch):04X} confusable with '{_HOMOGLYPH_MAP[ch]}')")
            normalized_chars.append(_HOMOGLYPH_MAP[ch])
        else:
            normalized_chars.append(ch)

    has_homoglyph = len(confusables_found) > 0
    return has_homoglyph, "".join(normalized_chars), confusables_found


def analyze_url_heuristics(url_info: NormalizedURL) -> dict[str, Any]:
    """
    Perform deep heuristic analysis on a normalized URL, producing structured evidence for every check.
    """
    indicators: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    total_points = 0

    hostname = url_info.hostname.lower()
    path = url_info.path
    query = url_info.query
    raw = url_info.normalized_url

    # 1. IP address as hostname
    if url_info.is_ip:
        pts = 6
        total_points += pts
        ev = create_evidence(
            test="url_heuristic_ip_hostname",
            status=TestStatus.WARNING,
            severity=FindingSeverity.MEDIUM,
            confidence=95,
            observed_value=f"Direct IP: {hostname}",
            expected_value="Registered domain name (FQDN)",
            evidence=f"Hostname is a raw IP address ({hostname}) rather than a registered domain name.",
            source="URL String Parser",
            methodology="Syntax pattern matching against RFC 791 / RFC 4291 formats",
            why_it_matters="Direct IP URLs bypass domain reputation registries and are common in phishing and ad-fraud campaigns.",
            limitations="Legitimate test servers or internal staging environments may also use raw IP addresses.",
            remediation="Bind public web services to a fully qualified domain name with an active reputation history.",
            category="URL Structure",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "heur_ip_host",
            "title": "Direct IP address used instead of domain name",
            "severity": "Medium",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })
    else:
        evidence_records.append(create_evidence(
            test="url_heuristic_ip_hostname",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=95,
            observed_value=f"Domain: {hostname}",
            expected_value="Registered domain name (FQDN)",
            evidence=f"URL targets a standard domain name ({hostname}).",
            source="URL String Parser",
            methodology="Domain structure parsing",
            why_it_matters="Standard domain names allow reputation and DNS verification.",
            limitations="Domain presence alone does not establish safety.",
            remediation="None required.",
            category="URL Structure",
        ).to_dict())

    # 2. Homoglyph / Punycode Lookalike Detection
    has_punycode = "xn--" in hostname
    has_homoglyph, normalized_equiv, confusables = _detect_homoglyphs(hostname)

    if has_punycode or has_homoglyph:
        # Check if the normalized equivalent impersonates a known brand
        impersonated_brand = next((b for b in _PHISH_TARGET_KEYWORDS if b in normalized_equiv), None)
        title = "POTENTIAL IMPERSONATION: Lookalike / Internationalized Domain Name"
        if impersonated_brand:
            title += f" (mimicking '{impersonated_brand}')"
        pts = 6 if impersonated_brand else 4
        total_points += pts

        desc = (
            f"The domain contains internationalized encoding (Punycode 'xn--') or lookalike characters: "
            f"{', '.join(confusables) if confusables else hostname}. "
            "Attackers register visually deceptive lookalike domains (homoglyphs) to trick users into confusing them with legitimate brands."
        )
        ev = create_evidence(
            test="url_heuristic_homoglyph",
            status=TestStatus.WARNING,
            severity=FindingSeverity.HIGH if impersonated_brand else FindingSeverity.MEDIUM,
            confidence=85,
            observed_value=f"Encoded: {hostname} -> Decoded equivalent: {normalized_equiv}",
            expected_value="Standard ASCII domain without confusable characters",
            evidence=desc,
            source="Unicode Confusable & Punycode Analyzer",
            methodology="Unicode character decomposition and homoglyph mapping against UTS #39",
            why_it_matters="Homograph attacks deceive users by rendering foreign scripts identically to trusted Latin domain names.",
            limitations="Multilingual international organizations legitimately register Punycode domains in native scripts.",
            remediation="Verify that this internationalized domain genuinely matches your organization's official brand registry.",
            category="URL Structure",
        )
        evidence_records.append(ev.to_dict())
        indicator_id = "heur_punycode" if has_punycode else "heur_homoglyph"
        indicators.append({
            "id": indicator_id,
            "title": title,
            "severity": "High" if impersonated_brand else "Medium",
            "points": pts,
            "description": desc,
            "recommendation": ev.remediation,
        })
    else:
        evidence_records.append(create_evidence(
            test="url_heuristic_homoglyph",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=95,
            observed_value="Clean ASCII characters",
            expected_value="Clean ASCII domain",
            evidence="No Punycode (xn--) or Cyrillic/Greek lookalike homoglyphs detected in hostname.",
            source="Unicode Confusable & Punycode Analyzer",
            methodology="Unicode inspection",
            why_it_matters="Confirms absence of visual script confusion attacks.",
            limitations="Typo-squatting using regular ASCII letters (e.g. '0' for 'o') must be checked separately.",
            remediation="None required.",
            category="URL Structure",
        ).to_dict())

    # 3. URL Length and Path Structure
    url_len = len(raw)
    if url_len > 250:
        pts = 4
        total_points += pts
        ev = create_evidence(
            test="url_heuristic_length",
            status=TestStatus.WARNING,
            severity=FindingSeverity.MEDIUM,
            confidence=80,
            observed_value=f"{url_len} characters",
            expected_value="Under 150 characters",
            evidence=f"The URL length is unusually high ({url_len} characters). Attackers often pad URLs with hex tokens to conceal malicious subpaths.",
            source="URL String Parser",
            methodology="Length calculation",
            why_it_matters="Obfuscated and deeply nested URLs hinder user inspection.",
            limitations="Legitimate analytics tracking links and OAuth callbacks can also be lengthy.",
            remediation="Simplify URL structure where possible.",
            category="URL Structure",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "heur_extreme_length",
            "title": "Extremely long URL structure",
            "severity": "Medium",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })
    else:
        evidence_records.append(create_evidence(
            test="url_heuristic_length",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=90,
            observed_value=f"{url_len} characters",
            expected_value="Standard URL length (< 250 chars)",
            evidence=f"URL length is within standard parameters ({url_len} chars).",
            source="URL String Parser",
            methodology="Length check",
            why_it_matters="Standard length aids readability and inspection.",
            limitations="Short URLs can still conceal payloads.",
            remediation="None required.",
            category="URL Structure",
        ).to_dict())

    # 4. Excessive Subdomains
    if not url_info.is_ip:
        labels = [lbl for lbl in hostname.split(".") if lbl]
        if len(labels) > 4:
            pts = 3
            total_points += pts
            ev = create_evidence(
                test="url_heuristic_subdomains",
                status=TestStatus.WARNING,
                severity=FindingSeverity.LOW,
                confidence=75,
                observed_value=f"{len(labels) - 2} subdomain levels ({hostname})",
                expected_value="1-2 subdomain levels",
                evidence=f"The domain contains {len(labels) - 2} subdomain levels ({hostname}). Deep nesting can be used to mimic trusted brands.",
                source="URL String Parser",
                methodology="Label splitting",
                why_it_matters="Excessive subdomains complicate origin validation.",
                limitations="Complex enterprise architectures legitimately use multiple nested tiers.",
                remediation="Flatten domain hierarchy where appropriate.",
                category="URL Structure",
            )
            evidence_records.append(ev.to_dict())
            indicators.append({
                "id": "heur_subdomains",
                "title": "Excessive subdomain hierarchy",
                "severity": "Low",
                "points": pts,
                "description": ev.evidence,
                "recommendation": ev.remediation,
            })

    # 5. Phishing Brand Keywords paired with Sensitive Action Paths
    detected_brands = [b for b in _PHISH_TARGET_KEYWORDS if b in hostname or b in path.lower()]
    detected_actions = [a for a in _SUSPICIOUS_PATH_KEYWORDS if a in path.lower()]
    base_domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname

    if detected_brands and detected_actions and not any(b in base_domain for b in detected_brands):
        pts = 6
        total_points += pts
        ev = create_evidence(
            test="url_heuristic_brand_pattern",
            status=TestStatus.WARNING,
            severity=FindingSeverity.HIGH,
            confidence=85,
            observed_value=f"Brand: {', '.join(detected_brands)} | Action: {', '.join(detected_actions)}",
            expected_value="Official organization domain for branded login paths",
            evidence=(
                f"The URL references '{', '.join(detected_brands)}' alongside authentication paths "
                f"('{', '.join(detected_actions)}'), but base domain '{base_domain}' does not appear to be the official domain. "
                "This pattern is strongly indicative of potential credential harvesting."
            ),
            source="Heuristic Pattern Matcher",
            methodology="Brand keyword correlation with sensitive action paths",
            why_it_matters="Phishing kits commonly stage login workflows on third-party domains.",
            limitations="Affiliate portals or authorized partners may legitimately host authentication integrations.",
            remediation="Confirm whether this domain is an authorized asset for the mentioned service.",
            category="URL Structure",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "heur_brand_impersonation",
            "title": "Brand keyword paired with authentication/verification path",
            "severity": "High",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })

    # 6. Unencrypted HTTP Scheme
    if url_info.scheme == "http":
        pts = 3
        total_points += pts
        ev = create_evidence(
            test="url_heuristic_scheme_encryption",
            status=TestStatus.FAIL,
            severity=FindingSeverity.LOW,
            confidence=95,
            observed_value="http:// (plaintext)",
            expected_value="https:// (TLS encrypted)",
            evidence="The URL uses unencrypted plain HTTP rather than HTTPS.",
            source="URL String Parser",
            methodology="Scheme inspection",
            why_it_matters="Unencrypted connections expose credentials and web traffic to interception and tampering.",
            limitations="None.",
            remediation="Enforce HTTPS across the entire domain with an HTTP-to-HTTPS 301 redirect.",
            category="Transport Security",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "heur_http_protocol",
            "title": "Unencrypted HTTP protocol",
            "severity": "Low",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })
    else:
        evidence_records.append(create_evidence(
            test="url_heuristic_scheme_encryption",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=95,
            observed_value="https://",
            expected_value="https://",
            evidence="The target URL specifies an encrypted HTTPS transport scheme.",
            source="URL String Parser",
            methodology="Scheme inspection",
            why_it_matters="HTTPS is the foundation of modern web confidentiality.",
            limitations="Transport encryption secures the wire; it does not verify destination intent.",
            remediation="None required.",
            category="Transport Security",
        ).to_dict())

    # 7. Non-standard Web Port
    if url_info.port not in _COMMON_PORTS:
        pts = 3
        total_points += pts
        ev = create_evidence(
            test="url_heuristic_port",
            status=TestStatus.WARNING,
            severity=FindingSeverity.LOW,
            confidence=90,
            observed_value=f"Port {url_info.port}",
            expected_value="Port 80 (HTTP) or 443 (HTTPS)",
            evidence=f"The URL connects over non-standard port {url_info.port}.",
            source="URL Parser",
            methodology="Port number evaluation",
            why_it_matters="Non-standard ports may bypass security gateways or host unintended admin panels.",
            limitations="Development or custom internal services routinely use non-standard ports.",
            remediation="Host public web services on standard ports 80 and 443 behind a reverse proxy.",
            category="URL Structure",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "heur_unusual_port",
            "title": f"Non-standard web port: :{url_info.port}",
            "severity": "Low",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })

    # 8. Open Redirect Parameters
    parsed_query = parse_qs(query)
    redirect_keys = {"redirect", "redirect_uri", "next", "return", "url", "target", "goto", "dest"}
    found_redirect_keys = [k for k in parsed_query if k.lower() in redirect_keys]
    for k in found_redirect_keys:
        for val in parsed_query[k]:
            if val.startswith("http://") or val.startswith("https://") or val.startswith("//"):
                pts = 3
                total_points += pts
                ev = create_evidence(
                    test="url_heuristic_open_redirect_param",
                    status=TestStatus.WARNING,
                    severity=FindingSeverity.LOW,
                    confidence=85,
                    observed_value=f"{k}={val}",
                    expected_value="Relative path or allowlisted domain parameter",
                    evidence=f"Query parameter '{k}' points to an external destination ('{val}').",
                    source="URL Query Parser",
                    methodology="Query parameter inspection",
                    why_it_matters="Unvalidated redirect parameters can be weaponized in phishing emails to bypass link scanners.",
                    limitations="Server may enforce server-side allowlisting before following parameter.",
                    remediation="Validate redirection destinations against an explicit server-side allowlist.",
                    category="URL Structure",
                )
                evidence_records.append(ev.to_dict())
                indicators.append({
                    "id": "heur_open_redirect_param",
                    "title": f"Potential open redirect parameter: '{k}'",
                    "severity": "Low",
                    "points": pts,
                    "description": ev.evidence,
                    "recommendation": ev.remediation,
                })
                break

    normalized_score = min(total_points, 15)
    if not indicators:
        status = "clean"
        summary = "No suspicious URL patterns, homoglyphs, or heuristic anomalies detected."
    elif normalized_score <= 4:
        status = "low_indicators"
        summary = f"{len(indicators)} minor indicator(s) noted; typical for non-standard configurations."
    else:
        status = "suspicious_indicators"
        summary = f"{len(indicators)} heuristic indicator(s) detected with elevated risk contribution."

    return {
        "score": normalized_score,
        "max_score": 15,
        "raw_points": total_points,
        "status": status,
        "summary": summary,
        "indicators": indicators,
        "evidence_records": evidence_records,
    }
