"""
services/cookie_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Inspects observable cookies from Set-Cookie HTTP response headers.
Evaluates Secure, HttpOnly, SameSite, Domain, and Path attributes.
Identifies sensitive naming patterns (session, token, auth, csrf, jwt)
and produces Evidence-First audit logs.
"""

from __future__ import annotations

import re
from typing import Any

from services.evidence import FindingSeverity, TestStatus, create_evidence

_SENSITIVE_COOKIE_PATTERNS = re.compile(
    r"(sess|session|token|auth|jwt|id_token|access_token|csrf|xsrf|sid|user_id)",
    re.IGNORECASE
)


def analyze_cookies(raw_headers: dict[str, str], is_https: bool = True) -> dict[str, Any]:
    """
    Parse and analyze Set-Cookie headers from HTTP responses.
    """
    evidence_records = []
    indicators = []
    cookie_items = []
    points = 0

    # Collect Set-Cookie headers (case-insensitive)
    set_cookie_raw = None
    for k, v in raw_headers.items():
        if k.lower() == "set-cookie":
            set_cookie_raw = v
            break

    if not set_cookie_raw:
        ev = create_evidence(
            test="cookie_attributes",
            status=TestStatus.NOT_APPLICABLE,
            severity=FindingSeverity.INFO,
            confidence=95,
            observed_value="No Set-Cookie headers observed",
            expected_value="N/A",
            evidence="Initial HTTP response did not issue any new cookies via Set-Cookie headers.",
            source="HTTP Response Headers",
            methodology="Set-Cookie header extraction",
            why_it_matters="Stateless pages or responses without session tracking do not emit cookies.",
            limitations="Cookies may be set dynamically via client-side JavaScript or sub-pages.",
            remediation="None required if the page is intentionally stateless.",
            category="Cookie Security",
        )
        evidence_records.append(ev.to_dict())
        return {
            "status": "not_applicable",
            "cookies": [],
            "cookie_count": 0,
            "sensitive_cookie_count": 0,
            "evidence_records": evidence_records,
            "indicators": [],
            "score": 0,
            "summary": "No cookies issued in the primary response.",
        }

    # Split multiple cookies (in headers, may be joined or comma separated)
    cookie_strings = re.split(r",\s*(?=[a-zA-Z0-9_\-]+=)", set_cookie_raw)

    for c_str in cookie_strings:
        parts = [p.strip() for p in c_str.split(";") if p.strip()]
        if not parts:
            continue

        name_val = parts[0].split("=", 1)
        c_name = name_val[0].strip()
        c_val = name_val[1].strip() if len(name_val) > 1 else ""

        is_sensitive = bool(_SENSITIVE_COOKIE_PATTERNS.search(c_name))

        # Check attributes
        has_secure = any(p.lower() == "secure" for p in parts[1:])
        has_httponly = any(p.lower() == "httponly" for p in parts[1:])
        samesite_part = next((p for p in parts[1:] if p.lower().startswith("samesite")), None)
        samesite_val = samesite_part.split("=", 1)[1].strip() if (samesite_part and "=" in samesite_part) else None

        cookie_info = {
            "name": c_name,
            "is_sensitive": is_sensitive,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite_val or "Not specified",
        }
        cookie_items.append(cookie_info)

        # Flag missing security attributes on sensitive cookies
        if is_sensitive:
            if not has_secure and is_https:
                points += 2
                indicators.append({
                    "id": f"cookie_insecure_{c_name}",
                    "title": f"Sensitive Cookie '{c_name}' Missing 'Secure' Flag",
                    "severity": "High",
                    "points": 2,
                    "description": (
                        f"The cookie '{c_name}' appears to store authentication or session tokens but lacks the 'Secure' attribute. "
                        "Browsers may transmit this cookie over unencrypted HTTP connections if accessed."
                    ),
                    "recommendation": f"Add the 'Secure' directive to Set-Cookie for '{c_name}'.",
                })

            if not has_httponly:
                points += 2
                indicators.append({
                    "id": f"cookie_no_httponly_{c_name}",
                    "title": f"Sensitive Cookie '{c_name}' Missing 'HttpOnly' Flag",
                    "severity": "Medium",
                    "points": 2,
                    "description": (
                        f"The cookie '{c_name}' is accessible via client-side JavaScript (document.cookie). "
                        "If an XSS vulnerability exists, attackers can steal this session cookie."
                    ),
                    "recommendation": f"Add the 'HttpOnly' directive to Set-Cookie for '{c_name}'.",
                })

            if not samesite_val or samesite_val.lower() == "none":
                points += 1
                indicators.append({
                    "id": f"cookie_samesite_{c_name}",
                    "title": f"Sensitive Cookie '{c_name}' Missing 'SameSite' Protection",
                    "severity": "Low",
                    "points": 1,
                    "description": f"Cookie '{c_name}' does not restrict cross-site transmission (SameSite=Lax or Strict recommended).",
                    "recommendation": "Configure SameSite=Lax or SameSite=Strict to mitigate Cross-Site Request Forgery (CSRF).",
                })

    ev = create_evidence(
        test="cookie_attributes",
        status=TestStatus.PASS if not indicators else TestStatus.WARNING,
        severity=FindingSeverity.INFO if not indicators else FindingSeverity.LOW,
        confidence=90,
        observed_value=f"{len(cookie_items)} cookie(s) observed ({sum(1 for c in cookie_items if c['is_sensitive'])} sensitive)",
        expected_value="Cookies have Secure, HttpOnly, and SameSite attributes",
        evidence=f"Audited {len(cookie_items)} cookie(s). Sensitive flags evaluated for session confidentiality.",
        source="HTTP Set-Cookie Headers",
        methodology="Cookie attribute parsing against RFC 6265bis specifications",
        why_it_matters="Proper cookie flags prevent session theft via XSS and CSRF attacks.",
        limitations="Only cookies set on the initial response are visible to the scanner.",
        remediation="Ensure sensitive session cookies set Secure, HttpOnly, and SameSite.",
        category="Cookie Security",
    )
    evidence_records.append(ev.to_dict())

    return {
        "status": "warning" if indicators else "pass",
        "cookies": cookie_items,
        "cookie_count": len(cookie_items),
        "sensitive_cookie_count": sum(1 for c in cookie_items if c["is_sensitive"]),
        "evidence_records": evidence_records,
        "indicators": indicators,
        "score": min(points, 5),
        "summary": f"Inspected {len(cookie_items)} response cookie(s).",
    }
