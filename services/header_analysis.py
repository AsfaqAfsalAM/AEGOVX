"""
services/header_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified HTTP response header analysis engine for AEGOVX Scanner.
Evaluates core defense-in-depth security headers and information disclosure headers.
Provides weighted scoring (100-point scale), letter grades (A+ to F),
copy-ready server configuration fixes (Nginx, Apache, Express),
and produces structured Evidence-First records.

Crucial Architectural Rule:
  Missing security headers represent defensive configuration opportunities,
  NOT proof that the website is malicious.
"""

from __future__ import annotations

import datetime
import re
from typing import Any

from services.evidence import FindingSeverity, TestStatus, create_evidence

# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0,  "F"),
]

GRADE_SUMMARY = {
    "A+": "Outstanding! Your site has excellent defensive security headers.",
    "A":  "Great job! Your site is well protected with only minor hardening gaps.",
    "B":  "Good posture, but a few important defense-in-depth headers are missing or weak.",
    "C":  "Your site has noticeable security configuration gaps that should be addressed.",
    "D":  "Several critical defensive headers are missing. Your visitors may have reduced browser protection.",
    "F":  "Your site is missing most security headers. Defense-in-depth hardening is recommended.",
}

# ---------------------------------------------------------------------------
# Referrer-Policy – strict vs lenient
# ---------------------------------------------------------------------------
STRICT_REFERRER_VALUES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
LENIENT_REFERRER_VALUES = {
    "origin",
    "origin-when-cross-origin",
    "same-origin",
}

# ---------------------------------------------------------------------------
# Copy-ready fix snippets
# ---------------------------------------------------------------------------
FIXES: dict[str, dict[str, str]] = {
    "Content-Security-Policy": {
        "Nginx":   "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;\" always;",
        "Apache":  "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;\"",
        "Express": "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"], styleSrc: [\"'self'\"], imgSrc: [\"'self'\", 'data:'], objectSrc: [\"'none'\"], frameAncestors: [\"'none'\"] } }));",
    },
    "Strict-Transport-Security": {
        "Nginx":   "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "Apache":  "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
        "Express": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
    },
    "X-Frame-Options": {
        "Nginx":   "add_header X-Frame-Options \"DENY\" always;",
        "Apache":  "Header always set X-Frame-Options \"DENY\"",
        "Express": "app.use(helmet.frameguard({ action: 'deny' }));",
    },
    "X-Content-Type-Options": {
        "Nginx":   "add_header X-Content-Type-Options \"nosniff\" always;",
        "Apache":  "Header always set X-Content-Type-Options \"nosniff\"",
        "Express": "app.use(helmet.noSniff());",
    },
    "Referrer-Policy": {
        "Nginx":   "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "Apache":  "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "Express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
    },
    "Permissions-Policy": {
        "Nginx":   "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\" always;",
        "Apache":  "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\"",
        "Express": "res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');",
    },
    "Cross-Origin-Opener-Policy": {
        "Nginx":   "add_header Cross-Origin-Opener-Policy \"same-origin\" always;",
        "Apache":  "Header always set Cross-Origin-Opener-Policy \"same-origin\"",
        "Express": "app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));",
    },
    "Cross-Origin-Resource-Policy": {
        "Nginx":   "add_header Cross-Origin-Resource-Policy \"same-origin\" always;",
        "Apache":  "Header always set Cross-Origin-Resource-Policy \"same-origin\"",
        "Express": "app.use(helmet.crossOriginResourcePolicy({ policy: 'same-origin' }));",
    },
    "Server": {
        "Nginx":   "server_tokens off;  # Put this inside your http { } block in nginx.conf",
        "Apache":  "ServerTokens Prod\nServerSignature Off  # Add to httpd.conf or .htaccess",
        "Express": "app.disable('x-powered-by');  // Also remove Server header via a reverse proxy",
    },
    "X-Powered-By": {
        "Nginx":   "# Nginx does not add X-Powered-By. Make sure your app framework isn't adding it.",
        "Apache":  "Header always unset X-Powered-By  # Add to httpd.conf",
        "Express": "app.disable('x-powered-by');  // This removes the X-Powered-By header",
    },
}

# Ensure both lowercase and title-case server keys exist for compatibility
for _d in FIXES.values():
    _d.update({k.lower(): v for k, v in list(_d.items())})

# ---------------------------------------------------------------------------
# Plain-English descriptions & Educational context
# ---------------------------------------------------------------------------
DESCRIPTIONS: dict[str, dict[str, str]] = {
    "Content-Security-Policy": {
        "what":  "Controls which scripts, images, styles, and other resources the browser is permitted to execute or load.",
        "why":   "Without this, Cross-Site Scripting (XSS) attacks can execute malicious JavaScript to extract user cookies, tokens, or credentials.",
        "emoji": "🛡️",
        "plain_name": "Script Attack Shield (CSP)",
    },
    "Strict-Transport-Security": {
        "what":  "Instructs web browsers to strictly connect over encrypted HTTPS, automatically upgrading any insecure HTTP attempts.",
        "why":   "Mitigates SSL-stripping and active Man-in-the-Middle (MITM) attacks by enforcing HTTPS at the browser level.",
        "emoji": "🔒",
        "plain_name": "Force Secure Connection (HSTS)",
    },
    "X-Frame-Options": {
        "what":  "Governs whether your web page may be embedded inside <iframe>, <frame>, or <object> tags by other domains.",
        "why":   "Prevents Clickjacking attacks where an adversary overlays an invisible frame on your site to trick users into unintended clicks.",
        "emoji": "🖼️",
        "plain_name": "Clickjacking Protection",
    },
    "X-Content-Type-Options": {
        "what":  "Instructs browsers to strictly honor the declared Content-Type header and disables MIME-type sniffing.",
        "why":   "Stops attackers from disguising executable script files as innocent images or text files to bypass security filters.",
        "emoji": "📄",
        "plain_name": "File Type Protection",
    },
    "Referrer-Policy": {
        "what":  "Controls how much path and query string metadata is transmitted in the Referer header when navigating to external links.",
        "why":   "Prevents sensitive URL parameters (like password reset tokens or session keys) from leaking to third-party domains.",
        "emoji": "🔗",
        "plain_name": "Link Privacy Control",
    },
    "Permissions-Policy": {
        "what":  "Allows developers to selectively restrict access to browser hardware APIs (microphone, camera, geolocation, payments).",
        "why":   "Prevents compromised third-party scripts or embedded ads from secretly accessing sensitive device hardware.",
        "emoji": "🎛️",
        "plain_name": "Feature Access Control",
    },
    "Cross-Origin-Opener-Policy": {
        "what":  "Ensures a top-level document does not share a browsing context group with cross-origin documents.",
        "why":   "Protects against cross-origin window-interaction attacks and enables crossOriginIsolated process protection.",
        "emoji": "🪟",
        "plain_name": "Tab Isolation (COOP)",
    },
    "Cross-Origin-Resource-Policy": {
        "what":  "Prevents other websites from loading your images, scripts, or assets via cross-origin embedding.",
        "why":   "Mitigates speculative execution side-channel vulnerabilities (Spectre) by keeping resources origin-isolated.",
        "emoji": "📦",
        "plain_name": "Resource Protection (CORP)",
    },
    "Server": {
        "what":  "Discloses the specific web server software and version number (e.g., nginx/1.18 or Apache/2.4).",
        "why":   "Exposing exact versions enables automated exploit scanners to identify unpatched CVEs for that software release.",
        "emoji": "🖥️",
        "plain_name": "Server Software Hidden",
    },
    "X-Powered-By": {
        "what":  "Discloses the underlying application framework or runtime technology (e.g., PHP/8.1, Express, ASP.NET).",
        "why":   "Revealing framework architecture gives attackers a targeted roadmap to craft framework-specific exploit payloads.",
        "emoji": "⚡",
        "plain_name": "Backend Technology Hidden",
    },
}

# ---------------------------------------------------------------------------
# Scoring weights (total = 100 points)
# ---------------------------------------------------------------------------
WEIGHTS: dict[str, int] = {
    "Content-Security-Policy":       25,
    "Strict-Transport-Security":     20,
    "X-Frame-Options":               15,
    "X-Content-Type-Options":        10,
    "Referrer-Policy":               10,
    "Permissions-Policy":            10,
    "Cross-Origin-Opener-Policy":     5,
    "Cross-Origin-Resource-Policy":   5,
}

MIN_HSTS_MAX_AGE = 15_552_000  # 6 months in seconds


def _header_ci(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _parse_hsts_max_age(value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(m.group(1)) if m else None


def _csp_has_frame_ancestors(csp_value: str) -> bool:
    return "frame-ancestors" in csp_value.lower()


# ---------------------------------------------------------------------------
# Individual Header Checks
# ---------------------------------------------------------------------------

def _check_csp(headers: dict[str, str]) -> dict[str, Any]:
    value = _header_ci(headers, "Content-Security-Policy")
    notes: list[str] = []
    if value is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is not present in server response. Script execution is not restricted by policy."],
            "methodology": "Direct inspection of Content-Security-Policy header",
        }
    lower = value.lower()
    if "'unsafe-inline'" in lower:
        notes.append("Contains 'unsafe-inline' — permits inline script execution, reducing XSS mitigation effectiveness.")
    if "'unsafe-eval'" in lower:
        notes.append("Contains 'unsafe-eval' — allows dynamic string-to-code evaluation (eval()), creating potential attack vectors.")
    if "default-src" not in lower and "script-src" not in lower:
        notes.append("Missing both 'default-src' and 'script-src' fallback directives.")
    status = "warning" if notes else "pass"
    return {"status": status, "value": value, "notes": notes, "methodology": "Directive syntax parsing"}


def _check_hsts(headers: dict[str, str]) -> dict[str, Any]:
    value = _header_ci(headers, "Strict-Transport-Security")
    notes: list[str] = []
    if value is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is not present. Browsers will not automatically enforce HTTPS connections."],
            "methodology": "Strict-Transport-Security presence check",
        }
    max_age = _parse_hsts_max_age(value)
    if max_age is None:
        notes.append("Could not parse 'max-age' duration. Ensure header syntax is valid.")
    elif max_age < MIN_HSTS_MAX_AGE:
        notes.append(
            f"The duration (max-age={max_age:,} seconds) is under the recommended minimum "
            f"of {MIN_HSTS_MAX_AGE:,} seconds (180 days)."
        )
    if "includesubdomains" not in value.lower():
        notes.append("'includeSubDomains' is missing — subdomains are not automatically protected by HSTS.")
    status = "warning" if notes else "pass"
    return {"status": status, "value": value, "notes": notes, "methodology": "Directive regex parsing"}


def _check_x_frame_options(headers: dict[str, str]) -> dict[str, Any]:
    xfo = _header_ci(headers, "X-Frame-Options")
    csp = _header_ci(headers, "Content-Security-Policy")

    if csp and _csp_has_frame_ancestors(csp):
        return {
            "status": "pass",
            "value": xfo or "(Covered by CSP frame-ancestors)",
            "notes": ["Protected via Content-Security-Policy 'frame-ancestors' (supersedes X-Frame-Options in modern browsers)."],
            "methodology": "CSP frame-ancestors & XFO evaluation",
        }

    if xfo is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Neither X-Frame-Options nor CSP 'frame-ancestors' is configured. Page can be embedded in an <iframe>."],
            "methodology": "X-Frame-Options lookup",
        }

    upper = xfo.strip().upper()
    if upper in ("DENY", "SAMEORIGIN"):
        return {"status": "pass", "value": xfo, "notes": [], "methodology": "X-Frame-Options value comparison"}

    return {
        "status": "warning",
        "value": xfo,
        "notes": [f"Uncommon value '{xfo}'. Recommended values are 'DENY' or 'SAMEORIGIN'."],
        "methodology": "XFO value comparison",
    }


def _check_x_content_type_options(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "X-Content-Type-Options")
    if val is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is missing. Browsers may attempt to guess (sniff) MIME types of received resources."],
            "methodology": "X-Content-Type-Options presence check",
        }
    if val.strip().lower() == "nosniff":
        return {"status": "pass", "value": val, "notes": [], "methodology": "Value equality check against 'nosniff'"}
    return {
        "status": "warning",
        "value": val,
        "notes": [f"Expected 'nosniff' but observed '{val}'."],
        "methodology": "Value equality check",
    }


def _check_referrer_policy(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "Referrer-Policy")
    if val is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is missing. Browser default referrer behavior applies."],
            "methodology": "Referrer-Policy lookup",
        }

    tokens = [t.strip().lower() for t in val.split(",") if t.strip()]
    last_policy = tokens[-1] if tokens else val.strip().lower()

    if last_policy in STRICT_REFERRER_VALUES:
        return {"status": "pass", "value": val, "notes": [], "methodology": "Strict policy comparison"}
    elif last_policy in LENIENT_REFERRER_VALUES:
        return {
            "status": "warning",
            "value": val,
            "notes": [f"Policy '{last_policy}' leaks origin or path data in cross-origin requests. Use 'strict-origin-when-cross-origin'."],
            "methodology": "Lenient policy comparison",
        }
    return {
        "status": "warning",
        "value": val,
        "notes": [f"Uncommon value '{val}'. Verify it matches standard specifications."],
        "methodology": "Policy value comparison",
    }


def _check_permissions_policy(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "Permissions-Policy")
    if val is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is missing. Embedded iframes and third-party scripts have unrestricted browser API access."],
            "methodology": "Permissions-Policy presence check",
        }
    return {"status": "pass", "value": val, "notes": [], "methodology": "Permissions-Policy directive verification"}


def _check_coop(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "Cross-Origin-Opener-Policy")
    if val is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is missing. Documents opened by other windows can share a browsing context."],
            "methodology": "COOP presence check",
        }
    lower = val.strip().lower()
    if lower == "same-origin":
        return {"status": "pass", "value": val, "notes": [], "methodology": "COOP value equality check"}
    return {
        "status": "warning",
        "value": val,
        "notes": [f"Value is '{val}'. For maximum isolation, 'same-origin' is recommended."],
        "methodology": "COOP value equality check",
    }


def _check_corp(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "Cross-Origin-Resource-Policy")
    if val is None:
        return {
            "status": "fail",
            "value": None,
            "notes": ["Header is missing. Resources can be embedded by any origin."],
            "methodology": "CORP presence check",
        }
    lower = val.strip().lower()
    if lower in ("same-origin", "same-site"):
        return {"status": "pass", "value": val, "notes": [], "methodology": "CORP value equality check"}
    return {
        "status": "warning",
        "value": val,
        "notes": [f"Value is '{val}'. Recommended values are 'same-origin' or 'same-site'."],
        "methodology": "CORP value equality check",
    }


def _check_server_leak(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "Server")
    if val is None:
        return {"status": "pass", "value": None, "notes": [], "methodology": "Server header lookup"}
    return {
        "status": "fail",
        "value": val,
        "notes": [f"Reveals web server software: '{val}'. Consider hiding this header to reduce fingerprinting."],
        "methodology": "Server header presence check",
    }


def _check_x_powered_by_leak(headers: dict[str, str]) -> dict[str, Any]:
    val = _header_ci(headers, "X-Powered-By")
    if val is None:
        return {"status": "pass", "value": None, "notes": [], "methodology": "X-Powered-By header lookup"}
    return {
        "status": "fail",
        "value": val,
        "notes": [f"Reveals backend technology: '{val}'. Remove this header in production."],
        "methodology": "X-Powered-By presence check",
    }


_SCORED_DISPATCH = {
    "Content-Security-Policy":       _check_csp,
    "Strict-Transport-Security":     _check_hsts,
    "X-Frame-Options":               _check_x_frame_options,
    "X-Content-Type-Options":        _check_x_content_type_options,
    "Referrer-Policy":               _check_referrer_policy,
    "Permissions-Policy":            _check_permissions_policy,
    "Cross-Origin-Opener-Policy":     _check_coop,
    "Cross-Origin-Resource-Policy":   _check_corp,
}

_INFO_DISPATCH = {
    "Server":        _check_server_leak,
    "X-Powered-By":  _check_x_powered_by_leak,
}


def analyze_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Perform deep analysis of HTTP response headers.
    Returns:
      {
        "score": int,                  # 0 to 100 quality posture score
        "grade": str,                  # A+, A, B, C, D, F
        "grade_summary": str,
        "scored_headers": list[dict],
        "info_headers": list[dict],
        "evidence_records": list[dict],
        "indicators": list[dict],
        "summary": str,
      }
    """
    scored_headers: list[dict[str, Any]] = []
    info_headers: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    total_score = 0

    # 1. Scored Headers
    for name, max_pts in WEIGHTS.items():
        check_fn = _SCORED_DISPATCH[name]
        result = check_fn(headers)
        status = result["status"]
        val = result.get("value")
        notes = result.get("notes", [])
        desc = DESCRIPTIONS.get(name, {})
        fix = FIXES.get(name, {})

        if status == "pass":
            earned = max_pts
            test_st = TestStatus.PASS
            sev = FindingSeverity.INFO
        elif status == "warning":
            earned = max(1, max_pts // 2)
            test_st = TestStatus.WARNING
            sev = FindingSeverity.LOW
        else:
            earned = 0
            test_st = TestStatus.FAIL
            sev = FindingSeverity.MEDIUM if max_pts >= 15 else FindingSeverity.LOW

        total_score += earned

        scored_item = {
            "name": name,
            "plain_name": desc.get("plain_name", name),
            "emoji": desc.get("emoji", "🛡️"),
            "status": status,
            "points": earned,
            "max_points": max_pts,
            "value": val,
            "notes": notes,
            "what": desc.get("what", ""),
            "why": desc.get("why", ""),
            "fix": fix,
        }
        scored_headers.append(scored_item)

        # Build formal evidence record
        evidence_msg = notes[0] if notes else f"Header '{name}' is active and correctly configured."
        ev = create_evidence(
            test=f"security_header_{name.lower().replace('-', '_')}",
            status=test_st,
            severity=sev,
            confidence=98,
            observed_value=str(val) if val else "Header absent from response",
            expected_value="Configured defensive header",
            evidence=evidence_msg,
            source="HTTP Response Headers",
            methodology=result.get("methodology", "Direct header parsing"),
            why_it_matters=desc.get("why", "Hardens browser against opportunistic client-side attacks."),
            limitations="Evaluates the landing page response. Sub-pages or APIs may send different headers.",
            remediation=f"Configure '{name}' header on the web server according to recommended security profile.",
            category="Security Configuration",
        )
        evidence_records.append(ev.to_dict())

        # If missing or warning, add to unified findings list
        if status in ("warning", "fail"):
            indicators.append({
                "id": f"hdr_{name.lower().replace('-', '_')}",
                "title": f"Security Header {status.capitalize()}: {name}",
                "severity": "Medium" if max_pts >= 15 else "Low",
                "points": 0,  # CRITICAL: Missing headers do NOT penalize Threat Reputation!
                "category": "Security Configuration",
                "description": notes[0] if notes else desc.get("why", ""),
                "recommendation": f"Add or optimize the '{name}' header in your web server configuration.",
            })

    # 2. Information Leakage Headers
    for name, check_fn in _INFO_DISPATCH.items():
        result = check_fn(headers)
        status = result["status"]
        val = result.get("value")
        notes = result.get("notes", [])
        desc = DESCRIPTIONS.get(name, {})
        fix = FIXES.get(name, {})

        info_headers.append({
            "name": name,
            "plain_name": desc.get("plain_name", name),
            "emoji": desc.get("emoji", "🔍"),
            "status": status,
            "value": val,
            "notes": notes,
            "what": desc.get("what", ""),
            "why": desc.get("why", ""),
            "fix": fix,
        })

        if status == "fail":
            indicators.append({
                "id": f"hdr_leak_{name.lower().replace('-', '_')}",
                "title": f"Information Leakage: {name} Header Present",
                "severity": "Informational",
                "points": 0,
                "category": "Security Configuration",
                "description": notes[0] if notes else f"Exposes server software details ('{val}').",
                "recommendation": f"Suppress the '{name}' header in web server tokens.",
            })

    # Calculate letter grade
    grade = "F"
    for threshold, g in GRADE_THRESHOLDS:
        if total_score >= threshold:
            grade = g
            break

    grade_summary = GRADE_SUMMARY.get(grade, "")
    passed_count = sum(1 for h in scored_headers if h["status"] == "pass")

    return {
        "score": total_score,
        "header_quality_score": total_score,
        "max_score": 100,
        "grade": grade,
        "grade_summary": grade_summary,
        "scored_headers": scored_headers,
        "info_headers": info_headers,
        "evidence_records": evidence_records,
        "indicators": indicators,
        "summary": f"{passed_count} of 8 security headers passed ({total_score}/100 pts, Grade {grade}).",
    }


def analyze_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Compatibility alias for test suite."""
    return analyze_security_headers(headers)
