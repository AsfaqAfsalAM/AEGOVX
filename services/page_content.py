"""
services/page_content.py
~~~~~~~~~~~~~~~~~~~~~~~~
Safely inspects publicly accessible HTML page content and scripts.
Strictly adheres to Evidence-First rules:
  - A login form is NOT automatically phishing.
  - A payment form is NOT automatically a scam.
  - Minified JavaScript is normal production optimization, NOT malicious obfuscation.
  - Standard iframes are NOT automatically malicious.
  - Flags only genuine anomalies (e.g. password fields posting over plaintext HTTP or to raw IP).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from services.evidence import FindingSeverity, TestStatus, create_evidence


class _SimpleHTMLAnalyzer(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.iframes: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "get").upper()
            resolved_action = urljoin(self.base_url, action)
            self._current_form = {
                "action": action,
                "resolved_action": resolved_action,
                "method": method,
                "has_password": False,
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form:
            input_type = attr_dict.get("type", "text").lower()
            if input_type == "password":
                self._current_form["has_password"] = True
        elif tag == "script":
            src = attr_dict.get("src")
            if src:
                self.scripts.append(urljoin(self.base_url, src))
        elif tag == "iframe":
            src = attr_dict.get("src")
            if src:
                self.iframes.append(urljoin(self.base_url, src))

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


def analyze_page_content(html_content: str, base_url: str) -> dict[str, Any]:
    """
    Inspect publicly accessible HTML content (limited to 512KB) for observable security risks.
    """
    evidence_records = []
    indicators = []
    points = 0

    if not html_content or len(html_content.strip()) < 10:
        ev = create_evidence(
            test="page_content_analysis",
            status=TestStatus.NOT_APPLICABLE,
            severity=FindingSeverity.INFO,
            confidence=90,
            observed_value="Empty or non-HTML response body",
            expected_value="HTML content",
            evidence="Response payload does not contain sufficient HTML markup for content analysis.",
            source="HTTP Response Body",
            methodology="HTML parser initialization check",
            why_it_matters="Applies to API endpoints, static assets, or empty redirect bodies.",
            limitations="Non-HTML endpoints do not have DOM structure.",
            remediation="None required for API or asset responses.",
            category="Content & Scripts",
        )
        evidence_records.append(ev.to_dict())
        return {
            "status": "not_applicable",
            "forms_count": 0,
            "scripts_count": 0,
            "iframes_count": 0,
            "external_script_domains": [],
            "indicators": [],
            "evidence_records": evidence_records,
            "score": 0,
            "summary": "Non-HTML response body; content inspection not applicable.",
        }

    parser = _SimpleHTMLAnalyzer(base_url)
    try:
        parser.feed(html_content[:512_000])  # Cap at 512KB for performance & safety
    except Exception:
        pass

    # 1. Inspect Form Actions (Check for insecure password transmission)
    parsed_base = urlparse(base_url)
    base_host = parsed_base.hostname or ""

    for form in parser.forms:
        if form.get("has_password"):
            resolved = urlparse(form.get("resolved_action", ""))
            # Insecure form action over HTTP
            if resolved.scheme == "http":
                points += 6
                indicators.append({
                    "id": "form_insecure_password_post",
                    "title": "Password Form Submits Over Unencrypted HTTP",
                    "severity": "Critical",
                    "points": 6,
                    "description": (
                        f"A password input form targets an unencrypted HTTP destination ('{form.get('resolved_action')}'). "
                        "Submitting credentials over plaintext HTTP allows eavesdroppers to intercept user passwords."
                    ),
                    "recommendation": "Update form action to submit strictly over HTTPS.",
                })
            # Form posting password to external third-party domain
            elif resolved.hostname and not (resolved.hostname == base_host or resolved.hostname.endswith("." + base_host)):
                # Potential credential exfiltration or third-party auth
                points += 3
                indicators.append({
                    "id": "form_external_password_target",
                    "title": f"Cross-Domain Password Submission (to {resolved.hostname})",
                    "severity": "Medium",
                    "points": 3,
                    "description": (
                        f"A password form posts credentials to an external host ('{resolved.hostname}') "
                        f"different from the landing page domain ('{base_host}'). If this is an external authentication provider "
                        "(e.g. Auth0, Okta, Cognito), this may be intended; otherwise it could indicate data exfiltration."
                    ),
                    "recommendation": "Verify that cross-domain authentication destinations are authorized.",
                })

    # 2. Obfuscated script signatures
    obfuscated_patterns = [
        (r"eval\s*\(\s*unescape\s*\(", "eval(unescape(...)) pattern"),
        (r"document\.write\s*\(\s*unescape\s*\(", "document.write(unescape(...)) pattern"),
        (r"eval\s*\(\s*atob\s*\(", "eval(atob(...)) pattern"),
    ]
    for pat, desc in obfuscated_patterns:
        if re.search(pat, html_content, re.IGNORECASE):
            points += 5
            indicators.append({
                "id": "script_obfuscation_detected",
                "title": f"Suspicious Dynamic Code Execution: {desc}",
                "severity": "High",
                "points": 5,
                "description": f"Encountered dynamic script unpacking signature: {desc}. Attackers frequently use dynamic evaluation to conceal malicious scripts.",
                "recommendation": "Refactor client scripts to use standard, pre-compiled JavaScript modules.",
            })
            break

    # 3. External Script Domains
    external_domains = set()
    for s_url in parser.scripts:
        p = urlparse(s_url)
        if p.hostname and p.hostname != base_host and not p.hostname.endswith("." + base_host):
            external_domains.add(p.hostname)

    ev = create_evidence(
        test="page_content_analysis",
        status=TestStatus.PASS if not indicators else TestStatus.WARNING,
        severity=FindingSeverity.INFO if not indicators else FindingSeverity.LOW,
        confidence=90,
        observed_value=f"{len(parser.forms)} form(s), {len(parser.scripts)} script(s), {len(parser.iframes)} iframe(s)",
        expected_value="Secure form actions and standard scripts",
        evidence=f"Audited {len(parser.forms)} form(s) and {len(parser.scripts)} script(s) across {len(external_domains)} external third-party domain(s).",
        source="DOM / HTML Source Parser",
        methodology="HTML lexical tokenization",
        why_it_matters="Verifies form submission security and third-party resource dependencies.",
        limitations="Dynamic JavaScript-rendered single page applications (SPAs) may generate DOM elements after load.",
        remediation="Audit third-party script integrations and enforce strict Content Security Policy.",
        category="Content & Scripts",
    )
    evidence_records.append(ev.to_dict())

    return {
        "status": "warning" if indicators else "pass",
        "forms_count": len(parser.forms),
        "scripts_count": len(parser.scripts),
        "iframes_count": len(parser.iframes),
        "external_script_domains": sorted(list(external_domains)),
        "indicators": indicators,
        "evidence_records": evidence_records,
        "score": min(points, 10),
        "summary": f"Analyzed HTML markup: {len(parser.forms)} forms, {len(parser.scripts)} scripts, {len(external_domains)} third-party script origin(s).",
    }
