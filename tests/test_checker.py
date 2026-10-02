"""
tests/test_checker.py
~~~~~~~~~~~~~~~~~~~~~
Unit tests for checker.py.  No network calls are made – headers are mocked.
"""

import pytest
from services.header_analysis import analyze_headers, MIN_HSTS_MAX_AGE


# ---------------------------------------------------------------------------
# Header fixtures
# ---------------------------------------------------------------------------

PERFECT_HEADERS = {
    "Content-Security-Policy":      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
    "Strict-Transport-Security":    f"max-age={MIN_HSTS_MAX_AGE + 1000}; includeSubDomains; preload",
    "X-Frame-Options":              "DENY",
    "X-Content-Type-Options":       "nosniff",
    "Referrer-Policy":              "strict-origin-when-cross-origin",
    "Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy":   "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

EMPTY_HEADERS: dict[str, str] = {}

WEAK_CSP_HEADERS = {
    **PERFECT_HEADERS,
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
}

SERVER_LEAK_HEADERS = {
    **PERFECT_HEADERS,
    "Server":      "Apache/2.4.54 (Debian)",
    "X-Powered-By": "PHP/8.1.2",
}

WEAK_HSTS_HEADERS = {
    **PERFECT_HEADERS,
    "Strict-Transport-Security": f"max-age={MIN_HSTS_MAX_AGE - 1}",  # too short, no includeSubDomains
}

LENIENT_REFERRER_HEADERS = {
    **PERFECT_HEADERS,
    "Referrer-Policy": "origin-when-cross-origin",
}

COOP_WARNING_HEADERS = {
    **PERFECT_HEADERS,
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
}

CORP_WARNING_HEADERS = {
    **PERFECT_HEADERS,
    "Cross-Origin-Resource-Policy": "cross-origin",
}

MISSING_XFO_HEADERS = {
    k: v for k, v in PERFECT_HEADERS.items()
    if k not in ("X-Frame-Options", "Content-Security-Policy")
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _find_header(result: dict, name: str) -> dict:
    for h in result["scored_headers"]:
        if h["name"] == name:
            return h
    for h in result["info_headers"]:
        if h["name"] == name:
            return h
    raise KeyError(f"Header '{name}' not found in result")


# ---------------------------------------------------------------------------
# Tests – perfect headers
# ---------------------------------------------------------------------------

class TestPerfectHeaders:
    def test_grade_is_A_or_better(self):
        result = analyze_headers(PERFECT_HEADERS)
        assert result["grade"] in ("A+", "A"), f"Expected A/A+ but got {result['grade']}"

    def test_score_at_least_90(self):
        result = analyze_headers(PERFECT_HEADERS)
        assert result["score"] >= 90, f"Expected score ≥ 90, got {result['score']}"

    def test_all_scored_headers_pass(self):
        result = analyze_headers(PERFECT_HEADERS)
        for h in result["scored_headers"]:
            assert h["status"] == "pass", f"{h['name']} expected pass, got {h['status']}"

    def test_server_absent_is_pass(self):
        result = analyze_headers(PERFECT_HEADERS)
        server = _find_header(result, "Server")
        assert server["status"] == "pass"


# ---------------------------------------------------------------------------
# Tests – missing everything
# ---------------------------------------------------------------------------

class TestMissingEverything:
    def test_grade_is_F(self):
        result = analyze_headers(EMPTY_HEADERS)
        assert result["grade"] == "F", f"Expected F but got {result['grade']}"

    def test_score_below_30(self):
        result = analyze_headers(EMPTY_HEADERS)
        assert result["score"] < 30, f"Expected score < 30, got {result['score']}"

    def test_score_is_zero(self):
        result = analyze_headers(EMPTY_HEADERS)
        assert result["score"] == 0

    def test_all_scored_headers_fail(self):
        result = analyze_headers(EMPTY_HEADERS)
        for h in result["scored_headers"]:
            assert h["status"] == "fail", f"{h['name']} expected fail, got {h['status']}"


# ---------------------------------------------------------------------------
# Tests – weak CSP
# ---------------------------------------------------------------------------

class TestWeakCSP:
    def test_csp_status_is_warning(self):
        result = analyze_headers(WEAK_CSP_HEADERS)
        csp = _find_header(result, "Content-Security-Policy")
        assert csp["status"] == "warning"

    def test_csp_notes_mention_unsafe_inline(self):
        result = analyze_headers(WEAK_CSP_HEADERS)
        csp = _find_header(result, "Content-Security-Policy")
        notes_text = " ".join(csp["notes"]).lower()
        assert "unsafe-inline" in notes_text

    def test_csp_notes_mention_unsafe_eval(self):
        result = analyze_headers(WEAK_CSP_HEADERS)
        csp = _find_header(result, "Content-Security-Policy")
        notes_text = " ".join(csp["notes"]).lower()
        assert "unsafe-eval" in notes_text

    def test_csp_partial_points(self):
        result = analyze_headers(WEAK_CSP_HEADERS)
        csp = _find_header(result, "Content-Security-Policy")
        # Warning yields partial credit, must be > 0 and < max
        assert 0 < csp["points"] < csp["max_points"]


# ---------------------------------------------------------------------------
# Tests – info-leak headers (Server, X-Powered-By)
# ---------------------------------------------------------------------------

class TestInfoLeakHeaders:
    def test_server_header_flagged_as_fail(self):
        result = analyze_headers(SERVER_LEAK_HEADERS)
        server = _find_header(result, "Server")
        assert server["status"] == "fail"

    def test_x_powered_by_flagged_as_fail(self):
        result = analyze_headers(SERVER_LEAK_HEADERS)
        xpb = _find_header(result, "X-Powered-By")
        assert xpb["status"] == "fail"

    def test_server_value_captured(self):
        result = analyze_headers(SERVER_LEAK_HEADERS)
        server = _find_header(result, "Server")
        assert server["value"] == "Apache/2.4.54 (Debian)"

    def test_info_leaks_do_not_affect_score(self):
        """Info-leak headers are not part of the weighted score."""
        result_with_leak    = analyze_headers(SERVER_LEAK_HEADERS)
        result_without_leak = analyze_headers(PERFECT_HEADERS)
        assert result_with_leak["score"] == result_without_leak["score"]


# ---------------------------------------------------------------------------
# Tests – weak HSTS
# ---------------------------------------------------------------------------

class TestWeakHSTS:
    def test_hsts_status_is_warning(self):
        result = analyze_headers(WEAK_HSTS_HEADERS)
        hsts = _find_header(result, "Strict-Transport-Security")
        assert hsts["status"] == "warning"

    def test_hsts_notes_mention_max_age(self):
        result = analyze_headers(WEAK_HSTS_HEADERS)
        hsts = _find_header(result, "Strict-Transport-Security")
        notes_text = " ".join(hsts["notes"]).lower()
        assert "max-age" in notes_text

    def test_hsts_notes_mention_includesubdomains(self):
        result = analyze_headers(WEAK_HSTS_HEADERS)
        hsts = _find_header(result, "Strict-Transport-Security")
        notes_text = " ".join(hsts["notes"]).lower()
        assert "includesubdomains" in notes_text


# ---------------------------------------------------------------------------
# Tests – Referrer-Policy
# ---------------------------------------------------------------------------

class TestReferrerPolicy:
    def test_lenient_referrer_is_warning(self):
        result = analyze_headers(LENIENT_REFERRER_HEADERS)
        rp = _find_header(result, "Referrer-Policy")
        assert rp["status"] == "warning"

    def test_strict_referrer_is_pass(self):
        result = analyze_headers(PERFECT_HEADERS)
        rp = _find_header(result, "Referrer-Policy")
        assert rp["status"] == "pass"

    def test_missing_referrer_is_fail(self):
        headers = {k: v for k, v in PERFECT_HEADERS.items() if k != "Referrer-Policy"}
        result = analyze_headers(headers)
        rp = _find_header(result, "Referrer-Policy")
        assert rp["status"] == "fail"


# ---------------------------------------------------------------------------
# Tests – COOP / CORP
# ---------------------------------------------------------------------------

class TestCOOPCORP:
    def test_coop_non_same_origin_is_warning(self):
        result = analyze_headers(COOP_WARNING_HEADERS)
        coop = _find_header(result, "Cross-Origin-Opener-Policy")
        assert coop["status"] == "warning"

    def test_corp_cross_origin_is_warning(self):
        result = analyze_headers(CORP_WARNING_HEADERS)
        corp = _find_header(result, "Cross-Origin-Resource-Policy")
        assert corp["status"] == "warning"


# ---------------------------------------------------------------------------
# Tests – X-Frame-Options
# ---------------------------------------------------------------------------

class TestXFrameOptions:
    def test_missing_xfo_no_csp_frame_ancestors_is_fail(self):
        result = analyze_headers(MISSING_XFO_HEADERS)
        xfo = _find_header(result, "X-Frame-Options")
        assert xfo["status"] == "fail"

    def test_csp_frame_ancestors_covers_xfo(self):
        """If CSP has frame-ancestors, X-Frame-Options should pass even if absent."""
        headers = {
            k: v for k, v in PERFECT_HEADERS.items() if k != "X-Frame-Options"
        }
        # Ensure CSP has frame-ancestors (PERFECT_HEADERS CSP does)
        result = analyze_headers(headers)
        xfo = _find_header(result, "X-Frame-Options")
        assert xfo["status"] == "pass"


# ---------------------------------------------------------------------------
# Tests – result structure
# ---------------------------------------------------------------------------

class TestResultStructure:
    def test_result_has_required_keys(self):
        result = analyze_headers(PERFECT_HEADERS)
        assert "score" in result
        assert "grade" in result
        assert "scored_headers" in result
        assert "info_headers" in result

    def test_each_header_has_fix_dict(self):
        result = analyze_headers(PERFECT_HEADERS)
        for h in result["scored_headers"]:
            assert "fix" in h, f"{h['name']} missing 'fix'"
            assert "nginx" in h["fix"]
            assert "apache" in h["fix"]
            assert "express" in h["fix"]

    def test_score_in_valid_range(self):
        for headers in (PERFECT_HEADERS, EMPTY_HEADERS, WEAK_CSP_HEADERS):
            result = analyze_headers(headers)
            assert 0 <= result["score"] <= 100, f"Score {result['score']} out of range"
