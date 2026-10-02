"""
tests/test_heuristics.py
~~~~~~~~~~~~~~~~~~~~~~~~
Tests for heuristic analysis patterns and risk indicator extraction.
"""

from services.url_heuristics import analyze_url_heuristics
from services.url_validator import NormalizedURL


def _make_dummy_url(url: str, hostname: str, scheme: str = "https", is_ip: bool = False, port: int = 443, path: str = "/") -> NormalizedURL:
    return NormalizedURL(
        original_url=url,
        normalized_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query="",
        is_ip=is_ip,
        ip_type="ipv4" if is_ip else None,
        resolved_ips=["93.184.216.34"],
    )


def test_clean_standard_domain():
    norm = _make_dummy_url("https://example.com/", "example.com")
    res = analyze_url_heuristics(norm)
    assert res["status"] == "clean"
    assert res["score"] == 0
    assert len(res["indicators"]) == 0


def test_ip_address_heuristic():
    norm = _make_dummy_url("https://93.184.216.34/", "93.184.216.34", is_ip=True)
    res = analyze_url_heuristics(norm)
    assert any(i["id"] == "heur_ip_host" for i in res["indicators"])
    assert res["score"] > 0


def test_punycode_heuristic():
    norm = _make_dummy_url("https://xn--e1afmkfd.xn--p1ai/", "xn--e1afmkfd.xn--p1ai")
    res = analyze_url_heuristics(norm)
    assert any(i["id"] == "heur_punycode" for i in res["indicators"])


def test_unusual_port_heuristic():
    norm = _make_dummy_url("https://example.com:31337/", "example.com", port=31337)
    res = analyze_url_heuristics(norm)
    assert any(i["id"] == "heur_unusual_port" for i in res["indicators"])


def test_insecure_http_heuristic():
    norm = _make_dummy_url("http://example.com/", "example.com", scheme="http", port=80)
    res = analyze_url_heuristics(norm)
    assert any(i["id"] == "heur_http_protocol" for i in res["indicators"])
