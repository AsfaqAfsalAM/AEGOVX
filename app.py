"""
app.py
~~~~~~
Flask application for the URL Security & Website Risk Scanner.

Security measures implemented:
  - Scheme allowlist (HTTP and HTTPS only).
  - Strict SSRF defense: blocks private/loopback/link-local/multicast IP ranges
    and internal domain suffixes BEFORE connecting, and re-validates on every redirect.
  - Rate limiting: configurable scans per minute per client IP (in-memory, thread-safe).
  - Security headers on every response served by this app.
  - Secure environment variables: API keys and credentials are never exposed to clients.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

# Load environment variables from .env if present
load_dotenv()

from services.scanner import run_full_scan
from services.url_validator import validate_and_normalize_url

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Rate-limit & Cache configuration
# ---------------------------------------------------------------------------
_RATE_LIMIT_WINDOW = 60  # seconds
_RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 10))
_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()

# Ephemeral in-memory scan cache: scan_id -> { "data": dict, "created_at": float }
_scan_cache: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 3600 * 2  # 2 hours retention


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is within rate limits, False otherwise."""
    now = time.monotonic()
    with _rate_lock:
        timestamps = _rate_store.get(ip, [])
        timestamps = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]
        if len(timestamps) >= _RATE_LIMIT_MAX:
            _rate_store[ip] = timestamps
            return False
        timestamps.append(now)
        _rate_store[ip] = timestamps
        return True


def _store_scan(scan_id: str, data: dict[str, Any]) -> None:
    now = time.monotonic()
    with _cache_lock:
        # Evict expired entries
        expired_keys = [k for k, v in _scan_cache.items() if now - v["created_at"] > _CACHE_TTL]
        for k in expired_keys:
            _scan_cache.pop(k, None)
        # Store new scan
        _scan_cache[scan_id] = {"data": data, "created_at": now}


def _get_scan(scan_id: str) -> dict[str, Any] | None:
    now = time.monotonic()
    with _cache_lock:
        entry = _scan_cache.get(scan_id)
        if entry and (now - entry["created_at"] <= _CACHE_TTL):
            return entry["data"]
        return None


# ---------------------------------------------------------------------------
# Security headers for this app's own responses
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response: Any) -> Any:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/v1/scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def scan() -> Any:
    """
    Perform a complete security and risk scan of a submitted URL.
    """
    # 1. Rate limiting check
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    client_ip = client_ip.split(",")[0].strip()
    if not _check_rate_limit(client_ip):
        return jsonify({
            "error": (
                f"Rate limit exceeded. You may perform at most {_RATE_LIMIT_MAX} "
                f"scans per minute."
            )
        }), 429

    # 2. Parse request payload
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()

    if not raw_url:
        return jsonify({
            "error": "Please provide a website address to scan (e.g., https://example.com)."
        }), 400

    # 3. Pre-validate URL and SSRF defenses
    try:
        validate_and_normalize_url(raw_url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # 4. Execute full multi-vector scan
    try:
        scan_result = run_full_scan(raw_url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({
            "error": f"An unexpected error occurred during scan execution: {exc}"
        }), 500

    # 5. Cache result for retrieval by Scan ID
    _store_scan(scan_result["scan_id"], scan_result)

    return jsonify(scan_result)


@app.route("/api/v1/scan/<scan_id>", methods=["GET"])
def get_scan_report(scan_id: str) -> Any:
    """
    Retrieve an existing scan report by Scan ID.
    """
    cleaned_id = scan_id.strip()
    report = _get_scan(cleaned_id)
    if not report:
        return jsonify({
            "error": f"Scan report '{cleaned_id}' was not found or has expired from cache."
        }), 404
    return jsonify(report)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="127.0.0.1", port=port)
