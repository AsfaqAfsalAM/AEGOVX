# URL Security & Website Risk Scanner
> **"Is Your Website Actually Secure?"**

Professional URL security and website-risk scanner. Analyzes submitted URLs for known threats, suspicious indicators, security configuration issues, TLS certificate validity, and multi-source threat intelligence signals.

---

## Key Features

1. **Evidence-Based Risk Model (0–100 Normalized Score)**
   - Strict separation between **Malicious Threats** (malware, phishing, botnets) and **Security Configuration Weakness** (missing CSP, missing HSTS).
   - Clear classification into **SAFE**, **LOW RISK**, **SUSPICIOUS**, **HIGH RISK**, **MALICIOUS**, and **UNKNOWN**.
   - Distinct **Confidence Level** indicator (**HIGH**, **MEDIUM**, **LOW**, **UNKNOWN**).
   - Confirmed threat feed matches trigger an immediate **KNOWN THREAT** override.

2. **Multi-Source Threat Intelligence**
   - **Google Safe Browsing v4**: Evaluates for Malware, Social Engineering (Phishing), and Unwanted Software.
   - **VirusTotal v3**: Aggregates antivirus engine detections and URL reputation scores.
   - **Authentic Reporting**: Strictly reports *"Not checked — API key not configured"* or *"Check unavailable"* when APIs or keys are inactive, never fabricating clean results.

3. **URL Heuristic Analysis**
   - Direct IP address targets, excessive length, nested subdomains, Punycode/IDN homoglyph attacks, brand typo-squatting, Shannon entropy (DGA detection), unusual web ports, and open-redirect query parameters.

4. **Domain & DNS Infrastructure**
   - Multi-record IPv4 and IPv6 resolution, reverse DNS (PTR), Cloud/CDN provider detection (Cloudflare, AWS, Google Cloud, Fastly, Azure, Akamai), and disposable/high-abuse TLD monitoring.

5. **HTTPS & TLS Certificate Deep-Dive**
   - Cryptographic handshake inspection: certificate authority (issuer), validity dates, days until expiration countdown, hostname matching, protocol version (TLS 1.2 / 1.3), and cipher suite.

6. **Hop-by-Hop Redirect Traversal**
   - Step-by-step redirect chain mapping with independent SSRF validation on every hop, protocol downgrade detection (HTTPS → HTTP), and loop prevention.

7. **HTTP Security Headers & Information Leakage**
   - Comprehensive checks for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`.
   - Flags information leakage from `Server` and `X-Powered-By` response headers.
   - Copy-ready configuration snippets for **Nginx**, **Apache**, and **Express**.

8. **Strict Multi-Layer SSRF Defense**
   - Blocks private IP ranges (RFC 1918), loopback (`127.0.0.0/8`, `::1`), link-local (AWS metadata `169.254.169.254`), multicast, and internal domain zones (`.local`, `.internal`, `.lan`).
   - Resolves DNS before connecting and re-checks every redirect hop.

9. **Professional Reporting & Exporting**
   - Unique **Scan ID** generation (e.g. `SCAN-2026-10-01-A8F29C`).
   - Copy plain-text audit summary.
   - Download complete structured JSON schema (strictly sanitizing all backend secrets).
   - One-click clean print / PDF generation (`window.print()`).
   - Ephemeral in-browser recent scan history.

---

## Architecture

```
security-headers-checker/
├── app.py                      # Flask app, REST endpoints, rate limiting, SSRF middleware
├── checker.py                  # HTTP header analysis engine & fix snippets
├── .env                        # Local configuration (API keys, rate limits)
├── .env.example                # Template configuration
├── requirements.txt            # Python dependencies
├── services/
│   ├── url_validator.py        # URL normalization, decomposition, strict SSRF shield
│   ├── url_heuristics.py       # Entropy, punycode, brand keywords, port checks
│   ├── dns_analysis.py         # DNS resolution, reverse PTR, TLD analysis, CDN detection
│   ├── tls_analysis.py         # SSL handshake, cert parsing, expiry, protocol versions
│   ├── redirect_analysis.py    # Safe redirect hop-by-hop follower with SSRF hooks
│   ├── virustotal.py           # VirusTotal v3 API client (authentic error handling)
│   ├── google_web_risk.py      # Google Safe Browsing v4 client
│   ├── threat_intelligence.py  # Concurrent aggregator for threat intelligence feeds
│   ├── header_analysis.py      # Adapter mapping header quality into risk model
│   ├── scoring.py              # Evidence-based risk score & confidence calculator
│   └── scanner.py              # End-to-end multi-threaded scan coordinator
├── static/
│   ├── style.css               # Modern dark cybersecurity design system (glassmorphism)
│   └── main.js                 # Vanilla JS controller (XSS-safe DOM, real progress UI)
├── templates/
│   └── index.html              # Single-page UI with educational landing sections
└── tests/
    ├── test_url_validator.py   # SSRF & URL normalization test suite
    ├── test_heuristics.py      # URL pattern and entropy test suite
    ├── test_scoring.py         # Risk scoring model and threat override test suite
    ├── test_checker.py         # Security headers analysis test suite (29 tests)
    └── test_api.py             # Flask REST endpoints test suite
```

---

## Setup & Running Locally

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env` and optionally set your threat intelligence API keys:
```bash
cp .env.example .env
```
*(If keys are left blank, the scanner operates normally and truthfully displays "Not configured" for external feeds).*

### 3. Start the Server
```bash
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

---

## API Endpoints

### 1. Perform a Scan
`POST /api/v1/scan` (or legacy `POST /api/scan`)
```bash
curl -X POST http://127.0.0.1:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response Format:**
```json
{
  "scan_id": "SCAN-2026-10-01-A8F29C",
  "timestamp": "2026-10-01T10:45:00.000Z",
  "original_url": "https://example.com",
  "normalized_url": "https://example.com/",
  "final_url": "https://example.com/",
  "status_code": 200,
  "risk_level": "LOW RISK",
  "risk_label": "LOW RISK",
  "risk_score": 15,
  "confidence": "HIGH",
  "confidence_score": 85,
  "breakdown": {
    "threat_intelligence": { "score": 0, "max": 50 },
    "url_heuristics": { "score": 0, "max": 15 },
    "domain_signals": { "score": 0, "max": 15 },
    "tls_https": { "score": 0, "max": 10 },
    "redirects": { "score": 0, "max": 5 },
    "security_configuration": { "score": 15, "max": 5 }
  },
  "findings": [...],
  "disclaimer": "..."
}
```

### 2. Retrieve Scan by ID
`GET /api/v1/scan/<scan_id>`
```bash
curl http://127.0.0.1:5000/api/v1/scan/SCAN-2026-10-01-A8F29C
```

---

## Automated Test Suite

Run all 52 unit and integration tests:
```bash
pytest -v
```

All tests execute with mocked and isolated networks, verifying SSRF defenses, URL sanitization, threat intelligence handling, risk scoring formulas, and HTTP headers.
