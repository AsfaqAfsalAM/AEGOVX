"""
services/tls_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~
Inspects TLS/SSL certificates, cipher negotiation, validity periods,
SAN matching, and protocol versions using standard socket/ssl libraries.
Strictly adheres to Evidence-First rules:
  - Valid TLS encrypts transport; it does NOT prove site intent or overall safety.
  - Return statuses: VALID | EXPIRED | MISMATCH | INVALID | NOT_TESTABLE.
  - Network timeouts are reported as NOT_TESTABLE with zero risk penalties.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from services.evidence import FindingSeverity, TestStatus, create_evidence
from services.url_validator import NormalizedURL


def _parse_cert_date(date_str: str) -> datetime.datetime | None:
    """Parse standard OpenSSL certificate date format: 'MMM DD HH:MM:SS YYYY GMT'."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt).replace(tzinfo=datetime.timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def analyze_tls_certificate(url_info: NormalizedURL, timeout: float = 6.0) -> dict[str, Any]:
    """
    Perform deep inspection of the target's TLS certificate, producing structured evidence for every check.
    """
    hostname = url_info.hostname
    port = url_info.port if (url_info.port and url_info.scheme == "https") else 443

    indicators: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    points = 0

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    cert_info: dict[str, Any] = {}
    tls_version: str | None = None
    cipher_name: str | None = None
    cert_status = "NOT_TESTABLE"
    is_valid = False
    is_expired = False
    days_remaining: int | None = None
    expiry_formatted: str = "Unknown"
    issuer_name = "Unknown"
    subject_cn = hostname
    sans_list: list[str] = []

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else None
                is_valid = True
                cert_status = "VALID"

                # Extract Issuer
                for field in cert.get("issuer", ()):
                    for k, val in field:
                        if k == "organizationName":
                            issuer_name = val
                            break
                        if k == "commonName" and issuer_name == "Unknown":
                            issuer_name = val

                # Extract Subject & SANs
                for field in cert.get("subject", ()):
                    for k, val in field:
                        if k == "commonName":
                            subject_cn = val

                for san_type, san_val in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans_list.append(san_val)

                # Extract Expiration & Validity Dates
                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")

                if not_after_str:
                    not_after_dt = _parse_cert_date(not_after_str)
                    if not_after_dt:
                        now_dt = datetime.datetime.now(datetime.timezone.utc)
                        delta = not_after_dt - now_dt
                        days_remaining = delta.days
                        expiry_formatted = not_after_dt.strftime("%B %d, %Y")

                        if days_remaining < 0:
                            is_expired = True
                            is_valid = False
                            cert_status = "EXPIRED"
                            pts = 10
                            points += pts
                            ev = create_evidence(
                                test="tls_certificate_validity",
                                status=TestStatus.FAIL,
                                severity=FindingSeverity.CRITICAL,
                                confidence=98,
                                observed_value=f"Expired on {expiry_formatted} ({abs(days_remaining)} days ago)",
                                expected_value="Active certificate within validity window",
                                evidence=f"TLS certificate for '{hostname}' expired {abs(days_remaining)} days ago on {expiry_formatted}.",
                                source="TLS Handshake x509 Peer Certificate",
                                methodology="Direct TLS socket handshake and notAfter date extraction",
                                why_it_matters="Browsers block expired certificates with prominent security warnings.",
                                limitations="Applies to the specific negotiated certificate.",
                                remediation="Renew and install an updated TLS certificate immediately.",
                                category="TLS / HTTPS",
                            )
                            evidence_records.append(ev.to_dict())
                            indicators.append({
                                "id": "tls_cert_expired",
                                "title": "TLS Certificate has expired",
                                "severity": "Critical",
                                "points": pts,
                                "description": ev.evidence,
                                "recommendation": ev.remediation,
                            })
                        elif days_remaining <= 14:
                            pts = 3
                            points += pts
                            ev = create_evidence(
                                test="tls_certificate_validity",
                                status=TestStatus.WARNING,
                                severity=FindingSeverity.MEDIUM,
                                confidence=95,
                                observed_value=f"Expires in {days_remaining} days ({expiry_formatted})",
                                expected_value="Certificate valid for > 14 days",
                                evidence=f"Certificate is approaching expiration date ({days_remaining} days remaining).",
                                source="TLS Handshake x509 Peer Certificate",
                                methodology="Date difference calculation",
                                why_it_matters="If renewal is missed, visitors will encounter browser security blocks.",
                                limitations="Automated ACME renewals (e.g. Certbot) may be scheduled within the final week.",
                                remediation="Verify automated certificate renewal jobs to prevent downtime.",
                                category="TLS / HTTPS",
                            )
                            evidence_records.append(ev.to_dict())
                            indicators.append({
                                "id": "tls_cert_expiring_soon",
                                "title": f"TLS Certificate expires soon ({days_remaining} days)",
                                "severity": "Medium",
                                "points": pts,
                                "description": ev.evidence,
                                "recommendation": ev.remediation,
                            })
                        else:
                            evidence_records.append(create_evidence(
                                test="tls_certificate_validity",
                                status=TestStatus.PASS,
                                severity=FindingSeverity.INFO,
                                confidence=98,
                                observed_value=f"Valid (expires in {days_remaining} days on {expiry_formatted})",
                                expected_value="Valid active certificate",
                                evidence=f"Certificate issued by '{issuer_name}' is valid until {expiry_formatted} ({days_remaining} days remaining).",
                                source="TLS Handshake x509 Peer Certificate",
                                methodology="OpenSSL verification against Mozilla CA trust store",
                                why_it_matters="HTTPS transport protection verified. Valid TLS encrypts transport; it does not verify site intent or safety.",
                                limitations="Validates cryptographic authenticity of transport channel only.",
                                remediation="None required.",
                                category="TLS / HTTPS",
                            ).to_dict())

                # Check TLS Protocol Version
                if tls_version in ("TLSv1", "TLSv1.1"):
                    pts = 6
                    points += pts
                    ev = create_evidence(
                        test="tls_protocol_version",
                        status=TestStatus.FAIL,
                        severity=FindingSeverity.HIGH,
                        confidence=95,
                        observed_value=str(tls_version),
                        expected_value="TLSv1.2 or TLSv1.3",
                        evidence=f"Server negotiated obsolete protocol {tls_version}.",
                        source="TLS Socket Negotiation",
                        methodology="SSL socket version negotiation",
                        why_it_matters="TLS 1.0 and 1.1 contain cryptographic design flaws (BEAST, POODLE) and are banned by PCI-DSS.",
                        limitations="Some legacy industrial embedded devices require older protocols.",
                        remediation="Disable TLS 1.0 and 1.1; enforce TLS 1.2 and modern TLS 1.3.",
                        category="TLS / HTTPS",
                    )
                    evidence_records.append(ev.to_dict())
                    indicators.append({
                        "id": "tls_outdated_version",
                        "title": f"Deprecated TLS Protocol Version ({tls_version})",
                        "severity": "High",
                        "points": pts,
                        "description": ev.evidence,
                        "recommendation": ev.remediation,
                    })
                else:
                    evidence_records.append(create_evidence(
                        test="tls_protocol_version",
                        status=TestStatus.PASS,
                        severity=FindingSeverity.INFO,
                        confidence=98,
                        observed_value=f"{tls_version} ({cipher_name})",
                        expected_value="TLSv1.2 or TLSv1.3",
                        evidence=f"Server negotiated modern cryptographic protocol {tls_version} with cipher {cipher_name}.",
                        source="TLS Socket Negotiation",
                        methodology="Socket handshake version inspection",
                        why_it_matters="Ensures strong forward secrecy and defense against downgrade attacks.",
                        limitations="None.",
                        remediation="None required.",
                        category="TLS / HTTPS",
                    ).to_dict())

    except ssl.SSLCertVerificationError as exc:
        is_valid = False
        err_msg = str(exc)
        if "hostname" in err_msg.lower() or "doesn't match" in err_msg.lower():
            cert_status = "MISMATCH"
            pts = 8
            title = "TLS Certificate Hostname Mismatch"
        else:
            cert_status = "INVALID"
            pts = 8
            title = "TLS Certificate Verification Failed"

        points += pts
        ev = create_evidence(
            test="tls_certificate_validity",
            status=TestStatus.FAIL,
            severity=FindingSeverity.HIGH,
            confidence=95,
            observed_value=f"{cert_status}: {err_msg}",
            expected_value="Publicly trusted certificate matching hostname",
            evidence=f"Certificate verification error: {err_msg}.",
            source="OpenSSL Trust Store",
            methodology="Standard CA trust chain validation",
            why_it_matters="Browsers block untrusted or mismatched certificates to protect users from Man-in-the-Middle (MITM) attacks.",
            limitations="May be a self-signed staging certificate or missing intermediate chain certificate.",
            remediation="Install a certificate issued by a public CA that includes this hostname in its Subject Alternative Names (SAN).",
            category="TLS / HTTPS",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "tls_verification_failed",
            "title": title,
            "severity": "High",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })

    except (socket.timeout, TimeoutError):
        cert_status = "NOT_TESTABLE"
        # CRITICAL: A timeout is NOT a malicious result! 0 penalty points.
        ev = create_evidence(
            test="tls_certificate_validity",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=40,
            observed_value=f"Timeout after {timeout}s",
            expected_value="TLS handshake response on port 443",
            evidence="TLS connection to port 443 timed out. The server did not complete the TLS handshake in the allocated timeframe.",
            source="TCP Socket Handshake",
            methodology="socket.create_connection with timeout",
            why_it_matters="Connection timeout prevents evaluating cryptographic certificate parameters.",
            limitations="Host may be behind a firewall that drops SYN packets or serves HTTP only.",
            remediation="Verify port 443 is open and TLS service is responding.",
            category="TLS / HTTPS",
        )
        evidence_records.append(ev.to_dict())

    except Exception as exc:
        cert_status = "NOT_TESTABLE"
        ev = create_evidence(
            test="tls_certificate_validity",
            status=TestStatus.NOT_TESTABLE,
            severity=FindingSeverity.INFO,
            confidence=40,
            observed_value=f"Socket error: {exc}",
            expected_value="Successful TLS connection",
            evidence=f"TLS handshake could not be established: {exc}",
            source="Socket Connection",
            methodology="Socket connection attempt",
            why_it_matters="Unable to verify TLS parameters.",
            limitations="Port may be closed or filtered.",
            remediation="Ensure HTTPS service is configured and accessible.",
            category="TLS / HTTPS",
        )
        evidence_records.append(ev.to_dict())

    # Build concise summary
    if cert_status == "VALID":
        summary = f"HTTPS transport protection verified. Valid {tls_version} certificate ({days_remaining} days remaining)."
    elif cert_status == "EXPIRED":
        summary = f"TLS certificate expired on {expiry_formatted}."
    elif cert_status in ("MISMATCH", "INVALID"):
        summary = "TLS certificate validation failed (untrusted or hostname mismatch)."
    else:
        summary = "TLS certificate test could not be completed (timeout or connection error)."

    return {
        "status": cert_status.lower(),
        "cert_status": cert_status,
        "is_valid": is_valid,
        "is_expired": is_expired,
        "https_enabled": is_valid,
        "tls_version": tls_version,
        "cipher_name": cipher_name,
        "issuer": issuer_name,
        "subject_cn": subject_cn,
        "subject_alt_names": sans_list,
        "days_remaining": days_remaining,
        "expiry_date": expiry_formatted,
        "score": min(points, 10),
        "indicators": indicators,
        "evidence_records": evidence_records,
        "summary": summary,
    }
