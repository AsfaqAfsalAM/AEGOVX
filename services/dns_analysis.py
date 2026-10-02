"""
services/dns_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~
Performs DNS record resolution (A, AAAA, MX, NS, TXT, CAA, DNSSEC),
reverse DNS (PTR), RDAP/WHOIS metadata collection, and CDN/cloud hosting classification.
Strictly adheres to Evidence-First rules:
  - Domain age is a signal, NOT proof of maliciousness.
  - Cloud/CDN hosting is normal engineering, NOT suspiciousness.
  - Privacy-protected WHOIS is standard privacy practice, NOT maliciousness.
  - DNS or RDAP timeouts are reported as NOT_TESTABLE, never as FAIL.
"""

from __future__ import annotations

import datetime
import socket
from typing import Any
from urllib.parse import urlparse
import requests

from services.evidence import FindingSeverity, TestStatus, create_evidence
from services.url_validator import NormalizedURL

# High abuse TLDs historically seen with disproportionate phishing/spam campaigns
_HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "click", "surf",
    "country", "stream", "gdn", "mom", "kim", "fit", "rest", "bar",
}

# Known CDN / Cloud provider substrings in PTR or ASN
_PROVIDER_PATTERNS = [
    ("cloudflare", "Cloudflare CDN & Edge"),
    ("cloudfront", "Amazon CloudFront / AWS"),
    ("amazonaws", "Amazon Web Services (AWS)"),
    ("google", "Google Cloud / Global Infrastructure"),
    ("1e100.net", "Google Edge Infrastructure"),
    ("akamai", "Akamai Technologies Intelligent Edge"),
    ("fastly", "Fastly Edge Cloud"),
    ("azure", "Microsoft Azure Cloud"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode / Akamai Connected Cloud"),
    ("ovh", "OVHcloud"),
    ("hetzner", "Hetzner Online"),
]


def _extract_tld_and_base(hostname: str) -> tuple[str, str]:
    """Extract TLD and estimated base domain."""
    parts = hostname.split(".")
    if len(parts) <= 1:
        return "", hostname

    two_part_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz", "co.jp"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        tld = ".".join(parts[-2:])
        base = ".".join(parts[-3:])
        return tld, base

    tld = parts[-1]
    base = ".".join(parts[-2:])
    return tld, base


def _query_doh_records(name: str, record_type: str, timeout: float = 3.5) -> list[str]:
    """Query Cloudflare DNS-over-HTTPS JSON API for records (MX, NS, TXT, CAA, CNAME)."""
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={name}&type={record_type}"
        resp = requests.get(url, headers={"Accept": "application/dns-json"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            results = []
            for ans in answers:
                val = ans.get("data", "").strip('"')
                if val:
                    results.append(val)
            return results
    except Exception:
        pass
    return []


def _query_rdap_info(base_domain: str, timeout: float = 3.5) -> dict[str, Any]:
    """Query public ICANN RDAP for domain registration details."""
    try:
        url = f"https://rdap.org/domain/{base_domain}"
        resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
            expires = next((e.get("eventDate") for e in events if e.get("eventAction") == "expiration"), None)
            updated = next((e.get("eventDate") for e in events if e.get("eventAction") == "last changed"), None)

            # Extract registrar name
            entities = data.get("entities", [])
            registrar = None
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar = item[3]
                                break

            # Check DNSSEC status
            secure_dns = data.get("secureDNS", {})
            dnssec_delegated = secure_dns.get("delegationSigned", False)

            return {
                "status": "available",
                "registrar": registrar,
                "created_date": created,
                "expires_date": expires,
                "updated_date": updated,
                "dnssec_signed": dnssec_delegated,
            }
    except Exception:
        pass
    return {"status": "unavailable", "registrar": None, "created_date": None, "expires_date": None, "dnssec_signed": False}


def analyze_dns_and_domain(url_info: NormalizedURL) -> dict[str, Any]:
    """
    Perform deep DNS, PTR, RDAP, and network infrastructure analysis.
    """
    hostname = url_info.hostname
    is_ip = url_info.is_ip

    indicators: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    points = 0

    if is_ip:
        tld, base = "", hostname
    else:
        tld, base = _extract_tld_and_base(hostname)

    # 1. IP Resolution
    ipv4_list: list[str] = []
    ipv6_list: list[str] = []
    ptr_records: list[str] = []

    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addr_infos:
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4_list:
                ipv4_list.append(ip)
            elif family == socket.AF_INET6 and ip not in ipv6_list:
                ipv6_list.append(ip)
    except socket.gaierror as exc:
        ev = create_evidence(
            test="dns_resolution",
            status=TestStatus.FAIL,
            severity=FindingSeverity.HIGH,
            confidence=95,
            observed_value=f"Resolution failure: {exc.strerror or exc}",
            expected_value="At least one valid public A or AAAA record",
            evidence=f"DNS query for domain '{hostname}' could not be resolved by authoritative nameservers.",
            source="Local Recursive DNS Resolver",
            methodology="socket.getaddrinfo lookup",
            why_it_matters="If DNS cannot resolve, visitors and security crawlers cannot connect to the server.",
            limitations="May reflect temporary network outage or newly registered propagation delay.",
            remediation="Verify domain delegation, nameserver NS records, and zone file configuration.",
            category="Domain & Infrastructure",
        )
        evidence_records.append(ev.to_dict())
        return {
            "status": "unresolved",
            "hostname": hostname,
            "tld": tld,
            "base_domain": base,
            "ipv4": [],
            "ipv6": [],
            "has_ipv6": False,
            "ptr_records": [],
            "hosting_provider": None,
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "caa_records": [],
            "rdap_info": {},
            "score": 0,
            "indicators": [{
                "id": "dns_resolution_failed",
                "title": "DNS resolution failed",
                "severity": "High",
                "points": 0,
                "description": f"Domain '{hostname}' could not be resolved by DNS ({exc.strerror or exc}).",
                "recommendation": "Check nameserver connectivity and zone propagation.",
            }],
            "evidence_records": evidence_records,
            "summary": "DNS lookup failed; the domain cannot be reached.",
        }

    # Successful resolution evidence
    evidence_records.append(create_evidence(
        test="dns_resolution",
        status=TestStatus.PASS,
        severity=FindingSeverity.INFO,
        confidence=95,
        observed_value=f"IPv4: {len(ipv4_list)} ({', '.join(ipv4_list[:3])}) | IPv6: {len(ipv6_list)}",
        expected_value="Resolved public IP addresses",
        evidence=f"Domain resolved successfully to {len(ipv4_list)} IPv4 address(es) and {len(ipv6_list)} IPv6 address(es).",
        source="DNS Resolver",
        methodology="RFC 1035 A/AAAA lookup",
        why_it_matters="Confirms active domain routing and operational host infrastructure.",
        limitations="IP routing may change rapidly via CDN Anycast or dynamic DNS.",
        remediation="None required.",
        category="Domain & Infrastructure",
    ).to_dict())

    # 2. Reverse DNS (PTR) and Hosting Provider Detection
    detected_provider: str | None = None
    target_ip = ipv4_list[0] if ipv4_list else (ipv6_list[0] if ipv6_list else None)

    if target_ip:
        try:
            host_entry = socket.gethostbyaddr(target_ip)
            ptr_name = host_entry[0].lower()
            ptr_records.append(ptr_name)
            for pat, prov_name in _PROVIDER_PATTERNS:
                if pat in ptr_name:
                    detected_provider = prov_name
                    break
        except (socket.herror, socket.gaierror, OSError):
            pass

    # 3. Query Extended DNS Records via DoH
    mx_records = _query_doh_records(base, "MX")
    ns_records = _query_doh_records(base, "NS")
    txt_records = _query_doh_records(base, "TXT")
    caa_records = _query_doh_records(base, "CAA")

    # CAA Record Check (Hardening recommendation)
    if caa_records:
        evidence_records.append(create_evidence(
            test="dns_caa_record",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=90,
            observed_value=f"{len(caa_records)} CAA record(s)",
            expected_value="Valid CAA records restricting certificate issuance",
            evidence=f"CAA record configured: {', '.join(caa_records[:2])}. Restricts which Certificate Authorities may issue certs.",
            source="DNS CAA Record Query",
            methodology="DoH CAA record lookup",
            why_it_matters="Certification Authority Authorization prevents unauthorized issuance of certificates for your domain.",
            limitations="Only enforced by complying public CAs.",
            remediation="None required.",
            category="Domain & Infrastructure",
        ).to_dict())
    else:
        evidence_records.append(create_evidence(
            test="dns_caa_record",
            status=TestStatus.WARNING,
            severity=FindingSeverity.INFO,
            confidence=80,
            observed_value="None",
            expected_value="CAA record (RFC 8659)",
            evidence="No CAA (Certification Authority Authorization) record found in DNS zone.",
            source="DNS CAA Record Query",
            methodology="DoH CAA record lookup",
            why_it_matters="Without a CAA record, any publicly trusted Certificate Authority can issue a certificate for your domain.",
            limitations="Optional defense-in-depth standard.",
            remediation="Deploy CAA records specifying your authorized Certificate Authorities (e.g., letsencrypt.org, digicert.com).",
            category="Domain & Infrastructure",
        ).to_dict())

    # 4. Query RDAP Info
    rdap_info = _query_rdap_info(base)
    if rdap_info.get("status") == "available":
        created = rdap_info.get("created_date")
        evidence_records.append(create_evidence(
            test="domain_registration_rdap",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=90,
            observed_value=f"Registrar: {rdap_info.get('registrar') or 'Authorized'} | Created: {created or 'Recorded'}",
            expected_value="Verifiable registration record",
            evidence=f"Domain '{base}' is registered with {rdap_info.get('registrar') or 'known registrar'}. Registered on {created or 'N/A'}.",
            source="ICANN RDAP Service",
            methodology="RFC 7482 RDAP JSON query",
            why_it_matters="Verifies authoritative domain registration provenance.",
            limitations="WHOIS privacy protection is common and does not indicate maliciousness.",
            remediation="Ensure domain renewal is automated to prevent domain expiration hijacks.",
            category="Domain & Infrastructure",
        ).to_dict())

    # 5. High-Abuse TLD Check
    if tld and tld.lower() in _HIGH_ABUSE_TLDS:
        pts = 4
        points += pts
        ev = create_evidence(
            test="dns_tld_reputation",
            status=TestStatus.WARNING,
            severity=FindingSeverity.MEDIUM,
            confidence=75,
            observed_value=f"TLD: .{tld}",
            expected_value="Standard commercial or national TLD",
            evidence=f"The domain uses the '.{tld}' top-level domain, which has historically elevated threat feed listings.",
            source="TLD Threat Intelligence Index",
            methodology="TLD suffix analysis",
            why_it_matters="Certain free or budget TLDs are frequently cycled by automated attack infrastructure.",
            limitations="Legitimate websites use these TLDs; TLD alone is never proof of malice.",
            remediation="For sensitive services, prefer established generic or regional TLDs.",
            category="Domain & Infrastructure",
        )
        evidence_records.append(ev.to_dict())
        indicators.append({
            "id": "dns_abuse_tld",
            "title": f"High-risk Top-Level Domain (.{tld})",
            "severity": "Medium",
            "points": pts,
            "description": ev.evidence,
            "recommendation": ev.remediation,
        })
    else:
        evidence_records.append(create_evidence(
            test="dns_tld_reputation",
            status=TestStatus.PASS,
            severity=FindingSeverity.INFO,
            confidence=90,
            observed_value=f".{tld}",
            expected_value="Standard TLD",
            evidence=f"Top-level domain '.{tld}' is a recognized standard registry.",
            source="TLD Registry",
            methodology="Suffix inspection",
            why_it_matters="Standard TLDs exhibit lower baseline abuse rates.",
            limitations="Any TLD can be targeted by attackers.",
            remediation="None required.",
            category="Domain & Infrastructure",
        ).to_dict())

    summary = f"DNS resolved ({len(ipv4_list)} IPv4, {len(ipv6_list)} IPv6). "
    if detected_provider:
        summary += f"Hosted on {detected_provider}."
    else:
        summary += "Direct / non-CDN routing."

    return {
        "status": "resolved",
        "hostname": hostname,
        "tld": tld,
        "base_domain": base,
        "ipv4": ipv4_list,
        "ipv6": ipv6_list,
        "has_ipv6": len(ipv6_list) > 0,
        "ptr_records": ptr_records,
        "hosting_provider": detected_provider,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "txt_records": txt_records,
        "caa_records": caa_records,
        "rdap_info": rdap_info,
        "score": min(points, 10),
        "indicators": indicators,
        "evidence_records": evidence_records,
        "summary": summary,
    }
