"""
services/evidence.py
~~~~~~~~~~~~~~~~~~~~
Evidence-First Architecture for AEGOVX Security Scanner.
Defines structured evidence models, test status classifications,
and evidence chain serialization.

Rules:
  - NEVER create a finding without evidence.
  - NEVER fabricate evidence.
  - NEVER convert an API error into a clean result or a malicious result.
  - NEVER treat NOT_TESTABLE or NOT_CONFIGURED as FAIL.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TestStatus(str, Enum):
    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_TESTABLE = "NOT_TESTABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EvidenceRecord:
    """
    Structured evidence object representing the verifiable result of a single security test.
    """
    test: str
    status: str                         # PASS | FAIL | WARNING | NOT_TESTABLE | NOT_CONFIGURED | NOT_APPLICABLE
    severity: str                       # INFO | LOW | MEDIUM | HIGH | CRITICAL
    confidence: int                     # 0 - 100
    observed_value: str
    expected_value: str
    evidence: str
    source: str
    methodology: str
    why_it_matters: str
    limitations: str
    remediation: str
    category: str                       # e.g., "Security Headers", "TLS / HTTPS", "Threat Intelligence"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Return dict with both snake_case and camelCase keys for API/frontend compatibility."""
        data = asdict(self)
        data["observedValue"] = self.observed_value
        data["expectedValue"] = self.expected_value
        data["whyItMatters"] = self.why_it_matters
        return data


def create_evidence(
    test: str,
    status: str | TestStatus,
    severity: str | FindingSeverity,
    confidence: int,
    observed_value: str,
    expected_value: str,
    evidence: str,
    source: str,
    methodology: str,
    why_it_matters: str,
    limitations: str,
    remediation: str,
    category: str,
) -> EvidenceRecord:
    """Factory function to build a validated EvidenceRecord."""
    st = status.value if isinstance(status, TestStatus) else str(status).upper()
    sev = severity.value if isinstance(severity, FindingSeverity) else str(severity).upper()

    valid_statuses = {s.value for s in TestStatus}
    if st not in valid_statuses:
        st = TestStatus.WARNING.value

    valid_severities = {s.value for s in FindingSeverity}
    if sev not in valid_severities:
        sev = FindingSeverity.LOW.value

    conf = max(0, min(100, int(confidence)))

    return EvidenceRecord(
        test=test,
        status=st,
        severity=sev,
        confidence=conf,
        observed_value=str(observed_value) if observed_value is not None else "None",
        expected_value=str(expected_value),
        evidence=str(evidence),
        source=str(source),
        methodology=str(methodology),
        why_it_matters=str(why_it_matters),
        limitations=str(limitations),
        remediation=str(remediation),
        category=str(category),
    )
