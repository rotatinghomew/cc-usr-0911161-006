from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

@dataclass(frozen=True)
class DomainSignal:
    code: str
    score: float
    severity: str
    evidence: dict[str, Any]

def number(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    try:
        value = float(payload.get(key, default))
    except (TypeError, ValueError):
        return default
    return default if value != value or value in (float('inf'), float('-inf')) else value

def ratio(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = number(payload, key, default)
    if value > 1.0:
        value /= 100.0
    return max(0.0, min(1.0, value))

def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

def permit_risk(payload: Mapping[str, Any]) -> DomainSignal:
    sensitive = ratio(payload, 'sensitive_share')
    missing = ratio(payload, 'missing_rate')
    protection = ratio(payload, 'protection_strength')
    audit = ratio(payload, 'audit_coverage')
    incidents = min(1.0, number(payload, 'incident_count') / 10.0)
    sample = max(0.0, number(payload, 'sample_size'))
    authorization = str(payload.get('authorization_scope', '')).strip()
    purpose = str(payload.get('purpose_code', '')).strip()
    small_group = 1.0 if sample < 25 else 0.0
    scope_mismatch = 1.0 if not authorization or not purpose else 0.0
    risk = clamp(sensitive*0.24 + missing*0.12 + (1-protection)*0.22 + (1-audit)*0.16 + incidents*0.14 + small_group*0.08 + scope_mismatch*0.04)
    severity = 'critical' if risk >= 0.68 or scope_mismatch else 'warning' if risk >= 0.38 else 'info'
    return DomainSignal('permit_risk', risk, severity, {'sensitive_share': sensitive, 'small_group': bool(small_group), 'scope_mismatch': bool(scope_mismatch), 'incident_pressure': incidents})

def peer_distribution(records: Iterable[Any], group_field: str = 'data_space') -> dict[str, Any]:
    risks = [permit_risk(getattr(r, 'payload', r)).score for r in records]
    return {'count': len(risks), 'high_risk': sum(v >= 0.68 for v in risks), 'average_risk': sum(risks)/len(risks) if risks else 0.0, 'risk_budget': sum(risks)}

def augment_context(record: Any, repository: Any) -> dict[str, Any]:
    signal = permit_risk(record.payload); peers = peer_distribution(repository.list_records())
    return {'domain_signal': signal.score, 'domain_severity': signal.severity, 'high_risk_permits': peers['high_risk'], 'risk_budget': peers['risk_budget']}
