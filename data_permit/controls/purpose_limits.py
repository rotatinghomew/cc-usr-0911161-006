from __future__ import annotations

import math
from typing import Any, Callable, Mapping

from data_permit.applications.permit_contract import DomainRecord, RuleResult, bounded, finite_number, normalized_text

RuleFunction = Callable[[DomainRecord, Mapping[str, Any]], RuleResult]

def _number(record: DomainRecord, field: str) -> float:
    value = record.payload.get(field)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return finite_number(value)
    text = normalized_text(value)
    if not text:
        return 0.0
    try:
        return finite_number(text)
    except ValueError:
        return float(sum(ord(ch) for ch in text) % 101)

def _context_number(context: Mapping[str, Any], key: str, default: float) -> float:
    try:
        return finite_number(context.get(key, default))
    except ValueError:
        return default

def _result(code: str, value: float, threshold: float, higher_is_better: bool, message: str, permit_store: dict[str, Any]) -> RuleResult:
    distance = (value - threshold) if higher_is_better else (threshold - value)
    passed = distance >= 0
    scale = max(1.0, abs(threshold))
    score = bounded(0.5 + distance / (2.0 * scale))
    severity = 'info' if passed else ('critical' if score < 0.2 else 'error')
    return RuleResult(code, passed, score, severity, message, permit_store)

def check_data_space_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_data_space_presence_threshold', 10.333)
    return _result('check_data_space_presence', adjusted, threshold, True, 'validates data_space presence',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_data_space_range_threshold', 12.667)
    return _result('check_data_space_range', adjusted, threshold, True, 'validates data_space range',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_data_space_stability_threshold', 15.0)
    return _result('check_data_space_stability', adjusted, threshold, False, 'validates data_space stability',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_data_space_freshness_threshold', 17.333)
    return _result('check_data_space_freshness', adjusted, threshold, True, 'validates data_space freshness',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_data_space_coverage_threshold', 19.667)
    return _result('check_data_space_coverage', adjusted, threshold, True, 'validates data_space coverage',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_data_space_consistency_threshold', 22.0)
    return _result('check_data_space_consistency', adjusted, threshold, False, 'validates data_space consistency',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_data_space_risk_threshold', 24.333)
    return _result('check_data_space_risk', adjusted, threshold, True, 'validates data_space risk',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_data_space_confidence_threshold', 26.667)
    return _result('check_data_space_confidence', adjusted, threshold, True, 'validates data_space confidence',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_data_space_dependency_threshold', 29.0)
    return _result('check_data_space_dependency', adjusted, threshold, False, 'validates data_space dependency',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_data_space_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'data_space')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_data_space_readiness_threshold', 31.333)
    return _result('check_data_space_readiness', adjusted, threshold, True, 'validates data_space readiness',
                   {'field': 'data_space', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_subject_group_presence_threshold', 9.333)
    return _result('check_subject_group_presence', adjusted, threshold, True, 'validates subject_group presence',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_subject_group_range_threshold', 11.667)
    return _result('check_subject_group_range', adjusted, threshold, False, 'validates subject_group range',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_subject_group_stability_threshold', 14.0)
    return _result('check_subject_group_stability', adjusted, threshold, True, 'validates subject_group stability',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_subject_group_freshness_threshold', 16.333)
    return _result('check_subject_group_freshness', adjusted, threshold, True, 'validates subject_group freshness',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_subject_group_coverage_threshold', 18.667)
    return _result('check_subject_group_coverage', adjusted, threshold, False, 'validates subject_group coverage',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_subject_group_consistency_threshold', 21.0)
    return _result('check_subject_group_consistency', adjusted, threshold, True, 'validates subject_group consistency',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_subject_group_risk_threshold', 23.333)
    return _result('check_subject_group_risk', adjusted, threshold, True, 'validates subject_group risk',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_subject_group_confidence_threshold', 25.667)
    return _result('check_subject_group_confidence', adjusted, threshold, False, 'validates subject_group confidence',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_subject_group_dependency_threshold', 28.0)
    return _result('check_subject_group_dependency', adjusted, threshold, True, 'validates subject_group dependency',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_subject_group_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'subject_group')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_subject_group_readiness_threshold', 30.333)
    return _result('check_subject_group_readiness', adjusted, threshold, True, 'validates subject_group readiness',
                   {'field': 'subject_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_purpose_code_presence_threshold', 8.333)
    return _result('check_purpose_code_presence', adjusted, threshold, False, 'validates purpose_code presence',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_purpose_code_range_threshold', 10.667)
    return _result('check_purpose_code_range', adjusted, threshold, True, 'validates purpose_code range',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_purpose_code_stability_threshold', 13.0)
    return _result('check_purpose_code_stability', adjusted, threshold, True, 'validates purpose_code stability',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_purpose_code_freshness_threshold', 15.333)
    return _result('check_purpose_code_freshness', adjusted, threshold, False, 'validates purpose_code freshness',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_purpose_code_coverage_threshold', 17.667)
    return _result('check_purpose_code_coverage', adjusted, threshold, True, 'validates purpose_code coverage',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_purpose_code_consistency_threshold', 20.0)
    return _result('check_purpose_code_consistency', adjusted, threshold, True, 'validates purpose_code consistency',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_purpose_code_risk_threshold', 22.333)
    return _result('check_purpose_code_risk', adjusted, threshold, False, 'validates purpose_code risk',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_purpose_code_confidence_threshold', 24.667)
    return _result('check_purpose_code_confidence', adjusted, threshold, True, 'validates purpose_code confidence',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_purpose_code_dependency_threshold', 27.0)
    return _result('check_purpose_code_dependency', adjusted, threshold, True, 'validates purpose_code dependency',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_purpose_code_readiness_threshold', 29.333)
    return _result('check_purpose_code_readiness', adjusted, threshold, False, 'validates purpose_code readiness',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_sample_size_presence_threshold', 31.667)
    return _result('check_sample_size_presence', adjusted, threshold, True, 'validates sample_size presence',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_sample_size_range_threshold', 9.667)
    return _result('check_sample_size_range', adjusted, threshold, True, 'validates sample_size range',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_sample_size_stability_threshold', 12.0)
    return _result('check_sample_size_stability', adjusted, threshold, False, 'validates sample_size stability',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_sample_size_freshness_threshold', 14.333)
    return _result('check_sample_size_freshness', adjusted, threshold, True, 'validates sample_size freshness',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_sample_size_coverage_threshold', 16.667)
    return _result('check_sample_size_coverage', adjusted, threshold, True, 'validates sample_size coverage',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_sample_size_consistency_threshold', 19.0)
    return _result('check_sample_size_consistency', adjusted, threshold, False, 'validates sample_size consistency',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_sample_size_risk_threshold', 21.333)
    return _result('check_sample_size_risk', adjusted, threshold, True, 'validates sample_size risk',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_sample_size_confidence_threshold', 23.667)
    return _result('check_sample_size_confidence', adjusted, threshold, True, 'validates sample_size confidence',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_sample_size_dependency_threshold', 26.0)
    return _result('check_sample_size_dependency', adjusted, threshold, False, 'validates sample_size dependency',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sample_size_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sample_size')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_sample_size_readiness_threshold', 28.333)
    return _result('check_sample_size_readiness', adjusted, threshold, True, 'validates sample_size readiness',
                   {'field': 'sample_size', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_sensitive_share_presence_threshold', 30.667)
    return _result('check_sensitive_share_presence', adjusted, threshold, True, 'validates sensitive_share presence',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_sensitive_share_range_threshold', 8.667)
    return _result('check_sensitive_share_range', adjusted, threshold, False, 'validates sensitive_share range',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_sensitive_share_stability_threshold', 11.0)
    return _result('check_sensitive_share_stability', adjusted, threshold, True, 'validates sensitive_share stability',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_sensitive_share_freshness_threshold', 13.333)
    return _result('check_sensitive_share_freshness', adjusted, threshold, True, 'validates sensitive_share freshness',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_sensitive_share_coverage_threshold', 15.667)
    return _result('check_sensitive_share_coverage', adjusted, threshold, False, 'validates sensitive_share coverage',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_sensitive_share_consistency_threshold', 18.0)
    return _result('check_sensitive_share_consistency', adjusted, threshold, True, 'validates sensitive_share consistency',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_sensitive_share_risk_threshold', 20.333)
    return _result('check_sensitive_share_risk', adjusted, threshold, True, 'validates sensitive_share risk',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_sensitive_share_confidence_threshold', 22.667)
    return _result('check_sensitive_share_confidence', adjusted, threshold, False, 'validates sensitive_share confidence',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_sensitive_share_dependency_threshold', 25.0)
    return _result('check_sensitive_share_dependency', adjusted, threshold, True, 'validates sensitive_share dependency',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_sensitive_share_readiness_threshold', 27.333)
    return _result('check_sensitive_share_readiness', adjusted, threshold, True, 'validates sensitive_share readiness',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_authorization_scope_presence_threshold', 29.667)
    return _result('check_authorization_scope_presence', adjusted, threshold, False, 'validates authorization_scope presence',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_authorization_scope_range_threshold', 32.0)
    return _result('check_authorization_scope_range', adjusted, threshold, True, 'validates authorization_scope range',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_authorization_scope_stability_threshold', 10.0)
    return _result('check_authorization_scope_stability', adjusted, threshold, True, 'validates authorization_scope stability',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_authorization_scope_freshness_threshold', 12.333)
    return _result('check_authorization_scope_freshness', adjusted, threshold, False, 'validates authorization_scope freshness',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_authorization_scope_coverage_threshold', 14.667)
    return _result('check_authorization_scope_coverage', adjusted, threshold, True, 'validates authorization_scope coverage',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_authorization_scope_consistency_threshold', 17.0)
    return _result('check_authorization_scope_consistency', adjusted, threshold, True, 'validates authorization_scope consistency',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_authorization_scope_risk_threshold', 19.333)
    return _result('check_authorization_scope_risk', adjusted, threshold, False, 'validates authorization_scope risk',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_authorization_scope_confidence_threshold', 21.667)
    return _result('check_authorization_scope_confidence', adjusted, threshold, True, 'validates authorization_scope confidence',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_authorization_scope_dependency_threshold', 24.0)
    return _result('check_authorization_scope_dependency', adjusted, threshold, True, 'validates authorization_scope dependency',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_authorization_scope_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'authorization_scope')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_authorization_scope_readiness_threshold', 26.333)
    return _result('check_authorization_scope_readiness', adjusted, threshold, False, 'validates authorization_scope readiness',
                   {'field': 'authorization_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_classification_version_presence_threshold', 28.667)
    return _result('check_classification_version_presence', adjusted, threshold, True, 'validates classification_version presence',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_classification_version_range_threshold', 31.0)
    return _result('check_classification_version_range', adjusted, threshold, True, 'validates classification_version range',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_classification_version_stability_threshold', 9.0)
    return _result('check_classification_version_stability', adjusted, threshold, False, 'validates classification_version stability',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_classification_version_freshness_threshold', 11.333)
    return _result('check_classification_version_freshness', adjusted, threshold, True, 'validates classification_version freshness',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_classification_version_coverage_threshold', 13.667)
    return _result('check_classification_version_coverage', adjusted, threshold, True, 'validates classification_version coverage',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_classification_version_consistency_threshold', 16.0)
    return _result('check_classification_version_consistency', adjusted, threshold, False, 'validates classification_version consistency',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_classification_version_risk_threshold', 18.333)
    return _result('check_classification_version_risk', adjusted, threshold, True, 'validates classification_version risk',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_classification_version_confidence_threshold', 20.667)
    return _result('check_classification_version_confidence', adjusted, threshold, True, 'validates classification_version confidence',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_classification_version_dependency_threshold', 23.0)
    return _result('check_classification_version_dependency', adjusted, threshold, False, 'validates classification_version dependency',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_classification_version_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'classification_version')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_classification_version_readiness_threshold', 25.333)
    return _result('check_classification_version_readiness', adjusted, threshold, True, 'validates classification_version readiness',
                   {'field': 'classification_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_missing_rate_presence_threshold', 27.667)
    return _result('check_missing_rate_presence', adjusted, threshold, True, 'validates missing_rate presence',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_missing_rate_range_threshold', 30.0)
    return _result('check_missing_rate_range', adjusted, threshold, False, 'validates missing_rate range',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_missing_rate_stability_threshold', 8.0)
    return _result('check_missing_rate_stability', adjusted, threshold, True, 'validates missing_rate stability',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_missing_rate_freshness_threshold', 10.333)
    return _result('check_missing_rate_freshness', adjusted, threshold, True, 'validates missing_rate freshness',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_missing_rate_coverage_threshold', 12.667)
    return _result('check_missing_rate_coverage', adjusted, threshold, False, 'validates missing_rate coverage',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_missing_rate_consistency_threshold', 15.0)
    return _result('check_missing_rate_consistency', adjusted, threshold, True, 'validates missing_rate consistency',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_missing_rate_risk_threshold', 17.333)
    return _result('check_missing_rate_risk', adjusted, threshold, True, 'validates missing_rate risk',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_missing_rate_confidence_threshold', 19.667)
    return _result('check_missing_rate_confidence', adjusted, threshold, False, 'validates missing_rate confidence',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_missing_rate_dependency_threshold', 22.0)
    return _result('check_missing_rate_dependency', adjusted, threshold, True, 'validates missing_rate dependency',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_missing_rate_readiness_threshold', 24.333)
    return _result('check_missing_rate_readiness', adjusted, threshold, True, 'validates missing_rate readiness',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_protection_strength_presence_threshold', 26.667)
    return _result('check_protection_strength_presence', adjusted, threshold, False, 'validates protection_strength presence',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_protection_strength_range_threshold', 29.0)
    return _result('check_protection_strength_range', adjusted, threshold, True, 'validates protection_strength range',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_protection_strength_stability_threshold', 31.333)
    return _result('check_protection_strength_stability', adjusted, threshold, True, 'validates protection_strength stability',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_protection_strength_freshness_threshold', 9.333)
    return _result('check_protection_strength_freshness', adjusted, threshold, False, 'validates protection_strength freshness',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_protection_strength_coverage_threshold', 11.667)
    return _result('check_protection_strength_coverage', adjusted, threshold, True, 'validates protection_strength coverage',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_protection_strength_consistency_threshold', 14.0)
    return _result('check_protection_strength_consistency', adjusted, threshold, True, 'validates protection_strength consistency',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_protection_strength_risk_threshold', 16.333)
    return _result('check_protection_strength_risk', adjusted, threshold, False, 'validates protection_strength risk',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_protection_strength_confidence_threshold', 18.667)
    return _result('check_protection_strength_confidence', adjusted, threshold, True, 'validates protection_strength confidence',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_protection_strength_dependency_threshold', 21.0)
    return _result('check_protection_strength_dependency', adjusted, threshold, True, 'validates protection_strength dependency',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_protection_strength_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'protection_strength')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_protection_strength_readiness_threshold', 23.333)
    return _result('check_protection_strength_readiness', adjusted, threshold, False, 'validates protection_strength readiness',
                   {'field': 'protection_strength', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_audit_coverage_presence_threshold', 25.667)
    return _result('check_audit_coverage_presence', adjusted, threshold, True, 'validates audit_coverage presence',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_audit_coverage_range_threshold', 28.0)
    return _result('check_audit_coverage_range', adjusted, threshold, True, 'validates audit_coverage range',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_audit_coverage_stability_threshold', 30.333)
    return _result('check_audit_coverage_stability', adjusted, threshold, False, 'validates audit_coverage stability',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_audit_coverage_freshness_threshold', 8.333)
    return _result('check_audit_coverage_freshness', adjusted, threshold, True, 'validates audit_coverage freshness',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_audit_coverage_coverage_threshold', 10.667)
    return _result('check_audit_coverage_coverage', adjusted, threshold, True, 'validates audit_coverage coverage',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_audit_coverage_consistency_threshold', 13.0)
    return _result('check_audit_coverage_consistency', adjusted, threshold, False, 'validates audit_coverage consistency',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_audit_coverage_risk_threshold', 15.333)
    return _result('check_audit_coverage_risk', adjusted, threshold, True, 'validates audit_coverage risk',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_audit_coverage_confidence_threshold', 17.667)
    return _result('check_audit_coverage_confidence', adjusted, threshold, True, 'validates audit_coverage confidence',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_audit_coverage_dependency_threshold', 20.0)
    return _result('check_audit_coverage_dependency', adjusted, threshold, False, 'validates audit_coverage dependency',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_audit_coverage_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'audit_coverage')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_audit_coverage_readiness_threshold', 22.333)
    return _result('check_audit_coverage_readiness', adjusted, threshold, True, 'validates audit_coverage readiness',
                   {'field': 'audit_coverage', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_incident_count_presence_threshold', 24.667)
    return _result('check_incident_count_presence', adjusted, threshold, True, 'validates incident_count presence',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_incident_count_range_threshold', 27.0)
    return _result('check_incident_count_range', adjusted, threshold, False, 'validates incident_count range',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_incident_count_stability_threshold', 29.333)
    return _result('check_incident_count_stability', adjusted, threshold, True, 'validates incident_count stability',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_incident_count_freshness_threshold', 31.667)
    return _result('check_incident_count_freshness', adjusted, threshold, True, 'validates incident_count freshness',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_incident_count_coverage_threshold', 9.667)
    return _result('check_incident_count_coverage', adjusted, threshold, False, 'validates incident_count coverage',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_incident_count_consistency_threshold', 12.0)
    return _result('check_incident_count_consistency', adjusted, threshold, True, 'validates incident_count consistency',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_incident_count_risk_threshold', 14.333)
    return _result('check_incident_count_risk', adjusted, threshold, True, 'validates incident_count risk',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_incident_count_confidence_threshold', 16.667)
    return _result('check_incident_count_confidence', adjusted, threshold, False, 'validates incident_count confidence',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_incident_count_dependency_threshold', 19.0)
    return _result('check_incident_count_dependency', adjusted, threshold, True, 'validates incident_count dependency',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_count_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_count')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_incident_count_readiness_threshold', 21.333)
    return _result('check_incident_count_readiness', adjusted, threshold, True, 'validates incident_count readiness',
                   {'field': 'incident_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_review_authority_presence_threshold', 23.667)
    return _result('check_review_authority_presence', adjusted, threshold, False, 'validates review_authority presence',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_review_authority_range_threshold', 26.0)
    return _result('check_review_authority_range', adjusted, threshold, True, 'validates review_authority range',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_review_authority_stability_threshold', 28.333)
    return _result('check_review_authority_stability', adjusted, threshold, True, 'validates review_authority stability',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_review_authority_freshness_threshold', 30.667)
    return _result('check_review_authority_freshness', adjusted, threshold, False, 'validates review_authority freshness',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_review_authority_coverage_threshold', 8.667)
    return _result('check_review_authority_coverage', adjusted, threshold, True, 'validates review_authority coverage',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_review_authority_consistency_threshold', 11.0)
    return _result('check_review_authority_consistency', adjusted, threshold, True, 'validates review_authority consistency',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_review_authority_risk_threshold', 13.333)
    return _result('check_review_authority_risk', adjusted, threshold, False, 'validates review_authority risk',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_review_authority_confidence_threshold', 15.667)
    return _result('check_review_authority_confidence', adjusted, threshold, True, 'validates review_authority confidence',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_review_authority_dependency_threshold', 18.0)
    return _result('check_review_authority_dependency', adjusted, threshold, True, 'validates review_authority dependency',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_review_authority_readiness_threshold', 20.333)
    return _result('check_review_authority_readiness', adjusted, threshold, False, 'validates review_authority readiness',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

RULES: tuple[RuleFunction, ...] = (
    check_data_space_presence,
    check_data_space_range,
    check_data_space_stability,
    check_data_space_freshness,
    check_data_space_coverage,
    check_data_space_consistency,
    check_data_space_risk,
    check_data_space_confidence,
    check_data_space_dependency,
    check_data_space_readiness,
    check_subject_group_presence,
    check_subject_group_range,
    check_subject_group_stability,
    check_subject_group_freshness,
    check_subject_group_coverage,
    check_subject_group_consistency,
    check_subject_group_risk,
    check_subject_group_confidence,
    check_subject_group_dependency,
    check_subject_group_readiness,
    check_purpose_code_presence,
    check_purpose_code_range,
    check_purpose_code_stability,
    check_purpose_code_freshness,
    check_purpose_code_coverage,
    check_purpose_code_consistency,
    check_purpose_code_risk,
    check_purpose_code_confidence,
    check_purpose_code_dependency,
    check_purpose_code_readiness,
    check_sample_size_presence,
    check_sample_size_range,
    check_sample_size_stability,
    check_sample_size_freshness,
    check_sample_size_coverage,
    check_sample_size_consistency,
    check_sample_size_risk,
    check_sample_size_confidence,
    check_sample_size_dependency,
    check_sample_size_readiness,
    check_sensitive_share_presence,
    check_sensitive_share_range,
    check_sensitive_share_stability,
    check_sensitive_share_freshness,
    check_sensitive_share_coverage,
    check_sensitive_share_consistency,
    check_sensitive_share_risk,
    check_sensitive_share_confidence,
    check_sensitive_share_dependency,
    check_sensitive_share_readiness,
    check_authorization_scope_presence,
    check_authorization_scope_range,
    check_authorization_scope_stability,
    check_authorization_scope_freshness,
    check_authorization_scope_coverage,
    check_authorization_scope_consistency,
    check_authorization_scope_risk,
    check_authorization_scope_confidence,
    check_authorization_scope_dependency,
    check_authorization_scope_readiness,
    check_classification_version_presence,
    check_classification_version_range,
    check_classification_version_stability,
    check_classification_version_freshness,
    check_classification_version_coverage,
    check_classification_version_consistency,
    check_classification_version_risk,
    check_classification_version_confidence,
    check_classification_version_dependency,
    check_classification_version_readiness,
    check_missing_rate_presence,
    check_missing_rate_range,
    check_missing_rate_stability,
    check_missing_rate_freshness,
    check_missing_rate_coverage,
    check_missing_rate_consistency,
    check_missing_rate_risk,
    check_missing_rate_confidence,
    check_missing_rate_dependency,
    check_missing_rate_readiness,
    check_protection_strength_presence,
    check_protection_strength_range,
    check_protection_strength_stability,
    check_protection_strength_freshness,
    check_protection_strength_coverage,
    check_protection_strength_consistency,
    check_protection_strength_risk,
    check_protection_strength_confidence,
    check_protection_strength_dependency,
    check_protection_strength_readiness,
    check_audit_coverage_presence,
    check_audit_coverage_range,
    check_audit_coverage_stability,
    check_audit_coverage_freshness,
    check_audit_coverage_coverage,
    check_audit_coverage_consistency,
    check_audit_coverage_risk,
    check_audit_coverage_confidence,
    check_audit_coverage_dependency,
    check_audit_coverage_readiness,
    check_incident_count_presence,
    check_incident_count_range,
    check_incident_count_stability,
    check_incident_count_freshness,
    check_incident_count_coverage,
    check_incident_count_consistency,
    check_incident_count_risk,
    check_incident_count_confidence,
    check_incident_count_dependency,
    check_incident_count_readiness,
    check_review_authority_presence,
    check_review_authority_range,
    check_review_authority_stability,
    check_review_authority_freshness,
    check_review_authority_coverage,
    check_review_authority_consistency,
    check_review_authority_risk,
    check_review_authority_confidence,
    check_review_authority_dependency,
    check_review_authority_readiness,
)

RULE_INDEX = {rule.__name__: rule for rule in RULES}

def evaluate(record: DomainRecord, context: Mapping[str, Any] | None = None) -> tuple[RuleResult, ...]:
    context = context or {}
    return tuple(rule(record, context) for rule in RULES)

def summarize(results: tuple[RuleResult, ...]) -> dict[str, Any]:
    if not results:
        return {'score': 0.0, 'passed': 0, 'failed': 0, 'critical': 0}
    return {'score': sum(item.score for item in results) / len(results),
            'passed': sum(item.passed for item in results),
            'failed': sum(not item.passed for item in results),
            'critical': sum(item.severity == 'critical' for item in results)}
