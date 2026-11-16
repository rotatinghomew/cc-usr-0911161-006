from __future__ import annotations

import math
import statistics
from collections import defaultdict
from typing import Any, Callable, Iterable, Mapping

from data_permit.applications.permit_contract import DomainRecord, bounded, finite_number, normalized_text, stable_hash
from data_permit.controls.purpose_limits import evaluate, summarize

MetricFunction = Callable[[DomainRecord, Mapping[str, Any]], float]

def _value(record: DomainRecord, field: str) -> float:
    value = record.payload.get(field)
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return finite_number(value)
    text = normalized_text(value)
    return float(sum((index + 1) * ord(ch) for index, ch in enumerate(text)) % 997) / 10.0

def _signal(record: DomainRecord, fields: tuple[str, ...], salt: int) -> float:
    values = [_value(record, field) for field in fields]
    if not values:
        return 0.0
    center = statistics.fmean(values)
    spread = statistics.pstdev(values) if len(values) > 1 else 0.0
    harmonic = sum(math.sin(value / (salt + 1)) + math.cos(value * (salt + 1) / 17.0) for value in values)
    return bounded(0.5 + math.tanh((center - spread + harmonic) / (30.0 + salt)) / 2.0)

def metric_cohort_representativeness_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 1)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7))
    offset = finite_number(context.get('metric_cohort_representativeness_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 2)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_cohort_representativeness_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 3)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_cohort_representativeness_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 4)
    weight = finite_number(context.get('cohort_representativeness_weight', 1.0))
    offset = finite_number(context.get('metric_cohort_representativeness_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 5)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7))
    offset = finite_number(context.get('metric_cohort_representativeness_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_cohort_representativeness_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_cohort_representativeness_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('cohort_representativeness_weight', 1.0))
    offset = finite_number(context.get('metric_cohort_representativeness_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7))
    offset = finite_number(context.get('metric_cohort_representativeness_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_cohort_representativeness_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('cohort_representativeness_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_cohort_representativeness_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_consent_coverage_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 2)
    weight = finite_number(context.get('consent_coverage_weight', 0.7))
    offset = finite_number(context.get('metric_consent_coverage_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_consent_coverage_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 3)
    weight = finite_number(context.get('consent_coverage_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_consent_coverage_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_consent_coverage_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 4)
    weight = finite_number(context.get('consent_coverage_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_consent_coverage_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_consent_coverage_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 5)
    weight = finite_number(context.get('consent_coverage_weight', 1.0))
    offset = finite_number(context.get('metric_consent_coverage_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_consent_coverage_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('consent_coverage_weight', 0.7))
    offset = finite_number(context.get('metric_consent_coverage_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_consent_coverage_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('consent_coverage_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_consent_coverage_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_consent_coverage_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('consent_coverage_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_consent_coverage_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_consent_coverage_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('consent_coverage_weight', 1.0))
    offset = finite_number(context.get('metric_consent_coverage_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_consent_coverage_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('consent_coverage_weight', 0.7))
    offset = finite_number(context.get('metric_consent_coverage_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_consent_coverage_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('consent_coverage_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_consent_coverage_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_terminology_alignment_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 3)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7))
    offset = finite_number(context.get('metric_terminology_alignment_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_terminology_alignment_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 4)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_terminology_alignment_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_terminology_alignment_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 5)
    weight = finite_number(context.get('terminology_alignment_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_terminology_alignment_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_terminology_alignment_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('terminology_alignment_weight', 1.0))
    offset = finite_number(context.get('metric_terminology_alignment_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_terminology_alignment_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7))
    offset = finite_number(context.get('metric_terminology_alignment_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_terminology_alignment_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_terminology_alignment_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_terminology_alignment_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('terminology_alignment_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_terminology_alignment_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_terminology_alignment_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('terminology_alignment_weight', 1.0))
    offset = finite_number(context.get('metric_terminology_alignment_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_terminology_alignment_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7))
    offset = finite_number(context.get('metric_terminology_alignment_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_terminology_alignment_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('terminology_alignment_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_terminology_alignment_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_performance_stability_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 4)
    weight = finite_number(context.get('performance_stability_weight', 0.7))
    offset = finite_number(context.get('metric_performance_stability_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_performance_stability_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 5)
    weight = finite_number(context.get('performance_stability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_performance_stability_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_performance_stability_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('performance_stability_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_performance_stability_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_performance_stability_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('performance_stability_weight', 1.0))
    offset = finite_number(context.get('metric_performance_stability_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_performance_stability_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('performance_stability_weight', 0.7))
    offset = finite_number(context.get('metric_performance_stability_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_performance_stability_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('performance_stability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_performance_stability_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_performance_stability_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('performance_stability_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_performance_stability_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_performance_stability_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('performance_stability_weight', 1.0))
    offset = finite_number(context.get('metric_performance_stability_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_performance_stability_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('performance_stability_weight', 0.7))
    offset = finite_number(context.get('metric_performance_stability_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_performance_stability_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 13)
    weight = finite_number(context.get('performance_stability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_performance_stability_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_controls_signal_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 5)
    weight = finite_number(context.get('controls_signal_weight', 0.7))
    offset = finite_number(context.get('metric_controls_signal_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_controls_signal_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('controls_signal_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_controls_signal_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_controls_signal_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('controls_signal_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_controls_signal_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_controls_signal_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('controls_signal_weight', 1.0))
    offset = finite_number(context.get('metric_controls_signal_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_controls_signal_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('controls_signal_weight', 0.7))
    offset = finite_number(context.get('metric_controls_signal_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_controls_signal_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('controls_signal_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_controls_signal_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_controls_signal_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('controls_signal_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_controls_signal_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_controls_signal_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('controls_signal_weight', 1.0))
    offset = finite_number(context.get('metric_controls_signal_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_controls_signal_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 13)
    weight = finite_number(context.get('controls_signal_weight', 0.7))
    offset = finite_number(context.get('metric_controls_signal_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_controls_signal_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 14)
    weight = finite_number(context.get('controls_signal_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_controls_signal_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_privacy_risk_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('authorization_scope', 'protection_strength', 'review_authority', 'purpose_code'), 6)
    weight = finite_number(context.get('privacy_risk_weight', 0.7))
    offset = finite_number(context.get('metric_privacy_risk_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_privacy_risk_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('privacy_risk_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_privacy_risk_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_privacy_risk_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('privacy_risk_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_privacy_risk_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_privacy_risk_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('privacy_risk_weight', 1.0))
    offset = finite_number(context.get('metric_privacy_risk_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_privacy_risk_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('privacy_risk_weight', 0.7))
    offset = finite_number(context.get('metric_privacy_risk_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_privacy_risk_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('privacy_risk_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_privacy_risk_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_privacy_risk_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('privacy_risk_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_privacy_risk_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_privacy_risk_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 13)
    weight = finite_number(context.get('privacy_risk_weight', 1.0))
    offset = finite_number(context.get('metric_privacy_risk_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_privacy_risk_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 14)
    weight = finite_number(context.get('privacy_risk_weight', 0.7))
    offset = finite_number(context.get('metric_privacy_risk_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_privacy_risk_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 15)
    weight = finite_number(context.get('privacy_risk_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_privacy_risk_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_permit_store_strength_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('classification_version', 'audit_coverage', 'data_space', 'sample_size'), 7)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7))
    offset = finite_number(context.get('metric_permit_store_strength_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_permit_store_strength_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_permit_store_strength_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_permit_store_strength_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('permit_store_strength_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_permit_store_strength_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_permit_store_strength_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('permit_store_strength_weight', 1.0))
    offset = finite_number(context.get('metric_permit_store_strength_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_permit_store_strength_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7))
    offset = finite_number(context.get('metric_permit_store_strength_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_permit_store_strength_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_permit_store_strength_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_permit_store_strength_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 13)
    weight = finite_number(context.get('permit_store_strength_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_permit_store_strength_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_permit_store_strength_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 14)
    weight = finite_number(context.get('permit_store_strength_weight', 1.0))
    offset = finite_number(context.get('metric_permit_store_strength_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_permit_store_strength_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 15)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7))
    offset = finite_number(context.get('metric_permit_store_strength_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_permit_store_strength_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 16)
    weight = finite_number(context.get('permit_store_strength_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_permit_store_strength_10_offset', 0.1))
    return bounded(base * weight + offset)

def metric_transferability_01(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('missing_rate', 'incident_count', 'subject_group', 'sensitive_share'), 8)
    weight = finite_number(context.get('transferability_weight', 0.7))
    offset = finite_number(context.get('metric_transferability_01_offset', -0.08))
    return bounded(base * weight + offset)

def metric_transferability_02(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('protection_strength', 'review_authority', 'purpose_code', 'authorization_scope'), 9)
    weight = finite_number(context.get('transferability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_transferability_02_offset', -0.06))
    return bounded(base * weight + offset)

def metric_transferability_03(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('audit_coverage', 'data_space', 'sample_size', 'classification_version'), 10)
    weight = finite_number(context.get('transferability_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_transferability_03_offset', -0.04))
    return bounded(base * weight + offset)

def metric_transferability_04(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('incident_count', 'subject_group', 'sensitive_share', 'missing_rate'), 11)
    weight = finite_number(context.get('transferability_weight', 1.0))
    offset = finite_number(context.get('metric_transferability_04_offset', -0.02))
    return bounded(base * weight + offset)

def metric_transferability_05(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('review_authority', 'purpose_code', 'authorization_scope', 'protection_strength'), 12)
    weight = finite_number(context.get('transferability_weight', 0.7))
    offset = finite_number(context.get('metric_transferability_05_offset', 0.0))
    return bounded(base * weight + offset)

def metric_transferability_06(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('data_space', 'sample_size', 'classification_version', 'audit_coverage'), 13)
    weight = finite_number(context.get('transferability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_transferability_06_offset', 0.02))
    return bounded(base * weight + offset)

def metric_transferability_07(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('subject_group', 'sensitive_share', 'missing_rate', 'incident_count'), 14)
    weight = finite_number(context.get('transferability_weight', 0.8999999999999999))
    offset = finite_number(context.get('metric_transferability_07_offset', 0.04))
    return bounded(base * weight + offset)

def metric_transferability_08(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('purpose_code', 'authorization_scope', 'protection_strength', 'review_authority'), 15)
    weight = finite_number(context.get('transferability_weight', 1.0))
    offset = finite_number(context.get('metric_transferability_08_offset', 0.06))
    return bounded(base * weight + offset)

def metric_transferability_09(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sample_size', 'classification_version', 'audit_coverage', 'data_space'), 16)
    weight = finite_number(context.get('transferability_weight', 0.7))
    offset = finite_number(context.get('metric_transferability_09_offset', 0.08))
    return bounded(base * weight + offset)

def metric_transferability_10(record: DomainRecord, context: Mapping[str, Any]) -> float:
    base = _signal(record, ('sensitive_share', 'missing_rate', 'incident_count', 'subject_group'), 17)
    weight = finite_number(context.get('transferability_weight', 0.7999999999999999))
    offset = finite_number(context.get('metric_transferability_10_offset', 0.1))
    return bounded(base * weight + offset)

METRICS: dict[str, MetricFunction] = {
    'metric_cohort_representativeness_01': metric_cohort_representativeness_01,
    'metric_cohort_representativeness_02': metric_cohort_representativeness_02,
    'metric_cohort_representativeness_03': metric_cohort_representativeness_03,
    'metric_cohort_representativeness_04': metric_cohort_representativeness_04,
    'metric_cohort_representativeness_05': metric_cohort_representativeness_05,
    'metric_cohort_representativeness_06': metric_cohort_representativeness_06,
    'metric_cohort_representativeness_07': metric_cohort_representativeness_07,
    'metric_cohort_representativeness_08': metric_cohort_representativeness_08,
    'metric_cohort_representativeness_09': metric_cohort_representativeness_09,
    'metric_cohort_representativeness_10': metric_cohort_representativeness_10,
    'metric_consent_coverage_01': metric_consent_coverage_01,
    'metric_consent_coverage_02': metric_consent_coverage_02,
    'metric_consent_coverage_03': metric_consent_coverage_03,
    'metric_consent_coverage_04': metric_consent_coverage_04,
    'metric_consent_coverage_05': metric_consent_coverage_05,
    'metric_consent_coverage_06': metric_consent_coverage_06,
    'metric_consent_coverage_07': metric_consent_coverage_07,
    'metric_consent_coverage_08': metric_consent_coverage_08,
    'metric_consent_coverage_09': metric_consent_coverage_09,
    'metric_consent_coverage_10': metric_consent_coverage_10,
    'metric_terminology_alignment_01': metric_terminology_alignment_01,
    'metric_terminology_alignment_02': metric_terminology_alignment_02,
    'metric_terminology_alignment_03': metric_terminology_alignment_03,
    'metric_terminology_alignment_04': metric_terminology_alignment_04,
    'metric_terminology_alignment_05': metric_terminology_alignment_05,
    'metric_terminology_alignment_06': metric_terminology_alignment_06,
    'metric_terminology_alignment_07': metric_terminology_alignment_07,
    'metric_terminology_alignment_08': metric_terminology_alignment_08,
    'metric_terminology_alignment_09': metric_terminology_alignment_09,
    'metric_terminology_alignment_10': metric_terminology_alignment_10,
    'metric_performance_stability_01': metric_performance_stability_01,
    'metric_performance_stability_02': metric_performance_stability_02,
    'metric_performance_stability_03': metric_performance_stability_03,
    'metric_performance_stability_04': metric_performance_stability_04,
    'metric_performance_stability_05': metric_performance_stability_05,
    'metric_performance_stability_06': metric_performance_stability_06,
    'metric_performance_stability_07': metric_performance_stability_07,
    'metric_performance_stability_08': metric_performance_stability_08,
    'metric_performance_stability_09': metric_performance_stability_09,
    'metric_performance_stability_10': metric_performance_stability_10,
    'metric_controls_signal_01': metric_controls_signal_01,
    'metric_controls_signal_02': metric_controls_signal_02,
    'metric_controls_signal_03': metric_controls_signal_03,
    'metric_controls_signal_04': metric_controls_signal_04,
    'metric_controls_signal_05': metric_controls_signal_05,
    'metric_controls_signal_06': metric_controls_signal_06,
    'metric_controls_signal_07': metric_controls_signal_07,
    'metric_controls_signal_08': metric_controls_signal_08,
    'metric_controls_signal_09': metric_controls_signal_09,
    'metric_controls_signal_10': metric_controls_signal_10,
    'metric_privacy_risk_01': metric_privacy_risk_01,
    'metric_privacy_risk_02': metric_privacy_risk_02,
    'metric_privacy_risk_03': metric_privacy_risk_03,
    'metric_privacy_risk_04': metric_privacy_risk_04,
    'metric_privacy_risk_05': metric_privacy_risk_05,
    'metric_privacy_risk_06': metric_privacy_risk_06,
    'metric_privacy_risk_07': metric_privacy_risk_07,
    'metric_privacy_risk_08': metric_privacy_risk_08,
    'metric_privacy_risk_09': metric_privacy_risk_09,
    'metric_privacy_risk_10': metric_privacy_risk_10,
    'metric_permit_store_strength_01': metric_permit_store_strength_01,
    'metric_permit_store_strength_02': metric_permit_store_strength_02,
    'metric_permit_store_strength_03': metric_permit_store_strength_03,
    'metric_permit_store_strength_04': metric_permit_store_strength_04,
    'metric_permit_store_strength_05': metric_permit_store_strength_05,
    'metric_permit_store_strength_06': metric_permit_store_strength_06,
    'metric_permit_store_strength_07': metric_permit_store_strength_07,
    'metric_permit_store_strength_08': metric_permit_store_strength_08,
    'metric_permit_store_strength_09': metric_permit_store_strength_09,
    'metric_permit_store_strength_10': metric_permit_store_strength_10,
    'metric_transferability_01': metric_transferability_01,
    'metric_transferability_02': metric_transferability_02,
    'metric_transferability_03': metric_transferability_03,
    'metric_transferability_04': metric_transferability_04,
    'metric_transferability_05': metric_transferability_05,
    'metric_transferability_06': metric_transferability_06,
    'metric_transferability_07': metric_transferability_07,
    'metric_transferability_08': metric_transferability_08,
    'metric_transferability_09': metric_transferability_09,
    'metric_transferability_10': metric_transferability_10,
}

def metric_vector(record: DomainRecord, context: Mapping[str, Any] | None = None) -> dict[str, float]:
    context = context or {}
    return {name: function(record, context) for name, function in METRICS.items()}

def grouped_metrics(record: DomainRecord, context: Mapping[str, Any] | None = None) -> dict[str, float]:
    vector = metric_vector(record, context)
    groups: dict[str, list[float]] = defaultdict(list)
    for name, value in vector.items():
        key = name.rsplit('_', 1)[0].removeprefix('metric_')
        groups[key].append(value)
    return {key: statistics.fmean(values) for key, values in groups.items()}

def record_score(record: DomainRecord, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    rules = evaluate(record, context)
    rule_summary = summarize(rules)
    metrics = grouped_metrics(record, context)
    metric_score = statistics.fmean(metrics.values()) if metrics else 0.0
    combined = bounded(rule_summary['score'] * 0.55 + metric_score * 0.45)
    return {'score': combined, 'rule_summary': rule_summary, 'metrics': metrics,
            'fingerprint': stable_hash({'record': record.fingerprint, 'metrics': metrics, 'rules': rule_summary})}

def portfolio(records: Iterable[DomainRecord], context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    rows = [record_score(record, context) | {'record_id': record.record_id} for record in records]
    if not rows:
        return {'count': 0, 'average': 0.0, 'minimum': 0.0, 'maximum': 0.0, 'rows': []}
    scores = [row['score'] for row in rows]
    return {'count': len(rows), 'average': statistics.fmean(scores),
            'minimum': min(scores), 'maximum': max(scores), 'rows': sorted(rows, key=lambda row: (-row['score'], row['record_id']))}

def compare(left: DomainRecord, right: DomainRecord, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    left_metrics = grouped_metrics(left, context)
    right_metrics = grouped_metrics(right, context)
    delta = {key: right_metrics.get(key, 0.0) - left_metrics.get(key, 0.0) for key in sorted(set(left_metrics) | set(right_metrics))}
    return {'left': left.record_id, 'right': right.record_id, 'delta': delta,
            'winner': right.record_id if sum(delta.values()) >= 0 else left.record_id}
