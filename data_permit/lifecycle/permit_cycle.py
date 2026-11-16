from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from data_permit.applications.permit_contract import ContractError, Decision, DomainRecord, RuleResult, bounded
from data_permit.privacy.risk_metrics import grouped_metrics, record_score
from data_permit.controls.purpose_limits import evaluate

STATES = ['proposed', 'assessed', 'conditioned', 'permitted', 'monitored', 'revoked']
TRANSITIONS = {state: tuple(STATES[i + 1:i + 3]) for i, state in enumerate(STATES)}

@dataclass(frozen=True)
class TransitionPlan:
    from_state: str
    to_state: str
    allowed: bool
    reasons: tuple[str, ...]
    score: float

def allowed_targets(state: str) -> tuple[str, ...]:
    if state not in TRANSITIONS:
        raise ContractError('unknown workflow state')
    return TRANSITIONS[state]

def plan_transition(record: DomainRecord, target: str, context: Mapping[str, Any] | None = None) -> TransitionPlan:
    context = context or {}
    if target not in STATES:
        raise ContractError('unknown target state')
    scorecard = record_score(record, context)
    reasons: list[str] = []
    structurally_allowed = target in allowed_targets(record.state)
    if not structurally_allowed:
        reasons.append('transition is not adjacent in the lifecycle')
    threshold = float(context.get('transition_threshold', 0.42))
    if scorecard['score'] < threshold:
        reasons.append('record score is below the transition threshold')
    return TransitionPlan(record.state, target, structurally_allowed and not reasons, tuple(reasons or ['eligible']), scorecard['score'])

def apply_transition(record: DomainRecord, target: str, context: Mapping[str, Any] | None = None) -> DomainRecord:
    plan = plan_transition(record, target, context)
    if not plan.allowed:
        raise ContractError('; '.join(plan.reasons))
    return record.with_state(target)

def guard_data_space_cohort_representativeness_01(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_data_space_cohort_representativeness_01_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_cohort_representativeness_01' + (':passed' if allowed else ':blocked')

def guard_subject_group_consent_coverage_02(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_subject_group_consent_coverage_02_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_consent_coverage_02' + (':passed' if allowed else ':blocked')

def guard_purpose_code_terminology_alignment_03(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_purpose_code_terminology_alignment_03_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_terminology_alignment_03' + (':passed' if allowed else ':blocked')

def guard_sample_size_performance_stability_04(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_sample_size_performance_stability_04_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_performance_stability_04' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_controls_signal_05(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_sensitive_share_controls_signal_05_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_controls_signal_05' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_privacy_risk_06(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_authorization_scope_privacy_risk_06_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_privacy_risk_06' + (':passed' if allowed else ':blocked')

def guard_classification_version_permit_store_strength_07(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_classification_version_permit_store_strength_07_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_permit_store_strength_07' + (':passed' if allowed else ':blocked')

def guard_missing_rate_transferability_08(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_missing_rate_transferability_08_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_transferability_08' + (':passed' if allowed else ':blocked')

def guard_protection_strength_cohort_representativeness_09(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_protection_strength_cohort_representativeness_09_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_cohort_representativeness_09' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_consent_coverage_10(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_audit_coverage_consent_coverage_10_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_consent_coverage_10' + (':passed' if allowed else ':blocked')

def guard_incident_count_terminology_alignment_11(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_incident_count_terminology_alignment_11_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_terminology_alignment_11' + (':passed' if allowed else ':blocked')

def guard_review_authority_performance_stability_12(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_review_authority_performance_stability_12_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_performance_stability_12' + (':passed' if allowed else ':blocked')

def guard_data_space_controls_signal_13(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_data_space_controls_signal_13_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_controls_signal_13' + (':passed' if allowed else ':blocked')

def guard_subject_group_privacy_risk_14(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_subject_group_privacy_risk_14_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_privacy_risk_14' + (':passed' if allowed else ':blocked')

def guard_purpose_code_permit_store_strength_15(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_purpose_code_permit_store_strength_15_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_permit_store_strength_15' + (':passed' if allowed else ':blocked')

def guard_sample_size_transferability_16(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_sample_size_transferability_16_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_transferability_16' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_cohort_representativeness_17(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_sensitive_share_cohort_representativeness_17_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_cohort_representativeness_17' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_consent_coverage_18(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_authorization_scope_consent_coverage_18_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_consent_coverage_18' + (':passed' if allowed else ':blocked')

def guard_classification_version_terminology_alignment_19(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_classification_version_terminology_alignment_19_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_terminology_alignment_19' + (':passed' if allowed else ':blocked')

def guard_missing_rate_performance_stability_20(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_missing_rate_performance_stability_20_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_performance_stability_20' + (':passed' if allowed else ':blocked')

def guard_protection_strength_controls_signal_21(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_protection_strength_controls_signal_21_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_controls_signal_21' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_privacy_risk_22(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_audit_coverage_privacy_risk_22_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_privacy_risk_22' + (':passed' if allowed else ':blocked')

def guard_incident_count_permit_store_strength_23(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_incident_count_permit_store_strength_23_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_permit_store_strength_23' + (':passed' if allowed else ':blocked')

def guard_review_authority_transferability_24(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_review_authority_transferability_24_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_transferability_24' + (':passed' if allowed else ':blocked')

def guard_data_space_cohort_representativeness_25(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_data_space_cohort_representativeness_25_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_cohort_representativeness_25' + (':passed' if allowed else ':blocked')

def guard_subject_group_consent_coverage_26(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_subject_group_consent_coverage_26_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_consent_coverage_26' + (':passed' if allowed else ':blocked')

def guard_purpose_code_terminology_alignment_27(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_purpose_code_terminology_alignment_27_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_terminology_alignment_27' + (':passed' if allowed else ':blocked')

def guard_sample_size_performance_stability_28(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_sample_size_performance_stability_28_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_performance_stability_28' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_controls_signal_29(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_sensitive_share_controls_signal_29_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_controls_signal_29' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_privacy_risk_30(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_authorization_scope_privacy_risk_30_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_privacy_risk_30' + (':passed' if allowed else ':blocked')

def guard_classification_version_permit_store_strength_31(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_classification_version_permit_store_strength_31_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_permit_store_strength_31' + (':passed' if allowed else ':blocked')

def guard_missing_rate_transferability_32(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_missing_rate_transferability_32_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_transferability_32' + (':passed' if allowed else ':blocked')

def guard_protection_strength_cohort_representativeness_33(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_protection_strength_cohort_representativeness_33_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_cohort_representativeness_33' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_consent_coverage_34(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_audit_coverage_consent_coverage_34_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_consent_coverage_34' + (':passed' if allowed else ':blocked')

def guard_incident_count_terminology_alignment_35(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_incident_count_terminology_alignment_35_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_terminology_alignment_35' + (':passed' if allowed else ':blocked')

def guard_review_authority_performance_stability_36(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_review_authority_performance_stability_36_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_performance_stability_36' + (':passed' if allowed else ':blocked')

def guard_data_space_controls_signal_37(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_data_space_controls_signal_37_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_controls_signal_37' + (':passed' if allowed else ':blocked')

def guard_subject_group_privacy_risk_38(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_subject_group_privacy_risk_38_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_privacy_risk_38' + (':passed' if allowed else ':blocked')

def guard_purpose_code_permit_store_strength_39(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_purpose_code_permit_store_strength_39_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_permit_store_strength_39' + (':passed' if allowed else ':blocked')

def guard_sample_size_transferability_40(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_sample_size_transferability_40_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_transferability_40' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_cohort_representativeness_41(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_sensitive_share_cohort_representativeness_41_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_cohort_representativeness_41' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_consent_coverage_42(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_authorization_scope_consent_coverage_42_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_consent_coverage_42' + (':passed' if allowed else ':blocked')

def guard_classification_version_terminology_alignment_43(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_classification_version_terminology_alignment_43_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_terminology_alignment_43' + (':passed' if allowed else ':blocked')

def guard_missing_rate_performance_stability_44(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_missing_rate_performance_stability_44_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_performance_stability_44' + (':passed' if allowed else ':blocked')

def guard_protection_strength_controls_signal_45(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_protection_strength_controls_signal_45_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_controls_signal_45' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_privacy_risk_46(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_audit_coverage_privacy_risk_46_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_privacy_risk_46' + (':passed' if allowed else ':blocked')

def guard_incident_count_permit_store_strength_47(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_incident_count_permit_store_strength_47_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_permit_store_strength_47' + (':passed' if allowed else ':blocked')

def guard_review_authority_transferability_48(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_review_authority_transferability_48_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_transferability_48' + (':passed' if allowed else ':blocked')

def guard_data_space_cohort_representativeness_49(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_data_space_cohort_representativeness_49_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_cohort_representativeness_49' + (':passed' if allowed else ':blocked')

def guard_subject_group_consent_coverage_50(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_subject_group_consent_coverage_50_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_consent_coverage_50' + (':passed' if allowed else ':blocked')

def guard_purpose_code_terminology_alignment_51(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_purpose_code_terminology_alignment_51_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_terminology_alignment_51' + (':passed' if allowed else ':blocked')

def guard_sample_size_performance_stability_52(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_sample_size_performance_stability_52_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_performance_stability_52' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_controls_signal_53(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_sensitive_share_controls_signal_53_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_controls_signal_53' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_privacy_risk_54(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_authorization_scope_privacy_risk_54_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_privacy_risk_54' + (':passed' if allowed else ':blocked')

def guard_classification_version_permit_store_strength_55(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_classification_version_permit_store_strength_55_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_permit_store_strength_55' + (':passed' if allowed else ':blocked')

def guard_missing_rate_transferability_56(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_missing_rate_transferability_56_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_transferability_56' + (':passed' if allowed else ':blocked')

def guard_protection_strength_cohort_representativeness_57(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_protection_strength_cohort_representativeness_57_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_cohort_representativeness_57' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_consent_coverage_58(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_audit_coverage_consent_coverage_58_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_consent_coverage_58' + (':passed' if allowed else ':blocked')

def guard_incident_count_terminology_alignment_59(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_incident_count_terminology_alignment_59_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_terminology_alignment_59' + (':passed' if allowed else ':blocked')

def guard_review_authority_performance_stability_60(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_review_authority_performance_stability_60_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_performance_stability_60' + (':passed' if allowed else ':blocked')

def guard_data_space_controls_signal_61(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_data_space_controls_signal_61_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_controls_signal_61' + (':passed' if allowed else ':blocked')

def guard_subject_group_privacy_risk_62(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_subject_group_privacy_risk_62_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_privacy_risk_62' + (':passed' if allowed else ':blocked')

def guard_purpose_code_permit_store_strength_63(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_purpose_code_permit_store_strength_63_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_permit_store_strength_63' + (':passed' if allowed else ':blocked')

def guard_sample_size_transferability_64(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_sample_size_transferability_64_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_transferability_64' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_cohort_representativeness_65(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_sensitive_share_cohort_representativeness_65_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_cohort_representativeness_65' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_consent_coverage_66(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_authorization_scope_consent_coverage_66_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_consent_coverage_66' + (':passed' if allowed else ':blocked')

def guard_classification_version_terminology_alignment_67(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_classification_version_terminology_alignment_67_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_terminology_alignment_67' + (':passed' if allowed else ':blocked')

def guard_missing_rate_performance_stability_68(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_missing_rate_performance_stability_68_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_performance_stability_68' + (':passed' if allowed else ':blocked')

def guard_protection_strength_controls_signal_69(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_protection_strength_controls_signal_69_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_controls_signal_69' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_privacy_risk_70(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_audit_coverage_privacy_risk_70_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_privacy_risk_70' + (':passed' if allowed else ':blocked')

def guard_incident_count_permit_store_strength_71(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_incident_count_permit_store_strength_71_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_permit_store_strength_71' + (':passed' if allowed else ':blocked')

def guard_review_authority_transferability_72(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_review_authority_transferability_72_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_transferability_72' + (':passed' if allowed else ':blocked')

def guard_data_space_cohort_representativeness_73(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_data_space_cohort_representativeness_73_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_cohort_representativeness_73' + (':passed' if allowed else ':blocked')

def guard_subject_group_consent_coverage_74(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_subject_group_consent_coverage_74_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_consent_coverage_74' + (':passed' if allowed else ':blocked')

def guard_purpose_code_terminology_alignment_75(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_purpose_code_terminology_alignment_75_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_terminology_alignment_75' + (':passed' if allowed else ':blocked')

def guard_sample_size_performance_stability_76(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_sample_size_performance_stability_76_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_performance_stability_76' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_controls_signal_77(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_sensitive_share_controls_signal_77_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_controls_signal_77' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_privacy_risk_78(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_authorization_scope_privacy_risk_78_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_privacy_risk_78' + (':passed' if allowed else ':blocked')

def guard_classification_version_permit_store_strength_79(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_classification_version_permit_store_strength_79_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_permit_store_strength_79' + (':passed' if allowed else ':blocked')

def guard_missing_rate_transferability_80(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_missing_rate_transferability_80_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_transferability_80' + (':passed' if allowed else ':blocked')

def guard_protection_strength_cohort_representativeness_81(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_protection_strength_cohort_representativeness_81_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_cohort_representativeness_81' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_consent_coverage_82(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_audit_coverage_consent_coverage_82_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_consent_coverage_82' + (':passed' if allowed else ':blocked')

def guard_incident_count_terminology_alignment_83(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_incident_count_terminology_alignment_83_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_terminology_alignment_83' + (':passed' if allowed else ':blocked')

def guard_review_authority_performance_stability_84(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_review_authority_performance_stability_84_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_performance_stability_84' + (':passed' if allowed else ':blocked')

def guard_data_space_controls_signal_85(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_data_space_controls_signal_85_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_controls_signal_85' + (':passed' if allowed else ':blocked')

def guard_subject_group_privacy_risk_86(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_subject_group_privacy_risk_86_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_privacy_risk_86' + (':passed' if allowed else ':blocked')

def guard_purpose_code_permit_store_strength_87(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_purpose_code_permit_store_strength_87_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_permit_store_strength_87' + (':passed' if allowed else ':blocked')

def guard_sample_size_transferability_88(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_sample_size_transferability_88_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_transferability_88' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_cohort_representativeness_89(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_sensitive_share_cohort_representativeness_89_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_cohort_representativeness_89' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_consent_coverage_90(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_authorization_scope_consent_coverage_90_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_consent_coverage_90' + (':passed' if allowed else ':blocked')

def guard_classification_version_terminology_alignment_91(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_classification_version_terminology_alignment_91_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_terminology_alignment_91' + (':passed' if allowed else ':blocked')

def guard_missing_rate_performance_stability_92(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_missing_rate_performance_stability_92_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_performance_stability_92' + (':passed' if allowed else ':blocked')

def guard_protection_strength_controls_signal_93(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_protection_strength_controls_signal_93_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_controls_signal_93' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_privacy_risk_94(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_audit_coverage_privacy_risk_94_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_privacy_risk_94' + (':passed' if allowed else ':blocked')

def guard_incident_count_permit_store_strength_95(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_incident_count_permit_store_strength_95_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_permit_store_strength_95' + (':passed' if allowed else ':blocked')

def guard_review_authority_transferability_96(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_review_authority_transferability_96_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_transferability_96' + (':passed' if allowed else ':blocked')

def guard_data_space_cohort_representativeness_97(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_data_space_cohort_representativeness_97_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_cohort_representativeness_97' + (':passed' if allowed else ':blocked')

def guard_subject_group_consent_coverage_98(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_subject_group_consent_coverage_98_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_consent_coverage_98' + (':passed' if allowed else ':blocked')

def guard_purpose_code_terminology_alignment_99(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_purpose_code_terminology_alignment_99_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_terminology_alignment_99' + (':passed' if allowed else ':blocked')

def guard_sample_size_performance_stability_100(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_sample_size_performance_stability_100_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_performance_stability_100' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_controls_signal_101(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_sensitive_share_controls_signal_101_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_controls_signal_101' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_privacy_risk_102(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_authorization_scope_privacy_risk_102_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_privacy_risk_102' + (':passed' if allowed else ':blocked')

def guard_classification_version_permit_store_strength_103(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_classification_version_permit_store_strength_103_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_permit_store_strength_103' + (':passed' if allowed else ':blocked')

def guard_missing_rate_transferability_104(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_missing_rate_transferability_104_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_transferability_104' + (':passed' if allowed else ':blocked')

def guard_protection_strength_cohort_representativeness_105(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_protection_strength_cohort_representativeness_105_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_cohort_representativeness_105' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_consent_coverage_106(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_audit_coverage_consent_coverage_106_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_consent_coverage_106' + (':passed' if allowed else ':blocked')

def guard_incident_count_terminology_alignment_107(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_incident_count_terminology_alignment_107_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_terminology_alignment_107' + (':passed' if allowed else ':blocked')

def guard_review_authority_performance_stability_108(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_review_authority_performance_stability_108_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_performance_stability_108' + (':passed' if allowed else ':blocked')

def guard_data_space_controls_signal_109(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_data_space_controls_signal_109_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_data_space_controls_signal_109' + (':passed' if allowed else ':blocked')

def guard_subject_group_privacy_risk_110(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_subject_group_privacy_risk_110_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_subject_group_privacy_risk_110' + (':passed' if allowed else ':blocked')

def guard_purpose_code_permit_store_strength_111(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_purpose_code_permit_store_strength_111_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_purpose_code_permit_store_strength_111' + (':passed' if allowed else ':blocked')

def guard_sample_size_transferability_112(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_sample_size_transferability_112_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sample_size_transferability_112' + (':passed' if allowed else ':blocked')

def guard_sensitive_share_cohort_representativeness_113(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('cohort_representativeness', 0.0)
    floor = float(context.get('guard_sensitive_share_cohort_representativeness_113_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_sensitive_share_cohort_representativeness_113' + (':passed' if allowed else ':blocked')

def guard_authorization_scope_consent_coverage_114(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('consent_coverage', 0.0)
    floor = float(context.get('guard_authorization_scope_consent_coverage_114_floor', 0.32))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_authorization_scope_consent_coverage_114' + (':passed' if allowed else ':blocked')

def guard_classification_version_terminology_alignment_115(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('terminology_alignment', 0.0)
    floor = float(context.get('guard_classification_version_terminology_alignment_115_floor', 0.39))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_classification_version_terminology_alignment_115' + (':passed' if allowed else ':blocked')

def guard_missing_rate_performance_stability_116(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('performance_stability', 0.0)
    floor = float(context.get('guard_missing_rate_performance_stability_116_floor', 0.46))
    state_ok = STATES.index(record.state) <= STATES.index('assessed')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_missing_rate_performance_stability_116' + (':passed' if allowed else ':blocked')

def guard_protection_strength_controls_signal_117(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('controls_signal', 0.0)
    floor = float(context.get('guard_protection_strength_controls_signal_117_floor', 0.53))
    state_ok = STATES.index(record.state) <= STATES.index('conditioned')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_protection_strength_controls_signal_117' + (':passed' if allowed else ':blocked')

def guard_audit_coverage_privacy_risk_118(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('privacy_risk', 0.0)
    floor = float(context.get('guard_audit_coverage_privacy_risk_118_floor', 0.6000000000000001))
    state_ok = STATES.index(record.state) <= STATES.index('permitted')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_audit_coverage_privacy_risk_118' + (':passed' if allowed else ':blocked')

def guard_incident_count_permit_store_strength_119(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('permit_store_strength', 0.0)
    floor = float(context.get('guard_incident_count_permit_store_strength_119_floor', 0.67))
    state_ok = STATES.index(record.state) <= STATES.index('monitored')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_incident_count_permit_store_strength_119' + (':passed' if allowed else ':blocked')

def guard_review_authority_transferability_120(record: DomainRecord, context: Mapping[str, Any]) -> tuple[bool, str]:
    metrics = context.get('_metrics') or grouped_metrics(record, context)
    value = metrics.get('transferability', 0.0)
    floor = float(context.get('guard_review_authority_transferability_120_floor', 0.25))
    state_ok = STATES.index(record.state) <= STATES.index('revoked')
    allowed = state_ok and value >= min(1.0, floor)
    return allowed, 'guard_review_authority_transferability_120' + (':passed' if allowed else ':blocked')

GUARDS: tuple[Callable[[DomainRecord, Mapping[str, Any]], tuple[bool, str]], ...] = (
    guard_data_space_cohort_representativeness_01,
    guard_subject_group_consent_coverage_02,
    guard_purpose_code_terminology_alignment_03,
    guard_sample_size_performance_stability_04,
    guard_sensitive_share_controls_signal_05,
    guard_authorization_scope_privacy_risk_06,
    guard_classification_version_permit_store_strength_07,
    guard_missing_rate_transferability_08,
    guard_protection_strength_cohort_representativeness_09,
    guard_audit_coverage_consent_coverage_10,
    guard_incident_count_terminology_alignment_11,
    guard_review_authority_performance_stability_12,
    guard_data_space_controls_signal_13,
    guard_subject_group_privacy_risk_14,
    guard_purpose_code_permit_store_strength_15,
    guard_sample_size_transferability_16,
    guard_sensitive_share_cohort_representativeness_17,
    guard_authorization_scope_consent_coverage_18,
    guard_classification_version_terminology_alignment_19,
    guard_missing_rate_performance_stability_20,
    guard_protection_strength_controls_signal_21,
    guard_audit_coverage_privacy_risk_22,
    guard_incident_count_permit_store_strength_23,
    guard_review_authority_transferability_24,
    guard_data_space_cohort_representativeness_25,
    guard_subject_group_consent_coverage_26,
    guard_purpose_code_terminology_alignment_27,
    guard_sample_size_performance_stability_28,
    guard_sensitive_share_controls_signal_29,
    guard_authorization_scope_privacy_risk_30,
    guard_classification_version_permit_store_strength_31,
    guard_missing_rate_transferability_32,
    guard_protection_strength_cohort_representativeness_33,
    guard_audit_coverage_consent_coverage_34,
    guard_incident_count_terminology_alignment_35,
    guard_review_authority_performance_stability_36,
    guard_data_space_controls_signal_37,
    guard_subject_group_privacy_risk_38,
    guard_purpose_code_permit_store_strength_39,
    guard_sample_size_transferability_40,
    guard_sensitive_share_cohort_representativeness_41,
    guard_authorization_scope_consent_coverage_42,
    guard_classification_version_terminology_alignment_43,
    guard_missing_rate_performance_stability_44,
    guard_protection_strength_controls_signal_45,
    guard_audit_coverage_privacy_risk_46,
    guard_incident_count_permit_store_strength_47,
    guard_review_authority_transferability_48,
    guard_data_space_cohort_representativeness_49,
    guard_subject_group_consent_coverage_50,
    guard_purpose_code_terminology_alignment_51,
    guard_sample_size_performance_stability_52,
    guard_sensitive_share_controls_signal_53,
    guard_authorization_scope_privacy_risk_54,
    guard_classification_version_permit_store_strength_55,
    guard_missing_rate_transferability_56,
    guard_protection_strength_cohort_representativeness_57,
    guard_audit_coverage_consent_coverage_58,
    guard_incident_count_terminology_alignment_59,
    guard_review_authority_performance_stability_60,
    guard_data_space_controls_signal_61,
    guard_subject_group_privacy_risk_62,
    guard_purpose_code_permit_store_strength_63,
    guard_sample_size_transferability_64,
    guard_sensitive_share_cohort_representativeness_65,
    guard_authorization_scope_consent_coverage_66,
    guard_classification_version_terminology_alignment_67,
    guard_missing_rate_performance_stability_68,
    guard_protection_strength_controls_signal_69,
    guard_audit_coverage_privacy_risk_70,
    guard_incident_count_permit_store_strength_71,
    guard_review_authority_transferability_72,
    guard_data_space_cohort_representativeness_73,
    guard_subject_group_consent_coverage_74,
    guard_purpose_code_terminology_alignment_75,
    guard_sample_size_performance_stability_76,
    guard_sensitive_share_controls_signal_77,
    guard_authorization_scope_privacy_risk_78,
    guard_classification_version_permit_store_strength_79,
    guard_missing_rate_transferability_80,
    guard_protection_strength_cohort_representativeness_81,
    guard_audit_coverage_consent_coverage_82,
    guard_incident_count_terminology_alignment_83,
    guard_review_authority_performance_stability_84,
    guard_data_space_controls_signal_85,
    guard_subject_group_privacy_risk_86,
    guard_purpose_code_permit_store_strength_87,
    guard_sample_size_transferability_88,
    guard_sensitive_share_cohort_representativeness_89,
    guard_authorization_scope_consent_coverage_90,
    guard_classification_version_terminology_alignment_91,
    guard_missing_rate_performance_stability_92,
    guard_protection_strength_controls_signal_93,
    guard_audit_coverage_privacy_risk_94,
    guard_incident_count_permit_store_strength_95,
    guard_review_authority_transferability_96,
    guard_data_space_cohort_representativeness_97,
    guard_subject_group_consent_coverage_98,
    guard_purpose_code_terminology_alignment_99,
    guard_sample_size_performance_stability_100,
    guard_sensitive_share_controls_signal_101,
    guard_authorization_scope_privacy_risk_102,
    guard_classification_version_permit_store_strength_103,
    guard_missing_rate_transferability_104,
    guard_protection_strength_cohort_representativeness_105,
    guard_audit_coverage_consent_coverage_106,
    guard_incident_count_terminology_alignment_107,
    guard_review_authority_performance_stability_108,
    guard_data_space_controls_signal_109,
    guard_subject_group_privacy_risk_110,
    guard_purpose_code_permit_store_strength_111,
    guard_sample_size_transferability_112,
    guard_sensitive_share_cohort_representativeness_113,
    guard_authorization_scope_consent_coverage_114,
    guard_classification_version_terminology_alignment_115,
    guard_missing_rate_performance_stability_116,
    guard_protection_strength_controls_signal_117,
    guard_audit_coverage_privacy_risk_118,
    guard_incident_count_permit_store_strength_119,
    guard_review_authority_transferability_120,
)

def guard_report(record: DomainRecord, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    context = dict(context or {})
    context['_metrics'] = grouped_metrics(record, context)
    results = [guard(record, context) for guard in GUARDS]
    return {'passed': sum(item[0] for item in results), 'failed': sum(not item[0] for item in results),
            'messages': [item[1] for item in results]}

def decide(record: DomainRecord, context: Mapping[str, Any] | None = None) -> Decision:
    context = context or {}
    rules = evaluate(record, context)
    scorecard = record_score(record, context)
    guards = guard_report(record, context)
    effective_score = scorecard['score'] * (1.0 - float(context.get('domain_signal', 0.0)) * 0.5)
    critical = sum(item.severity == 'critical' for item in rules)
    if context.get('domain_severity') == 'critical':
        outcome = 'hold'
    elif critical:
        outcome = 'hold'
    elif effective_score >= float(context.get('approve_threshold', 0.62)) and guards['passed'] >= guards['failed']:
        outcome = 'approve'
    elif effective_score >= float(context.get('review_threshold', 0.38)):
        outcome = 'review'
    else:
        outcome = 'reject'
    reasons = (f"score={scorecard['score']:.6f}", f"critical={critical}",
               f"guards={guards['passed']}/{guards['passed'] + guards['failed']}")
    return Decision(record.record_id, outcome, effective_score, reasons, rules, scorecard['metrics'])

def advance_for_outcome(record: DomainRecord, decision: Decision) -> DomainRecord:
    current = STATES.index(record.state)
    if decision.outcome == 'approve' and current + 1 < len(STATES):
        return record.with_state(STATES[current + 1])
    if decision.outcome == 'hold' and STATES[-1] != record.state:
        return record.with_state(STATES[-1])
    return record
