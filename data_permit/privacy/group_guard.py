from __future__ import annotations

from typing import Any, Iterable, Mapping

from data_permit.applications.permit_contract import DomainRecord, bounded, finite_number
from data_permit.privacy.stratified import (
    build_stratified_analysis,
    consent_allows,
    proportion,
    wilson_interval,
)

__all__ = [
    "confusion_counts",
    "wilson_interval",
    "cohort_metrics",
    "consent_allows",
    "stratified_gap",
    "derive_context",
]


def confusion_counts(record: DomainRecord) -> dict[str, float]:
    size = max(1.0, finite_number(record.payload.get("sample_size", 1.0)))
    prevalence = proportion(record.payload.get("sensitive_share", 0.0))
    protection_strength = proportion(record.payload.get("protection_strength", 0.0))
    audit_coverage = proportion(record.payload.get("audit_coverage", 0.0))
    positives = size * prevalence
    negatives = size - positives
    return {"tp": positives * protection_strength, "fn": positives * (1.0 - protection_strength),
            "tn": negatives * audit_coverage, "fp": negatives * (1.0 - audit_coverage)}


def cohort_metrics(record: DomainRecord) -> dict[str, float]:
    counts = confusion_counts(record)
    protection_strength_interval = wilson_interval(counts["tp"], counts["tp"] + counts["fn"])
    audit_coverage_interval = wilson_interval(counts["tn"], counts["tn"] + counts["fp"])
    missing = proportion(record.payload.get("missing_rate", 0.0))
    adverse = max(0.0, finite_number(record.payload.get("incident_count", 0.0)))
    return {"protection_strength_low": protection_strength_interval[0], "protection_strength_high": protection_strength_interval[1],
            "audit_coverage_low": audit_coverage_interval[0], "audit_coverage_high": audit_coverage_interval[1],
            "missing_rate": missing, "controls_signal": bounded(adverse / max(1.0, sum(counts.values())))}


def stratified_gap(records: Iterable[DomainRecord]) -> dict[str, float]:
    """Legacy convenience view; the canonical analysis lives in ``stratified``.

    The gap is only reported when a within-cell comparison is estimable.  When
    nothing is estimable the value is 0.0 and ``stability`` is 1.0, matching the
    conservative behaviour of the original helper for downstream weights.
    """

    analysis = build_stratified_analysis(records)
    gap = analysis["overall_gap"]["value"]
    resolved = gap if gap is not None else 0.0
    return {"group_count": float(len(analysis["strata"])),
            "protection_strength_gap": resolved,
            "stability": bounded(1.0 - resolved)}


def derive_context(record: DomainRecord, repository: Any) -> dict[str, float]:
    rows = repository.list_records() or [record]
    analysis = build_stratified_analysis(rows)
    metrics = cohort_metrics(record)
    gap = analysis["overall_gap"]["value"] or 0.0
    stability = bounded(1.0 - gap)
    consent = 1.0 if consent_allows(record, "validation") else 0.0
    return {"cohort_representativeness_weight": 0.6 + stability * 0.5,
            "consent_coverage_weight": 0.5 + consent * 0.6,
            "performance_stability_weight": 0.6 + metrics["protection_strength_low"] * 0.5,
            "controls_signal_weight": 0.8 + metrics["controls_signal"] * 0.7,
            "transferability_weight": 0.6 + stability * 0.5}
