from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Iterable

from data_permit.applications.permit_contract import DomainRecord, bounded, finite_number, normalized_text


def confusion_counts(record: DomainRecord) -> dict[str, float]:
    size = max(1.0, finite_number(record.payload.get("sample_size", 1.0)))
    prevalence = bounded(finite_number(record.payload.get("sensitive_share", 0.0)))
    protection_strength = bounded(finite_number(record.payload.get("protection_strength", 0.0)))
    audit_coverage = bounded(finite_number(record.payload.get("audit_coverage", 0.0)))
    positives = size * prevalence
    negatives = size - positives
    return {"tp": positives * protection_strength, "fn": positives * (1.0 - protection_strength),
            "tn": negatives * audit_coverage, "fp": negatives * (1.0 - audit_coverage)}


def wilson_interval(successes: float, total: float, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 1.0
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator
    return bounded(center - margin), bounded(center + margin)


def cohort_metrics(record: DomainRecord) -> dict[str, float]:
    counts = confusion_counts(record)
    protection_strength_interval = wilson_interval(counts["tp"], counts["tp"] + counts["fn"])
    audit_coverage_interval = wilson_interval(counts["tn"], counts["tn"] + counts["fp"])
    missing = bounded(finite_number(record.payload.get("missing_rate", 0.0)))
    adverse = max(0.0, finite_number(record.payload.get("incident_count", 0.0)))
    return {"protection_strength_low": protection_strength_interval[0], "protection_strength_high": protection_strength_interval[1],
            "audit_coverage_low": audit_coverage_interval[0], "audit_coverage_high": audit_coverage_interval[1],
            "missing_rate": missing, "controls_signal": bounded(adverse / max(1.0, sum(counts.values())))}


def consent_allows(record: DomainRecord, purpose: str) -> bool:
    scopes = {item.strip() for item in normalized_text(record.payload.get("authorization_scope", "")).replace(";", ",").split(",") if item.strip()}
    return purpose in scopes or "all" in scopes


def stratified_gap(records: Iterable[DomainRecord]) -> dict[str, float]:
    groups: dict[str, list[float]] = defaultdict(list)
    for record in records:
        group = normalized_text(record.payload.get("subject_group", "unknown"))
        groups[group].append(cohort_metrics(record)["protection_strength_low"])
    means = {group: sum(values) / len(values) for group, values in groups.items()}
    gap = max(means.values()) - min(means.values()) if means else 0.0
    return {"group_count": float(len(means)), "protection_strength_gap": gap, "stability": bounded(1.0 - gap)}


def derive_context(record: DomainRecord, repository: Any) -> dict[str, float]:
    rows = repository.list_records() or [record]
    metrics = cohort_metrics(record)
    gap = stratified_gap(rows)
    consent = 1.0 if consent_allows(record, "validation") else 0.0
    return {"cohort_representativeness_weight": 0.6 + gap["stability"] * 0.5,
            "consent_coverage_weight": 0.5 + consent * 0.6,
            "performance_stability_weight": 0.6 + metrics["protection_strength_low"] * 0.5,
            "controls_signal_weight": 0.8 + metrics["controls_signal"] * 0.7,
            "transferability_weight": 0.6 + gap["stability"] * 0.5}
