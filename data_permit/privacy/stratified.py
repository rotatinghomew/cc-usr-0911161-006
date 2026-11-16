"""Stratified protection-effect analysis.

The review group needs to compare protection effects across data spaces without
letting a single risk score (or a pooled "overall gap") hide differences in
sample size, subject population, classification version and authorization
purpose.  Every figure produced here therefore carries:

* an explicit analysis population (validation-authorized records only),
* an explicit denominator (sensitive-positive cases for protection, records for
  missingness),
* a Wilson score interval at the configured confidence level, and
* an eligibility decision.  Strata without validation authorization or with an
  insufficient validation-authorized sample are never ranked.

The module deliberately has no dependency on the repository or on the lifecycle
so that the same analysis object can be used by the review decision and by the
exported result bundle.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from data_permit.applications.permit_contract import (
    bounded,
    finite_number,
    normalized_text,
    stable_hash,
)

STRATUM_FIELDS: tuple[str, ...] = ("data_space", "subject_group", "classification_version")
VALIDATION_PURPOSE = "validation"
MIN_VALIDATION_SAMPLE = 30.0
CONFIDENCE_LEVEL = 0.95
CONFIDENCE_Z = 1.96
RATE_SCALE_NOTE = "rates are fractions; values greater than 1 are interpreted as percentages"


def proportion(value: Any) -> float:
    """Read a rate, accepting both fractions and percentages."""

    number = finite_number(value)
    if number > 1.0:
        number /= 100.0
    return bounded(number)


def wilson_interval(successes: float, total: float, z: float = CONFIDENCE_Z) -> tuple[float, float]:
    """Wilson score interval for a proportion; returns the full range when empty."""

    if total <= 0 or not math.isfinite(total):
        return 0.0, 1.0
    successes = max(0.0, min(float(successes), float(total)))
    proportion_value = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion_value + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(
        proportion_value * (1.0 - proportion_value) / total + z * z / (4.0 * total * total)
    ) / denominator
    return bounded(center - margin), bounded(center + margin)


def authorization_scopes(record: Any) -> set[str]:
    raw = normalized_text((getattr(record, "payload", {}) or {}).get("authorization_scope", ""))
    return {item.strip() for item in raw.replace(";", ",").split(",") if item.strip()}


def consent_allows(record: Any, purpose: str = VALIDATION_PURPOSE) -> bool:
    scopes = authorization_scopes(record)
    return normalized_text(purpose) in scopes or "all" in scopes


@dataclass(frozen=True)
class Contribution:
    """One record's contribution to a stratum, with both numerators and denominators."""

    record_id: str
    version: int
    data_space: str | None
    subject_group: str | None
    classification_version: str | None
    purpose_code: str
    validation_authorized: bool
    sample_size: float
    sensitive_share: float
    protection_strength: float
    missing_rate: float

    @property
    def stratum(self) -> tuple[str | None, str | None, str | None]:
        return (self.data_space, self.subject_group, self.classification_version)

    @property
    def positives(self) -> float:
        return self.sample_size * self.sensitive_share

    @property
    def protected(self) -> float:
        return self.positives * self.protection_strength

    @property
    def missing(self) -> float:
        return self.sample_size * self.missing_rate


def _dimension(record: Any, field: str) -> str | None:
    payload = getattr(record, "payload", {}) or {}
    text = normalized_text(payload.get(field))
    return text or None


def contribution(record: Any) -> Contribution:
    payload = getattr(record, "payload", {}) or {}
    return Contribution(
        record_id=str(getattr(record, "record_id", "") or ""),
        version=int(getattr(record, "version", 1) or 1),
        data_space=_dimension(record, "data_space"),
        subject_group=_dimension(record, "subject_group"),
        classification_version=_dimension(record, "classification_version"),
        purpose_code=normalized_text(payload.get("purpose_code", "")),
        validation_authorized=consent_allows(record),
        sample_size=max(0.0, finite_number(payload.get("sample_size", 0.0))),
        sensitive_share=proportion(payload.get("sensitive_share", 0.0)),
        protection_strength=proportion(payload.get("protection_strength", 0.0)),
        missing_rate=proportion(payload.get("missing_rate", 0.0)),
    )


def _interval(successes: float, total: float, level: float, z: float) -> dict[str, Any] | None:
    if total <= 0:
        return None
    low, high = wilson_interval(successes, total, z)
    return {"low": low, "high": high, "width": high - low, "level": level, "method": "wilson_score"}


def _eligibility(
    contributions: Sequence[Contribution],
    authorized: Sequence[Contribution],
    authorized_sample: float,
    positives: float,
    min_sample: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    if not authorized:
        reasons.append({
            "code": "no_validation_authorization",
            "message": "no record in this stratum authorizes validation use",
        })
    elif authorized_sample < min_sample:
        reasons.append({
            "code": "insufficient_validation_sample",
            "message": (
                f"validation-authorized sample {authorized_sample:g} is below "
                f"the minimum {min_sample:g}"
            ),
            "denominator": authorized_sample,
            "minimum": min_sample,
        })
    if authorized and positives <= 0:
        reasons.append({
            "code": "no_sensitive_positive_denominator",
            "message": "no sensitive-positive cases are available for a protection estimate",
        })

    if authorized and len(authorized) < len(contributions):
        warnings.append({
            "code": "partial_validation_coverage",
            "message": "some records are excluded because they do not authorize validation use",
            "excluded_records": len(contributions) - len(authorized),
        })
    if len(contributions) < 2:
        warnings.append({
            "code": "single_record_stratum",
            "message": "the stratum contains a single record; between-record variation is not observable",
        })
    return reasons, warnings


def analyze_stratum(
    key: tuple[str, str, str],
    contributions: Sequence[Contribution],
    *,
    min_sample: float,
    validation_purpose: str,
    confidence_level: float,
    z: float,
) -> dict[str, Any]:
    authorized = [item for item in contributions if item.validation_authorized]
    excluded = [item for item in contributions if not item.validation_authorized]
    total_sample = sum(item.sample_size for item in contributions)
    authorized_sample = sum(item.sample_size for item in authorized)
    positives = sum(item.positives for item in authorized)
    protected = sum(item.protected for item in authorized)
    missing_count = sum(item.missing for item in authorized)

    protection_estimate = protected / positives if positives > 0 else None
    protection_interval = _interval(protected, positives, confidence_level, z)
    missing_estimate = missing_count / authorized_sample if authorized_sample > 0 else None
    missing_interval = _interval(missing_count, authorized_sample, confidence_level, z)

    reasons, warnings = _eligibility(
        contributions, authorized, authorized_sample, positives, min_sample
    )
    rankable = not reasons

    return {
        "stratum": {
            "data_space": key[0],
            "subject_group": key[1],
            "classification_version": key[2],
        },
        "record_ids": sorted(item.record_id for item in contributions),
        "record_count": len(contributions),
        "sample_size": {
            "total": total_sample,
            "validation_authorized": authorized_sample,
            "unit": "records (sum of sample_size)",
        },
        "authorization": {
            "validation_purpose": normalized_text(validation_purpose),
            "validation_authorized_records": len(authorized),
            "validation_unauthorized_records": len(excluded),
            "validation_coverage": (len(authorized) / len(contributions)) if contributions else 0.0,
            "excluded_record_ids": sorted(item.record_id for item in excluded),
            "purpose_codes": sorted({item.purpose_code for item in contributions if item.purpose_code}),
        },
        "denominators": {
            "protection": {
                "value": positives,
                "unit": "sensitive-positive cases",
                "definition": "sum(sample_size * sensitive_share) over validation-authorized records",
            },
            "missing_rate": {
                "value": authorized_sample,
                "unit": "records",
                "definition": "sum(sample_size) over validation-authorized records",
            },
        },
        "protection_effect": {
            "estimate": protection_estimate,
            "numerator": protected,
            "denominator": positives,
            "population": "validation_authorized",
            "interval": protection_interval,
        },
        "missing_rate": {
            "estimate": missing_estimate,
            "numerator": missing_count,
            "denominator": authorized_sample,
            "population": "validation_authorized",
            "interval": missing_interval,
        },
        "eligibility": {"rankable": rankable, "reasons": reasons, "warnings": warnings},
        "rankable": rankable,
        "rank": None,
    }


def _cell_key(stratum: Mapping[str, Any]) -> tuple[str, str]:
    return (stratum["stratum"]["subject_group"], stratum["stratum"]["classification_version"])


def _intervals_overlap(left: Mapping[str, Any] | None, right: Mapping[str, Any] | None) -> bool | None:
    if not left or not right:
        return None
    return not (left["high"] < right["low"] or right["high"] < left["low"])


def _rank_by_interval_dominance(
    rankable: Sequence[dict[str, Any]],
) -> tuple[dict[str, int], str]:
    """Rank comparable strata only when every interval is separated.

    When any two intervals overlap, no numeric rank is assigned at all: the
    overlap may be transitive (A overlaps C, C overlaps B, A is above B), so a
    partial or banded order would still imply a precision the data does not
    support.  The ordered estimates and intervals remain available.
    """

    intervals = [item["protection_effect"]["interval"] for item in rankable]
    if any(interval is None for interval in intervals):
        return {}, "not_ranked: missing interval"
    overlaps = any(
        _intervals_overlap(intervals[left], intervals[right])
        for left in range(len(intervals))
        for right in range(left + 1, len(intervals))
    )
    if overlaps:
        return {}, "not_ranked: intervals overlap"
    ranks = {
        item["stratum"]["data_space"]: index
        for index, item in enumerate(rankable, start=1)
    }
    return ranks, "ordinal: intervals separated"


def _compare_cells(strata: list[dict[str, Any]], confidence_level: float) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for stratum in strata:
        cells.setdefault(_cell_key(stratum), []).append(stratum)

    for stratum in strata:
        stratum["rank"] = None
        stratum["rank_status"] = "not_eligible" if not stratum["rankable"] else "unranked"

    comparisons: list[dict[str, Any]] = []
    for cell in sorted(cells):
        members = cells[cell]
        rankable = [item for item in members if item["rankable"]]
        # A rank is a comparison, so it requires at least two eligible data
        # spaces in the same subject-group / classification-version cell.
        enough = len(rankable) >= 2
        ordered = sorted(
            rankable,
            key=lambda item: (
                -(item["protection_effect"]["estimate"] or 0.0),
                item["stratum"]["data_space"],
            ),
        )
        ranks: dict[str, int] = {}
        precision = "not_ranked"
        compared = False
        if enough:
            ranks, precision = _rank_by_interval_dominance(ordered)
            compared = bool(ranks)
            for item in ordered:
                item["rank"] = ranks.get(item["stratum"]["data_space"])
                item["rank_status"] = "ranked" if compared else "overlap"
        comparable = compared

        gaps = [
            item["protection_effect"]["estimate"]
            for item in ordered
            if item["protection_effect"]["estimate"] is not None
        ]
        gap = (max(gaps) - min(gaps)) if enough and len(gaps) >= 2 else None
        overlap: bool | None = None
        if len(ordered) >= 2:
            overlap = any(
                _intervals_overlap(
                    ordered[left]["protection_effect"]["interval"],
                    ordered[right]["protection_effect"]["interval"],
                )
                for left in range(len(ordered))
                for right in range(left + 1, len(ordered))
            )

        if comparable:
            status = "compared"
        elif not enough:
            status = "single_eligible_data_space" if len(rankable) == 1 else "no_eligible_data_space"
        else:
            status = "eligible_intervals_overlap"

        comparisons.append({
            "subject_group": cell[0],
            "classification_version": cell[1],
            "confidence_level": confidence_level,
            "status": status,
            "rank_method": "wilson_interval_dominance",
            "ranked_data_spaces": [
                {
                    "rank": item["rank"],
                    "data_space": item["stratum"]["data_space"],
                    "record_count": item["record_count"],
                    "protection_effect": item["protection_effect"]["estimate"],
                    "interval": item["protection_effect"]["interval"],
                    "denominator": item["protection_effect"]["denominator"],
                }
                for item in ordered
                if comparable
            ],
            "eligible_but_unranked_data_spaces": [
                {
                    "data_space": item["stratum"]["data_space"],
                    "record_count": item["record_count"],
                    "protection_effect": item["protection_effect"]["estimate"],
                    "interval": item["protection_effect"]["interval"],
                    "denominator": item["protection_effect"]["denominator"],
                    "reason": "interval_overlap" if enough else "no_comparison_partner",
                }
                for item in rankable
                if not comparable
            ],
            "not_ranked_data_spaces": [
                {
                    "data_space": item["stratum"]["data_space"],
                    "record_count": item["record_count"],
                    "reasons": [reason["code"] for reason in item["eligibility"]["reasons"]],
                }
                for item in members
                if not item["rankable"]
            ],
            "protection_gap": gap,
            "protection_gap_status": (
                "not_estimable" if gap is None
                else "point_estimate_with_overlapping_intervals" if overlap
                else "point_estimate_with_separated_intervals"
            ),
            "interval_overlap": overlap,
            "rank_precision": precision,
        })
    return comparisons


def _overall_gap(comparisons: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    estimable = [item for item in comparisons if item["protection_gap"] is not None]
    excluded: list[dict[str, Any]] = []
    for item in comparisons:
        for entry in item["not_ranked_data_spaces"]:
            excluded.append({
                "subject_group": item["subject_group"],
                "classification_version": item["classification_version"],
                "data_space": entry["data_space"],
                "reasons": entry["reasons"],
            })
    value = max(item["protection_gap"] for item in estimable) if estimable else None
    overlapping = any(item.get("interval_overlap") for item in estimable)
    return {
        "value": value,
        "status": (
            "not_estimable" if value is None
            else "point_estimate_with_overlapping_intervals" if overlapping
            else "point_estimate_with_separated_intervals"
        ),
        "definition": (
            "largest within-cell gap between data spaces, computed only from "
            "validation-authorized strata with sufficient sample; a gap is not "
            "a ranking and its intervals are reported per cell"
        ),
        "estimable_cells": [
            {"subject_group": item["subject_group"], "classification_version": item["classification_version"],
             "value": item["protection_gap"], "interval_overlap": item.get("interval_overlap")}
            for item in estimable
        ],
        "not_estimable_cells": [
            {"subject_group": item["subject_group"], "classification_version": item["classification_version"]}
            for item in comparisons
            if item["protection_gap"] is None
        ],
        "excluded_strata": excluded,
    }


def build_stratified_analysis(
    records: Iterable[Any],
    *,
    min_sample: float = MIN_VALIDATION_SAMPLE,
    validation_purpose: str = VALIDATION_PURPOSE,
    confidence_level: float = CONFIDENCE_LEVEL,
    z: float = CONFIDENCE_Z,
) -> dict[str, Any]:
    """Build the canonical stratified analysis used by decisions and exports."""

    rows = [contribution(record) for record in records]
    groups: dict[tuple[str, str, str], list[Contribution]] = {}
    unassigned: list[dict[str, Any]] = []
    for item in rows:
        if any(part is None for part in item.stratum):
            missing = [name for name, value in zip(STRATUM_FIELDS, item.stratum) if value is None]
            unassigned.append({"record_id": item.record_id, "missing_fields": missing})
            continue
        groups.setdefault(item.stratum, []).append(item)  # type: ignore[arg-type]

    strata = [
        analyze_stratum(
            key,
            groups[key],
            min_sample=min_sample,
            validation_purpose=validation_purpose,
            confidence_level=confidence_level,
            z=z,
        )
        for key in sorted(groups)
    ]
    comparisons = _compare_cells(strata, confidence_level)
    overall = _overall_gap(comparisons)

    authorized_records = sum(1 for item in rows if item.validation_authorized)
    content: dict[str, Any] = {
        "method": {
            "protection_effect": (
                "ratio of protection-weighted sensitive-positive cases to all "
                "sensitive-positive cases in the validation-authorized population"
            ),
            "missing_rate": "share of the validation-authorized sample that is missing",
            "uncertainty": "Wilson score interval",
            "rate_scale": RATE_SCALE_NOTE,
            "stratification": list(STRATUM_FIELDS),
        },
        "thresholds": {
            "min_validation_sample": min_sample,
            "validation_purpose": normalized_text(validation_purpose),
            "confidence_level": confidence_level,
            "z": z,
        },
        "counts": {
            "records": len(rows),
            "strata": len(strata),
            "rankable_strata": sum(1 for item in strata if item["rankable"]),
            "not_rankable_strata": sum(1 for item in strata if not item["rankable"]),
            "unassigned_records": len(unassigned),
            "validation_authorized_records": authorized_records,
            "validation_unauthorized_records": len(rows) - authorized_records,
        },
        "unassigned_records": unassigned,
        "strata": strata,
        "comparisons": comparisons,
        "overall_gap": overall,
    }
    content["basis"] = {
        "hash": stable_hash(content),
        "stratum_fields": list(STRATUM_FIELDS),
        "record_count": len(rows),
        "hashed_keys": sorted(content),
    }
    return content


def analysis_hash(analysis: Mapping[str, Any]) -> str:
    """Recompute the basis hash of a (possibly loaded) analysis document."""

    content = {key: value for key, value in analysis.items() if key not in ("basis", "analysis_hash")}
    return stable_hash(content)


def stratum_for(record: Any, analysis: Mapping[str, Any]) -> dict[str, Any] | None:
    key = (
        _dimension(record, "data_space"),
        _dimension(record, "subject_group"),
        _dimension(record, "classification_version"),
    )
    for stratum in analysis.get("strata", []):
        item = stratum["stratum"]
        if (item["data_space"], item["subject_group"], item["classification_version"]) == key:
            return stratum
    return None


def decision_basis(analysis: Mapping[str, Any], stratum: Mapping[str, Any] | None) -> dict[str, Any]:
    """A compact, self-describing reference to the shared analysis basis."""

    basis_hash = analysis.get("basis", {}).get("hash", "")
    if stratum is None:
        return {
            "hash": basis_hash,
            "stratum_fields": list(STRATUM_FIELDS),
            "stratum": None,
            "rankable": False,
            "rank": None,
            "reasons": [{
                "code": "incomplete_stratum_fields",
                "message": "record lacks data_space, subject_group or classification_version",
            }],
            "warnings": [],
            "denominators": {},
            "protection_effect": None,
            "missing_rate": None,
        }
    return {
        "hash": basis_hash,
        "stratum_fields": list(STRATUM_FIELDS),
        "stratum": dict(stratum["stratum"]),
        "rankable": bool(stratum["rankable"]),
        "rank": stratum.get("rank"),
        "reasons": list(stratum["eligibility"]["reasons"]),
        "warnings": list(stratum["eligibility"]["warnings"]),
        "record_count": stratum["record_count"],
        "denominators": dict(stratum["denominators"]),
        "protection_effect": {
            "estimate": stratum["protection_effect"]["estimate"],
            "interval": stratum["protection_effect"]["interval"],
            "population": stratum["protection_effect"]["population"],
        },
        "missing_rate": {
            "estimate": stratum["missing_rate"]["estimate"],
            "interval": stratum["missing_rate"]["interval"],
            "population": stratum["missing_rate"]["population"],
        },
    }
