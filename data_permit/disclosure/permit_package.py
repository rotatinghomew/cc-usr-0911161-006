from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from data_permit.applications.permit_contract import Decision, DomainRecord, canonical_json, stable_hash, utc_now
from data_permit.privacy.stratified import analysis_hash, build_stratified_analysis


ANALYSIS_FILE = "stratified-analysis.json"
ANALYSIS_TABLE_FILE = "stratified-strata.csv"


def ensure_output(path: str | Path) -> Path:
    output = Path(path)
    output.mkdir(parents=True, exist_ok=True)
    return output


def write_json(path: Path, value: Any) -> str:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    path.write_text(body + "\n", encoding="utf-8")
    return stable_hash(value)


def write_records(path: Path, records: Iterable[DomainRecord], decisions: Mapping[str, Decision]) -> int:
    rows = []
    for record in records:
        decision = decisions.get(record.record_id)
        rows.append({"record_id": record.record_id, "state": record.state, "version": record.version,
                     "source": record.source, "fingerprint": record.fingerprint,
                     "outcome": decision.outcome if decision else "", "score": decision.score if decision else "",
                     "analysis_basis": decision.analysis_basis.get("hash", "") if decision else "",
                     "stratum_rankable": decision.analysis_basis.get("rankable", "") if decision else ""})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["record_id", "state", "version", "source", "fingerprint",
                                                    "outcome", "score", "analysis_basis", "stratum_rankable"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_rules(path: Path, decisions: Mapping[str, Decision]) -> int:
    count = 0
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["record_id", "code", "passed", "score", "severity", "message"])
        writer.writeheader()
        for record_id, decision in sorted(decisions.items()):
            for result in decision.rule_results:
                writer.writerow({"record_id": record_id, "code": result.code, "passed": result.passed,
                                 "score": result.score, "severity": result.severity, "message": result.message})
                count += 1
    return count


def _number_text(value: Any) -> str:
    return "" if value is None else f"{value:.6f}"


def write_strata(path: Path, analysis: Mapping[str, Any]) -> int:
    fields = ["data_space", "subject_group", "classification_version", "record_count",
              "validation_authorized_records", "validation_sample_size", "protection_estimate",
              "protection_low", "protection_high", "protection_denominator",
              "missing_rate_estimate", "missing_low", "missing_high", "missing_denominator",
              "rankable", "rank", "blocking_reasons"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for stratum in analysis.get("strata", []):
            item = stratum["stratum"]
            protection = stratum["protection_effect"]
            missing = stratum["missing_rate"]
            writer.writerow({
                "data_space": item["data_space"],
                "subject_group": item["subject_group"],
                "classification_version": item["classification_version"],
                "record_count": stratum["record_count"],
                "validation_authorized_records": stratum["authorization"]["validation_authorized_records"],
                "validation_sample_size": _number_text(stratum["sample_size"]["validation_authorized"]),
                "protection_estimate": _number_text(protection["estimate"]),
                "protection_low": _number_text((protection["interval"] or {}).get("low")),
                "protection_high": _number_text((protection["interval"] or {}).get("high")),
                "protection_denominator": _number_text(protection["denominator"]),
                "missing_rate_estimate": _number_text(missing["estimate"]),
                "missing_low": _number_text((missing["interval"] or {}).get("low")),
                "missing_high": _number_text((missing["interval"] or {}).get("high")),
                "missing_denominator": _number_text(missing["denominator"]),
                "rankable": stratum["rankable"],
                "rank": stratum.get("rank") or "",
                "blocking_reasons": ";".join(reason["code"] for reason in stratum["eligibility"]["reasons"]),
            })
    return len(analysis.get("strata", []))


def build_summary(records: list[DomainRecord], decisions: Mapping[str, Decision],
                  snapshot: Mapping[str, Any], analysis: Mapping[str, Any] | None = None) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    for decision in decisions.values():
        outcomes[decision.outcome] = outcomes.get(decision.outcome, 0) + 1
    scores = [decision.score for decision in decisions.values()]
    analysis = analysis or build_stratified_analysis(records)
    counts = analysis.get("counts", {})
    return {"product": '跨境人工智能数据合作许可登记库', "entity": 'data_permit_case', "generated_at": utc_now(),
            "record_count": len(records), "decision_count": len(decisions), "outcomes": outcomes,
            "average_score": sum(scores) / len(scores) if scores else 0.0,
            "minimum_score": min(scores) if scores else 0.0, "maximum_score": max(scores) if scores else 0.0,
            "score_note": ("aggregate score is a portfolio description only; "
                           "protection effects are reported by stratum with explicit denominators and intervals"),
            "analysis_basis": {"hash": analysis.get("basis", {}).get("hash", ""),
                               "stratum_fields": analysis.get("basis", {}).get("stratum_fields", []),
                               "counts": counts,
                               "overall_gap": analysis.get("overall_gap", {}),
                               "thresholds": analysis.get("thresholds", {}),
                               "method": analysis.get("method", {})},
            "repository": snapshot}


def export_bundle(output: str | Path, records: list[DomainRecord], decisions: Mapping[str, Decision],
                  snapshot: Mapping[str, Any], events: list[dict[str, Any]],
                  analysis: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = ensure_output(output)
    analysis = analysis or build_stratified_analysis(records)
    expected_hash = analysis.get("basis", {}).get("hash")
    if expected_hash and analysis_hash(analysis) != expected_hash:
        raise ValueError("stratified analysis basis hash mismatch")
    summary = build_summary(records, decisions, snapshot, analysis)
    record_count = write_records(root / "records.csv", records, decisions)
    rule_count = write_rules(root / "rules.csv", decisions)
    stratum_count = write_strata(root / ANALYSIS_TABLE_FILE, analysis)
    summary_hash = write_json(root / "summary.json", summary)
    decision_hash = write_json(root / "decisions.json", [value.as_dict() for _, value in sorted(decisions.items())])
    event_hash = write_json(root / "audit-events.json", events)
    analysis_document = dict(analysis) | {"analysis_hash": analysis_hash(analysis)}
    analysis_file_hash = write_json(root / ANALYSIS_FILE, analysis_document)
    manifest = {"files": {"summary.json": summary_hash, "decisions.json": decision_hash,
                           "audit-events.json": event_hash},
                "supplementary_files": {ANALYSIS_FILE: analysis_file_hash},
                "analysis_basis": analysis.get("basis", {}),
                "analysis_rows": stratum_count,
                "record_rows": record_count,
                "rule_rows": rule_count, "created_at": utc_now()}
    manifest["manifest_hash"] = stable_hash(manifest)
    write_json(root / "manifest.json", manifest)
    return manifest


def verify_bundle(output: str | Path) -> list[str]:
    root = Path(output)
    errors: list[str] = []
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return ["manifest.json is missing"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_manifest_hash = manifest.pop("manifest_hash", "")
    if stable_hash(manifest) != expected_manifest_hash:
        errors.append("manifest hash mismatch")
    declared = dict(manifest.get("files", {}))
    declared.update(manifest.get("supplementary_files", {}))
    for name, expected in declared.items():
        path = root / name
        if not path.is_file():
            errors.append(f"{name} is missing")
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if name == ANALYSIS_FILE:
            content = dict(document)
            content.pop("analysis_hash", None)
            if analysis_hash(content) != manifest.get("analysis_basis", {}).get("hash", ""):
                errors.append(f"{ANALYSIS_FILE} basis mismatch")
        if stable_hash(document) != expected:
            errors.append(f"{name} hash mismatch")
    return errors
