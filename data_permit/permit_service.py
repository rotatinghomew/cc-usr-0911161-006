from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Mapping

from data_permit.applications.permit_contract import ContractError, Decision, DomainRecord, records_from_fixture, stable_hash
from data_permit.permit_store.permit_store import Repository
from data_permit.lifecycle.permit_cycle import advance_for_outcome, decide
from data_permit.disclosure.permit_package import export_bundle, verify_bundle
from data_permit.privacy.group_guard import derive_context
from data_permit.privacy.stratified import analysis_hash, build_stratified_analysis

from data_permit.permit_signal.permit_risk import augment_context


class Application:
    def __init__(self, database: str | Path, context: Mapping[str, Any] | None = None):
        self.repository = Repository(database)
        self.context = dict(context or {})

    def ingest(self, record: DomainRecord) -> DomainRecord:
        current = self.repository.get_record(record.record_id)
        if current is None:
            self.repository.save_record(record)
            return record
        # Re-submission is identified by content (payload and source), not by
        # the fixture's generation timestamp.  An unchanged re-submission is a
        # no-op and keeps the existing version so earlier decisions keep their
        # meaning.
        if current.payload == record.payload and current.source == record.source:
            return current
        replacement = DomainRecord(record.record_id, record.payload, current.state,
                                   current.version + 1, record.occurred_at, record.source)
        self.repository.save_record(replacement, expected_version=current.version)
        return replacement

    def analyse(self, records: list[DomainRecord] | None = None) -> dict[str, Any]:
        rows = records if records is not None else self.repository.list_records()
        return build_stratified_analysis(rows)

    def decide_stored(self, stored: DomainRecord,
                      analysis: Mapping[str, Any]) -> tuple[DomainRecord, Decision]:
        # The analysis object is persisted before any decision cites it, both
        # for direct API use and for fixture runs.
        self.repository.save_analysis(analysis)
        context = dict(self.context)
        context.update(derive_context(stored, self.repository))
        context.update(augment_context(stored, self.repository))
        decision = decide(stored, context, analysis=analysis)
        prior = self.repository.latest_decision(stored.record_id)
        if prior is not None and prior.get("record_content_hash") == stored.content_hash:
            if prior.get("analysis_basis", {}).get("hash") == decision.analysis_basis.get("hash"):
                # Unchanged content analysed against the identical basis: the
                # existing decision keeps its meaning and is not re-issued.
                return stored, Decision.from_dict(prior)
        if prior is not None:
            # Any new decision for an existing record explicitly supersedes the
            # prior one.  The prior row is kept, so the earlier permit
            # interpretation stays reproducible and cannot be silently
            # rewritten by a correction.
            decision = dataclasses.replace(decision, supersedes=stable_hash(prior))
        self.repository.save_decision(decision)
        advanced = advance_for_outcome(stored, decision)
        if advanced.fingerprint != stored.fingerprint:
            self.repository.save_record(advanced, expected_version=stored.version)
        return advanced, decision

    def process(self, record: DomainRecord,
                analysis: Mapping[str, Any] | None = None) -> tuple[DomainRecord, Decision]:
        stored = self.ingest(record)
        analysis = analysis if analysis is not None else self.analyse()
        return self.decide_stored(stored, analysis)

    def run_fixture(self, fixture: Mapping[str, Any], output: str | Path) -> dict[str, Any]:
        records = records_from_fixture(fixture)
        fixture_hash = stable_hash(fixture)
        run_id = self.repository.begin_run(fixture_hash, len(records))
        completed = self.repository.completed_run(run_id)
        if completed is not None:
            return completed
        stored_records = [self.ingest(record) for record in records]
        # One analysis object, built from the canonical stored records, is used
        # both for the review decisions and for the exported result bundle.
        analysis = self.analyse()
        self.repository.save_analysis(analysis)
        decisions: dict[str, Decision] = {}
        final_records: list[DomainRecord] = []
        for record in stored_records:
            final_record, decision = self.decide_stored(record, analysis)
            final_records.append(final_record)
            decisions[record.record_id] = decision
        snapshot = self.repository.snapshot()
        if snapshot["chain_errors"]:
            raise ContractError("audit chain verification failed")
        manifest = export_bundle(output, final_records, decisions, snapshot,
                                 self.repository.event_rows(), analysis)
        result = {"run_id": run_id, "fixture_hash": fixture_hash, "records": len(final_records),
                  "decisions": len(decisions), "analysis_basis": analysis["basis"],
                  "manifest": manifest, "snapshot": snapshot}
        self.repository.finish_run(run_id, result)
        return result

    def inspect(self) -> dict[str, Any]:
        analysis = self.analyse()
        return {"snapshot": self.repository.snapshot(), "records": [record.__dict__ for record in self.repository.list_records()],
                "decisions": self.repository.decision_rows(), "analysis": analysis}


def load_fixture(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read fixture: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("fixture root must be an object")
    return value


def run(fixture_path: str | Path, database: str | Path, output: str | Path,
        context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return Application(database, context).run_fixture(load_fixture(fixture_path), output)


def verify(database: str | Path, output: str | Path) -> dict[str, Any]:
    repository = Repository(database)
    chain_errors = repository.verify_chain()
    bundle_errors = verify_bundle(output)
    basis_errors: list[str] = []
    legacy_decisions: list[str] = []
    for decision in repository.decision_rows():
        analysis_id = (decision.get("analysis_basis") or {}).get("hash", "")
        if not analysis_id:
            # Decisions written before the stratified basis existed are
            # reported as legacy rather than silently treated as current.
            legacy_decisions.append(str(decision.get("record_id")))
            continue
        analysis = repository.get_analysis(analysis_id)
        if analysis is None:
            basis_errors.append(f"{decision.get('record_id')} cites unknown analysis {analysis_id}")
        elif analysis_hash(analysis) != analysis_id:
            basis_errors.append(f"{decision.get('record_id')} cites an analysis whose content changed")
    return {"ok": not chain_errors and not bundle_errors and not basis_errors,
            "chain_errors": chain_errors, "bundle_errors": bundle_errors,
            "basis_errors": basis_errors, "legacy_decisions": legacy_decisions,
            "snapshot": repository.snapshot()}
