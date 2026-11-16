from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from data_permit.applications.permit_contract import DomainRecord, records_from_fixture, stable_hash
from data_permit.disclosure.permit_package import verify_bundle
from data_permit.permit_store.permit_store import Repository
from data_permit.permit_service import run, verify
from data_permit.privacy.stratified import (
    analysis_hash,
    build_stratified_analysis,
    decision_basis,
    stratum_for,
    wilson_interval,
)

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "acceptance.json"
SYNTHETIC_SOURCE = "synthetic-local-acceptance"


def make(record_id, data_space, group, version, scope="validation", sample=40.0,
         protection=0.8, missing=0.1, purpose="validation") -> DomainRecord:
    return DomainRecord(record_id, {
        "data_space": data_space, "subject_group": group, "purpose_code": purpose,
        "sample_size": sample, "sensitive_share": 0.5, "authorization_scope": scope,
        "classification_version": version, "missing_rate": missing,
        "protection_strength": protection, "audit_coverage": 0.8,
        "incident_count": 1.0, "review_authority": "board",
    }, source=SYNTHETIC_SOURCE)


def acceptance_records() -> list[DomainRecord]:
    return records_from_fixture(json.loads(FIXTURE.read_text(encoding="utf-8")))


class StratumConstructionTests(unittest.TestCase):
    def test_strata_are_keyed_by_space_group_and_version(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s1", "g1", "v1"),
                   make("c", "s2", "g1", "v1"), make("d", "s1", "g2", "v2")]
        analysis = build_stratified_analysis(records)
        keys = {(item["stratum"]["data_space"], item["stratum"]["subject_group"],
                 item["stratum"]["classification_version"]) for item in analysis["strata"]}
        self.assertEqual(keys, {("s1", "g1", "v1"), ("s2", "g1", "v1"), ("s1", "g2", "v2")})
        s1 = [item for item in analysis["strata"]
              if (item["stratum"]["data_space"], item["stratum"]["subject_group"]) == ("s1", "g1")][0]
        self.assertEqual(s1["record_count"], 2)

    def test_missing_stratum_field_is_reported_not_guessed(self):
        record = make("x", "", "g1", "v1")
        analysis = build_stratified_analysis([record])
        self.assertEqual(analysis["counts"]["unassigned_records"], 1)
        self.assertEqual(analysis["unassigned_records"][0]["record_id"], "x")
        self.assertIn("data_space", analysis["unassigned_records"][0]["missing_fields"])
        self.assertEqual(analysis["strata"], [])

    def test_analysis_basis_hash_is_reproducible_and_excludes_itself(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1")]
        first = build_stratified_analysis(records)
        second = build_stratified_analysis(records)
        self.assertEqual(first["basis"]["hash"], second["basis"]["hash"])
        self.assertEqual(analysis_hash(first), first["basis"]["hash"])
        self.assertNotIn("basis", first["basis"]["hashed_keys"])


class DenominatorAndUncertaintyTests(unittest.TestCase):
    def test_protection_and_missing_denominators_are_explicit(self):
        analysis = build_stratified_analysis([make("a", "s1", "g1", "v1", sample=100.0,
                                                   protection=0.8, missing=0.2)])
        stratum = analysis["strata"][0]
        # sensitive_share=0.5 -> 50 positive cases; protection 0.8 -> 40 protected
        self.assertAlmostEqual(stratum["protection_effect"]["denominator"], 50.0)
        self.assertAlmostEqual(stratum["protection_effect"]["numerator"], 40.0)
        self.assertAlmostEqual(stratum["protection_effect"]["estimate"], 0.8)
        self.assertAlmostEqual(stratum["denominators"]["protection"]["value"], 50.0)
        self.assertAlmostEqual(stratum["missing_rate"]["denominator"], 100.0)
        self.assertAlmostEqual(stratum["missing_rate"]["numerator"], 20.0)
        self.assertAlmostEqual(stratum["denominators"]["missing_rate"]["value"], 100.0)

    def test_every_estimate_carries_an_interval(self):
        analysis = build_stratified_analysis([make("a", "s1", "g1", "v1")])
        stratum = analysis["strata"][0]
        for key in ("protection_effect", "missing_rate"):
            interval = stratum[key]["interval"]
            self.assertIsNotNone(interval)
            self.assertLessEqual(interval["low"], stratum[key]["estimate"])
            self.assertGreaterEqual(interval["high"], stratum[key]["estimate"])
            self.assertEqual(interval["level"], 0.95)
            self.assertEqual(interval["method"], "wilson_score")

    def test_wilson_interval_tightens_with_sample(self):
        small = wilson_interval(30, 40)
        large = wilson_interval(300, 400)
        self.assertLess(large[1] - large[0], small[1] - small[0])

    def test_empty_denominator_yields_full_range_not_zero(self):
        low, high = wilson_interval(0, 0)
        self.assertEqual((low, high), (0.0, 1.0))

    def test_percentage_rates_are_normalised(self):
        record = make("a", "s1", "g1", "v1", sample=100.0, protection=80.0, missing=25.0)
        analysis = build_stratified_analysis([record])
        stratum = analysis["strata"][0]
        self.assertAlmostEqual(stratum["protection_effect"]["estimate"], 0.8)
        self.assertAlmostEqual(stratum["missing_rate"]["estimate"], 0.25)


class EligibilityTests(unittest.TestCase):
    def test_no_validation_authorization_blocks_ranking(self):
        analysis = build_stratified_analysis([make("a", "s1", "g1", "v1", scope="research")])
        stratum = analysis["strata"][0]
        self.assertFalse(stratum["rankable"])
        self.assertIsNone(stratum["rank"])
        self.assertEqual([item["code"] for item in stratum["eligibility"]["reasons"]],
                         ["no_validation_authorization"])
        self.assertIsNone(stratum["protection_effect"]["estimate"])

    def test_insufficient_sample_blocks_ranking(self):
        analysis = build_stratified_analysis([make("a", "s1", "g1", "v1", sample=5.0)])
        stratum = analysis["strata"][0]
        self.assertFalse(stratum["rankable"])
        self.assertEqual([item["code"] for item in stratum["eligibility"]["reasons"]],
                         ["insufficient_validation_sample"])
        self.assertIn("minimum", stratum["eligibility"]["reasons"][0])

    def test_unauthorized_records_are_excluded_from_numerators(self):
        records = [make("a", "s1", "g1", "v1", sample=100.0, protection=0.9, missing=0.0),
                   make("b", "s1", "g1", "v1", sample=100.0, protection=0.1, missing=1.0,
                        scope="research")]
        analysis = build_stratified_analysis(records)
        stratum = analysis["strata"][0]
        self.assertEqual(stratum["authorization"]["validation_authorized_records"], 1)
        self.assertEqual(stratum["authorization"]["excluded_record_ids"], ["b"])
        self.assertAlmostEqual(stratum["protection_effect"]["denominator"], 50.0)
        self.assertAlmostEqual(stratum["protection_effect"]["estimate"], 0.9)
        self.assertTrue(any(w["code"] == "partial_validation_coverage"
                            for w in stratum["eligibility"]["warnings"]))

    def test_acceptance_fixture_is_not_ranked(self):
        analysis = build_stratified_analysis(acceptance_records())
        self.assertEqual(analysis["counts"]["rankable_strata"], 0)
        self.assertEqual(analysis["counts"]["validation_authorized_records"], 0)
        self.assertIsNone(analysis["overall_gap"]["value"])
        self.assertEqual(analysis["overall_gap"]["status"], "not_estimable")
        for stratum in analysis["strata"]:
            self.assertIsNone(stratum["rank"])


class RankingTests(unittest.TestCase):
    def cell(self, records):
        return [item for item in build_stratified_analysis(records)["comparisons"]]

    def test_separated_intervals_produce_ordinal_ranks(self):
        records = [
            make("a1", "s1", "g1", "v1", sample=100.0, protection=0.95),
            make("a2", "s2", "g1", "v1", sample=100.0, protection=0.55),
        ]
        comparison = self.cell(records)[0]
        self.assertEqual(comparison["status"], "compared")
        self.assertEqual(comparison["interval_overlap"], False)
        self.assertEqual([(row["rank"], row["data_space"]) for row in comparison["ranked_data_spaces"]],
                         [(1, "s1"), (2, "s2")])

    def test_overlapping_intervals_are_not_ranked(self):
        records = [
            make("a1", "s1", "g1", "v1", sample=20.0, protection=0.9),
            make("a2", "s2", "g1", "v1", sample=20.0, protection=0.6),
        ]
        # sample below threshold: both blocked, no ranking at all
        comparison = self.cell(records)[0]
        self.assertEqual(comparison["status"], "no_eligible_data_space")
        self.assertEqual(comparison["ranked_data_spaces"], [])

    def test_overlap_blocks_ranks_for_eligible_strata(self):
        records = [
            make("a1", "s1", "g1", "v1", sample=60.0, protection=0.7),
            make("a2", "s2", "g1", "v1", sample=60.0, protection=0.75),
        ]
        comparison = self.cell(records)[0]
        self.assertEqual(comparison["status"], "eligible_intervals_overlap")
        self.assertTrue(comparison["interval_overlap"])
        self.assertEqual(comparison["ranked_data_spaces"], [])
        self.assertEqual([row["data_space"] for row in comparison["eligible_but_unranked_data_spaces"]],
                         ["s1", "s2"])
        self.assertIsNotNone(comparison["protection_gap"])
        self.assertEqual(comparison["protection_gap_status"],
                         "point_estimate_with_overlapping_intervals")

    def test_single_eligible_space_is_not_ranked(self):
        records = [make("a1", "s1", "g1", "v1")]
        comparison = self.cell(records)[0]
        self.assertEqual(comparison["status"], "single_eligible_data_space")
        self.assertEqual(comparison["ranked_data_spaces"], [])
        self.assertIsNone(comparison["protection_gap"])
        self.assertEqual(comparison["eligible_but_unranked_data_spaces"][0]["reason"],
                         "no_comparison_partner")

    def test_ranking_never_crosses_group_or_version(self):
        records = [
            make("a1", "s1", "g1", "v1", protection=0.9),
            make("b1", "s1", "g1", "v1", protection=0.6),
            make("c1", "s1", "g1", "v2", protection=0.7),
            make("d1", "s1", "g2", "v1", protection=0.7),
        ]
        comparisons = self.cell(records)
        for comparison in comparisons:
            self.assertLessEqual(len(comparison["ranked_data_spaces"]), 1)
            self.assertNotEqual(comparison["status"], "compared")

    def test_not_rankable_strata_are_listed_with_reasons(self):
        records = [
            make("a1", "s1", "g1", "v1", sample=400.0, protection=0.9),
            make("b1", "s2", "g1", "v1", sample=400.0, protection=0.4),
            make("c1", "s3", "g1", "v1", scope="research"),
        ]
        comparison = self.cell(records)[0]
        self.assertEqual(comparison["status"], "compared")
        self.assertEqual(comparison["not_ranked_data_spaces"][0]["data_space"], "s3")
        self.assertEqual(comparison["not_ranked_data_spaces"][0]["reasons"],
                         ["no_validation_authorization"])


class DecisionBasisTests(unittest.TestCase):
    def test_decision_basis_mirrors_analysis(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        analysis = build_stratified_analysis(records)
        stratum = stratum_for(records[0], analysis)
        basis = decision_basis(analysis, stratum)
        self.assertEqual(basis["hash"], analysis["basis"]["hash"])
        self.assertEqual(basis["stratum"], {"data_space": "s1", "subject_group": "g1",
                                            "classification_version": "v1"})
        self.assertEqual(basis["denominators"], stratum["denominators"])
        self.assertEqual(basis["protection_effect"]["estimate"],
                         stratum["protection_effect"]["estimate"])

    def test_decide_records_the_shared_basis(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        analysis = build_stratified_analysis(records)
        from data_permit.lifecycle.permit_cycle import decide
        result = decide(records[0], {"analysis": analysis})
        self.assertEqual(result.analysis_basis["hash"], analysis["basis"]["hash"])
        self.assertEqual(result.record_content_hash, records[0].content_hash)
        self.assertTrue(any(reason.startswith("stratum=") for reason in result.reasons))

    def test_decision_serialises_basis_round_trip(self):
        from data_permit.applications.permit_contract import Decision
        records = [make("a", "s1", "g1", "v1")]
        analysis = build_stratified_analysis(records)
        from data_permit.lifecycle.permit_cycle import decide
        decision = decide(records[0], {"analysis": analysis})
        restored = Decision.from_dict(decision.as_dict())
        self.assertEqual(restored.fingerprint, decision.fingerprint)
        self.assertEqual(restored.analysis_basis, decision.analysis_basis)


class BundleAndReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "run.sqlite3"
        self.output = self.root / "output"

    def write(self, name, fixture):
        path = self.root / name
        path.write_text(json.dumps(fixture), encoding="utf-8")
        return path

    def fixture(self, records, occurred_at=None):
        payload = {"scenario": "test", "synthetic": True, "records": [
            {"record_id": r.record_id, "payload": r.payload, "state": "proposed",
             "source": r.source, **({"occurred_at": occurred_at} if occurred_at else {})}
            for r in records]}
        return payload

    def test_bundle_contains_analysis_and_decisions_share_basis(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        result = run(self.write("f.json", self.fixture(records)), self.database, self.output)
        analysis = json.loads((self.output / "stratified-analysis.json").read_text(encoding="utf-8"))
        decisions = json.loads((self.output / "decisions.json").read_text(encoding="utf-8"))
        summary = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        expected = analysis["basis"]["hash"]
        self.assertEqual(result["analysis_basis"]["hash"], expected)
        self.assertEqual(analysis_hash(analysis), expected)
        self.assertEqual(summary["analysis_basis"]["hash"], expected)
        for decision in decisions:
            self.assertEqual(decision["analysis_basis"]["hash"], expected)
        self.assertEqual(verify_bundle(self.output), [])
        self.assertTrue(verify(self.database, self.output)["ok"])

    def test_bundle_analysis_tampering_is_detected(self):
        records = [make("a", "s1", "g1", "v1")]
        run(self.write("f.json", self.fixture(records)), self.database, self.output)
        path = self.output / "stratified-analysis.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["thresholds"]["min_validation_sample"] = 1.0
        path.write_text(json.dumps(document), encoding="utf-8")
        errors = verify_bundle(self.output)
        self.assertTrue(any("stratified-analysis.json" in error for error in errors))

    def test_identical_resubmission_keeps_decision_and_versions(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        first = run(self.write("f1.json", self.fixture(records)), self.database, self.output)
        repository = Repository(self.database)
        before = repository.snapshot()["counts"]
        before_decisions = [(d["record_id"], d["decided_at"]) for d in repository.decision_rows()]
        second = run(self.write("f2.json", self.fixture(records, occurred_at="2020-01-01T00:00:00+00:00")),
                     self.database, self.output)
        after = repository.snapshot()["counts"]
        self.assertEqual(first["analysis_basis"]["hash"], second["analysis_basis"]["hash"])
        self.assertEqual(after["record_versions"], before["record_versions"])
        self.assertEqual(after["decisions"], before["decisions"])
        self.assertEqual([(d["record_id"], d["decided_at"]) for d in repository.decision_rows()],
                         before_decisions)

    def test_correction_supersedes_prior_decision_and_keeps_it(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        run(self.write("f1.json", self.fixture(records)), self.database, self.output)
        repository = Repository(self.database)
        prior_a = repository.latest_decision("a")
        prior_b = repository.latest_decision("b")
        corrected = [make("a", "s1", "g1", "v1", protection=0.2), records[1]]
        result = run(self.write("f2.json", self.fixture(corrected)), self.database, self.output)
        latest_a = repository.latest_decision("a")
        latest_b = repository.latest_decision("b")
        self.assertNotEqual(latest_a["record_content_hash"], prior_a["record_content_hash"])
        self.assertEqual(latest_a["supersedes"], stable_hash(prior_a))
        # Record b's content is unchanged, but its decision cited the earlier
        # analysis basis; the corrected basis re-issues it as an explicit
        # successor rather than rewriting history.
        self.assertEqual(latest_b["record_content_hash"], prior_b["record_content_hash"])
        self.assertNotEqual(latest_b["analysis_basis"]["hash"], prior_b["analysis_basis"]["hash"])
        self.assertEqual(latest_b["supersedes"], stable_hash(prior_b))
        self.assertEqual(repository.snapshot()["counts"]["decisions"], 4)
        history = [d for d in repository.decision_rows() if d["record_id"] == "a"]
        self.assertEqual(len(history), 2)
        self.assertTrue(any(d["supersedes"] == "" for d in history))

    def test_correction_is_not_silently_reapplied(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        run(self.write("f1.json", self.fixture(records)), self.database, self.output)
        corrected = [make("a", "s1", "g1", "v1", protection=0.2), records[1]]
        path = self.write("f2.json", self.fixture(corrected))
        run(path, self.database, self.output)
        repository = Repository(self.database)
        after_first = repository.snapshot()["counts"]
        run(path, self.database, self.output)
        run(path, self.database, self.output)
        after_repeat = repository.snapshot()["counts"]
        self.assertEqual(after_first["decisions"], after_repeat["decisions"])
        self.assertEqual(after_first["record_versions"], after_repeat["record_versions"])

    def test_decisions_cite_analyses_that_are_stored(self):
        records = [make("a", "s1", "g1", "v1"), make("b", "s2", "g1", "v1", protection=0.6)]
        run(self.write("f.json", self.fixture(records)), self.database, self.output)
        repository = Repository(self.database)
        for decision in repository.decision_rows():
            basis = decision["analysis_basis"]["hash"]
            self.assertIsNotNone(repository.get_analysis(basis))

    def test_summary_qualifies_aggregate_score(self):
        records = [make("a", "s1", "g1", "v1")]
        run(self.write("f.json", self.fixture(records)), self.database, self.output)
        summary = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        self.assertIn("score_note", summary)
        self.assertIn("overall_gap", summary["analysis_basis"])
        self.assertIn("counts", summary["analysis_basis"])


if __name__ == "__main__":
    unittest.main()
