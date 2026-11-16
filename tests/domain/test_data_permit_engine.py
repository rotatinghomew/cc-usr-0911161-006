from __future__ import annotations

import unittest
from data_permit.applications.permit_contract import DomainRecord
from data_permit.privacy.group_guard import cohort_metrics, consent_allows, stratified_gap, wilson_interval


class CohortGuardTests(unittest.TestCase):
    def record(self, key, group="a"):
        return DomainRecord(key, {"data_space": "h", "subject_group": group, "purpose_code": "c", "sample_size": 200,
            "sensitive_share": .2, "authorization_scope": "validation,research", "classification_version": "1", "missing_rate": .05,
            "protection_strength": .9, "audit_coverage": .85, "incident_count": 1, "review_authority": "rb"})

    def test_intervals_and_consent(self):
        low, high = wilson_interval(90, 100)
        self.assertLess(low, high)
        self.assertTrue(consent_allows(self.record("a"), "validation"))
        self.assertGreater(cohort_metrics(self.record("a"))["protection_strength_low"], 0.0)

    def test_stratified_gap(self):
        self.assertEqual(stratified_gap([self.record("a", "x"), self.record("b", "y")])["group_count"], 2.0)
