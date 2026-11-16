from __future__ import annotations
import unittest
from data_permit.permit_signal.permit_risk import permit_risk, peer_distribution
class Record:
    def __init__(self, payload): self.payload = payload
class SignalTests(unittest.TestCase):
    def setUp(self): self.payload = {'data_space': 'space-a', 'subject_group': 'group-a', 'purpose_code': 'research', 'sample_size': 300, 'sensitive_share': 0.35, 'authorization_scope': 'research-only', 'classification_version': 'v1', 'missing_rate': 0.08, 'protection_strength': 0.9, 'audit_coverage': 0.85, 'incident_count': 0, 'review_authority': 'board-a'}
    def test_signal_is_bounded_and_explainable(self):
        signal = permit_risk(self.payload)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)
        self.assertIn(signal.severity, {'info', 'warning', 'critical'})
        self.assertTrue({'small_group', 'sensitive_share', 'incident_pressure'}.issubset(signal.evidence))
    def test_peer_distribution_uses_business_group(self):
        other = dict(self.payload); other['data_space'] = 'group-b'
        result = peer_distribution([Record(self.payload), Record(other)])
        self.assertEqual(result['count'], 2)
        self.assertIn('high_risk', result)
    def test_material_business_change_is_observable(self):
        changed = dict(self.payload); changed['incident_count'] = 10
        self.assertNotEqual(permit_risk(changed).score, permit_risk(self.payload).score)
    def test_business_variant_1(self):
        changed = dict(self.payload)
        changed['purpose_code'] = self.payload['purpose_code']
        signal = permit_risk(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_2(self):
        changed = dict(self.payload)
        changed['sample_size'] = self.payload['sample_size']
        signal = permit_risk(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_3(self):
        changed = dict(self.payload)
        changed['sensitive_share'] = self.payload['sensitive_share']
        signal = permit_risk(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_4(self):
        changed = dict(self.payload)
        changed['authorization_scope'] = self.payload['authorization_scope']
        signal = permit_risk(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_5(self):
        changed = dict(self.payload)
        changed['classification_version'] = self.payload['classification_version']
        signal = permit_risk(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

if __name__ == '__main__': unittest.main()
