"""
Unit tests for Project Beacon ephemeral zero-retention attestation service.
"""

import unittest
from services.attestation import generate_attestation_receipt

class TestAttestation(unittest.TestCase):

    def test_attestation_generation_and_hash(self):
        telemetry = {
            "domain": "foremycorp.com",
            "mfa_enforced": True,
            "spf_valid": True,
            "dmarc_policy": "reject",
            "dlp_rules_active": True,
            "vault_retention_active": True
        }
        rating = {
            "decision": "APPROVED",
            "tier": "PREFERRED"
        }

        receipt = generate_attestation_receipt(telemetry, rating)

        self.assertTrue(receipt["verification_id"].startswith("BEACON-VERIF-"))
        self.assertTrue(receipt["policy_attestation_token"].startswith("hig_gcp_attest_"))
        self.assertEqual(len(receipt["sha256_fingerprint"]), 64)
        self.assertEqual(receipt["domain"], "foremycorp.com")
        self.assertEqual(receipt["rating_tier"], "PREFERRED")
        self.assertTrue(receipt["verified_claims"]["approved"])
        self.assertFalse(receipt["zero_retention_guarantee"]["raw_configuration_stored"])
        self.assertEqual(receipt["zero_retention_guarantee"]["ephemeral_lifecycle_policy"], "DISCARD_ON_COMPLETION")

if __name__ == "__main__":
    unittest.main()
