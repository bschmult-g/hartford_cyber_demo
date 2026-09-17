"""
Unit tests for Google Cloud Threat Intelligence (Mandiant) integration.
"""

import unittest
from services.threat_intel import get_all_sector_profiles, assess_applicant_posture_against_threats

class TestThreatIntel(unittest.TestCase):

    def test_get_all_sector_profiles(self):
        sectors = get_all_sector_profiles()
        self.assertGreaterEqual(len(sectors), 5)
        sector_ids = [s["id"] for s in sectors]
        self.assertIn("legal_accounting", sector_ids)
        self.assertIn("healthcare", sector_ids)
        self.assertIn("financial_services", sector_ids)
        self.assertIn("retail_hospitality", sector_ids)
        self.assertIn("technology_saas", sector_ids)

    def test_assess_applicant_posture_secure_tenant(self):
        telemetry = {
            "mfa_enforced": True,
            "mfa_enrolled_pct": 100.0,
            "mfa_method_tier": "FIDO2_SECURITY_KEY",
            "dmarc_policy": "reject",
            "spf_valid": True,
            "dkim_record_present": True,
            "super_admin_count": 2,
            "dormant_user_count": 0,
            "device_count": 20,
            "device_encryption_pct": 100.0,
            "screen_lock_enforced": True,
            "dlp_rules_active": True,
            "vault_retention_active": True
        }
        assessment = assess_applicant_posture_against_threats(telemetry, "legal_accounting")
        self.assertEqual(assessment["underwriter_verdict"], "PREFERRED_RISK_APPROVED")
        self.assertGreaterEqual(assessment["posture_fit_score"], 85)
        self.assertGreaterEqual(assessment["mitigated_vectors_count"], 3)

    def test_assess_applicant_posture_insecure_tenant(self):
        telemetry = {
            "mfa_enforced": False,
            "mfa_enrolled_pct": 15.0,
            "mfa_method_tier": "SMS_WEAK",
            "dmarc_policy": "missing",
            "spf_valid": False,
            "dkim_record_present": False,
            "super_admin_count": 8,
            "dormant_user_count": 5,
            "device_encryption_pct": 0.0,
            "screen_lock_enforced": False,
            "dlp_rules_active": False,
            "vault_retention_active": False
        }
        assessment = assess_applicant_posture_against_threats(telemetry, "legal_accounting")
        self.assertEqual(assessment["underwriter_verdict"], "DECLINE_OR_REFER")
        self.assertLess(assessment["posture_fit_score"], 50)
        self.assertLessEqual(assessment["mitigated_vectors_count"], 1)

if __name__ == "__main__":
    unittest.main()
