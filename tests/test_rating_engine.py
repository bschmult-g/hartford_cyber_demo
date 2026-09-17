"""
Unit tests for The Hartford cyber underwriting rating engine.
"""

import unittest
from services.rating_engine import evaluate_risk

class TestRatingEngine(unittest.TestCase):

    def test_secure_tenant_receives_preferred_tier(self):
        telemetry = {
            "mfa_enforced": True,
            "mfa_enrolled_pct": 100.0,
            "spf_valid": True,
            "dmarc_policy": "reject",
            "dlp_rules_active": True,
            "vault_retention_active": True,
            "super_admin_count": 2,
            "device_count": 30,
            "device_encryption_pct": 100.0,
            "screen_lock_enforced": True,
            "data_source": "preset_scenario_simulation",
            "delegation_verified": True
        }
        rating = evaluate_risk(telemetry)
        self.assertEqual(rating["decision"], "APPROVED")
        self.assertEqual(rating["tier"], "PREFERRED_RISK")
        self.assertGreaterEqual(rating["total_discount_pct"], 25.0)
        self.assertLess(rating["final_annual_premium"], rating["base_premium"])
        self.assertEqual(len(rating["remediations"]), 0)
        self.assertGreater(len(rating["credits"]), 3)

    def test_vulnerable_tenant_receives_substandard_or_declined(self):
        telemetry = {
            "mfa_enforced": False,
            "mfa_enrolled_pct": 18.0,
            "spf_valid": False,
            "dmarc_policy": "missing",
            "dlp_rules_active": False,
            "vault_retention_active": False,
            "data_source": "preset_scenario_simulation",
            "delegation_verified": True
        }
        rating = evaluate_risk(telemetry)
        self.assertIn(rating["decision"], ["DECLINED", "CONDITIONAL_APPROVAL"])
        self.assertEqual(rating["tier"], "HIGH_RISK")
        self.assertGreater(len(rating["remediations"]), 0)

    def test_gcp_api_disabled_blocks_with_action_required(self):
        telemetry = {
            "data_source": "live_google_workspace_api",
            "delegation_verified": False,
            "rbac_block_cause": "GCP_API_DISABLED",
            "rbac_block_detail": "Admin SDK API is disabled in GCP project 799321431260"
        }
        rating = evaluate_risk(telemetry)
        self.assertEqual(rating["decision"], "GCP_CONFIGURATION_REQUIRED")
        self.assertEqual(rating["tier"], "GCP_CONFIG_ERROR")
        self.assertIn("Google Cloud API Disabled", rating["tier_display"])

    def test_consumer_account_blocks_with_ineligible(self):
        telemetry = {
            "data_source": "live_google_workspace_api",
            "delegation_verified": False,
            "verified_account": "user@gmail.com",
            "rbac_block_cause": "CONSUMER_ACCOUNT"
        }
        rating = evaluate_risk(telemetry)
        self.assertEqual(rating["decision"], "CONSUMER_ACCOUNT_INELIGIBLE")
        self.assertEqual(rating["tier"], "CONSUMER_GMAIL")

    def test_standard_user_blocks_with_insufficient_delegation(self):
        telemetry = {
            "data_source": "live_google_workspace_api",
            "delegation_verified": False,
            "verified_account": "employee@midsizecorp.com",
            "rbac_block_cause": "WORKSPACE_ROLE_STANDARD"
        }
        rating = evaluate_risk(telemetry)
        self.assertEqual(rating["decision"], "INSUFFICIENT_DELEGATION")
        self.assertEqual(rating["tier"], "UNVERIFIED_ROLE")

if __name__ == "__main__":
    unittest.main()
