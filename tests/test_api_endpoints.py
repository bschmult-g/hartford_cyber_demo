"""
API endpoint tests for Project Beacon FastAPI service.
"""

import unittest
from starlette.testclient import TestClient
from app import app

class TestApiEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_serve_index(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Project Beacon", response.content)

    def test_no_cache_headers(self):
        response = self.client.get("/")
        self.assertIn("Cache-Control", response.headers)
        self.assertIn("no-cache", response.headers["Cache-Control"])

    def test_underwrite_empty_domain_fails(self):
        response = self.client.post("/api/underwrite", json={"domain": "", "organization_name": "Test Org"})
        self.assertEqual(response.status_code, 400)

    def test_underwrite_preset_scenario_succeeds(self):
        response = self.client.post("/api/underwrite", json={
            "domain": "foremycorp.com",
            "organization_name": "Foremy Corp",
            "profile_override": "foremycorp.com"
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("telemetry", data)
        self.assertIn("rating", data)
        self.assertIn("attestation", data)
        self.assertEqual(data["rating"]["decision"], "APPROVED")

    def test_simulate_what_if(self):
        response = self.client.post("/api/simulate-what-if", json={
            "mfa_enforced": True,
            "mfa_enrolled_pct": 100.0,
            "spf_valid": True,
            "dmarc_policy": "reject",
            "dlp_rules_active": True,
            "vault_retention_active": True
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["rating"]["decision"], "APPROVED")

    def test_threat_intel_sectors(self):
        response = self.client.get("/api/threat-intel/sectors")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(len(data["sectors"]), 5)

    def test_threat_intel_assess(self):
        response = self.client.post("/api/threat-intel/assess", json={
            "telemetry": {
                "mfa_enforced": True,
                "mfa_enrolled_pct": 100.0,
                "dmarc_policy": "reject"
            },
            "industry_key": "legal_accounting"
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("posture_fit_score", data["assessment"])
        self.assertIn("underwriter_verdict", data["assessment"])

if __name__ == "__main__":
    unittest.main()
