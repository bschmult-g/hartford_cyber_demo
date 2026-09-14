"""
Project Beacon - Automated Cyber Underwriting Microservice
The Hartford (HIG) & Google Cloud Proof of Technology
"""

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from services.telemetry import collect_telemetry, check_email_security
from services.rating_engine import evaluate_risk
from services.attestation import generate_attestation_receipt

app = FastAPI(
    title="Project Beacon - The Hartford Cyber Underwriting",
    description="Automated cyber underwriting via Google Workspace & DNS telemetry",
    version="1.0.0"
)

# Request Models
class UnderwritingRequest(BaseModel):
    domain: str = Field(..., description="Applicant domain, e.g. foremycorp.com")
    organization_name: str = Field(..., description="Registered business name")
    profile_override: Optional[str] = Field(None, description="Preset scenario override")

class WhatIfRequest(BaseModel):
    mfa_enforced: bool = True
    mfa_enrolled_pct: float = 100.0
    spf_valid: bool = True
    dmarc_policy: str = "reject"
    dlp_rules_active: bool = True
    vault_retention_active: bool = True

@app.post("/api/underwrite")
async def perform_underwriting(req: UnderwritingRequest):
    """
    Executes end-to-end automated cyber underwriting:
    1. Collects ephemeral Google Workspace & DNS telemetry.
    2. Evaluates posture against Hartford cyber rating rules.
    3. Issues cryptographic zero-retention attestation receipt.
    """
    clean_domain = req.domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
        
    telemetry = await collect_telemetry(
        domain=clean_domain,
        organization_name=req.organization_name,
        profile_override=req.profile_override
    )
    
    rating = evaluate_risk(telemetry)
    attestation = generate_attestation_receipt(telemetry, rating)
    
    return {
        "status": "success",
        "telemetry": telemetry,
        "rating": rating,
        "attestation": attestation
    }

@app.post("/api/simulate-what-if")
async def simulate_what_if(req: WhatIfRequest):
    """
    Simulates real-time rating changes when underwriter or applicant toggles controls.
    """
    simulated_telemetry = {
        "mfa_enforced": req.mfa_enforced,
        "mfa_enrolled_pct": req.mfa_enrolled_pct,
        "spf_valid": req.spf_valid,
        "dmarc_policy": req.dmarc_policy,
        "dlp_rules_active": req.dlp_rules_active,
        "vault_retention_active": req.vault_retention_active,
    }
    
    rating = evaluate_risk(simulated_telemetry)
    return {
        "status": "success",
        "simulated_telemetry": simulated_telemetry,
        "rating": rating
    }

@app.get("/api/dns-live-check")
async def probe_dns_live(domain: str = Query(..., description="Target domain, e.g. thehartford.com")):
    """
    Resolves live SPF, DMARC, and DKIM DNS records for any live domain in real time.
    """
    clean_domain = domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain required")
    
    res = await check_email_security(clean_domain)
    return {
        "status": "success",
        "dns_posture": res
    }

# Mount static frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_index():
    return FileResponse("static/index.html")

if __name__ == "__main__":
    # Localhost binding only as required by security guidelines
    uvicorn.run(app, host="127.0.0.1", port=8000)
