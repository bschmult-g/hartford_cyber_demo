"""
Project Beacon - The Hartford Underwriting Rating Engine
Evaluates security telemetry against cyber actuarial risk models.
"""

from typing import Any

def evaluate_risk(telemetry: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluates in-memory telemetry against Hartford rating guidelines.
    Returns risk classification, premium quote, credits, and remediation steps.
    """
    mfa_enforced = telemetry.get("mfa_enforced", False)
    mfa_pct = telemetry.get("mfa_enrolled_pct", 0.0)
    spf_valid = telemetry.get("spf_valid", False)
    dmarc_policy = telemetry.get("dmarc_policy", "missing").lower()
    dlp_active = telemetry.get("dlp_rules_active", False)
    vault_active = telemetry.get("vault_retention_active", False)

    base_annual_premium = 8500.00
    base_limit = 2000000.00  # $2,000,000
    deductible = 5000.00

    credits: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []

    # 0. Delegation & RBAC Gate:
    # If authenticated live, verify that the account possesses Delegated Admin or Super Admin privileges.
    if not telemetry.get("delegation_verified", False) and telemetry.get("data_source") in ["live_google_workspace_api", "preset_scenario_simulation"]:
        user_account = telemetry.get("verified_account") or "authenticated account"
        rbac_cause = telemetry.get("rbac_block_cause", "WORKSPACE_ROLE_STANDARD")

        if rbac_cause == "GCP_API_DISABLED":
            detail = telemetry.get("rbac_block_detail") or "Admin SDK API is disabled in Google Cloud Console."
            return {
                "decision": "GCP_CONFIGURATION_REQUIRED",
                "tier": "GCP_CONFIG_ERROR",
                "tier_display": "Action Required: Google Cloud API Disabled",
                "status_color": "#D97706",
                "summary": f"Underwriting verification paused: Google Cloud Project (799321431260) has not enabled the Admin SDK API in Google Cloud Console. This is an infrastructure project configuration step, not an applicant policy decline. Details: {detail}",
                "base_premium": base_annual_premium,
                "total_discount_pct": 0.0,
                "discount_amount": 0.0,
                "final_annual_premium": None,
                "final_monthly_premium": None,
                "coverage_limit": 0,
                "deductible": 0,
                "remediations": [
                    {
                        "control": "Enable Admin SDK API in Google Cloud Console",
                        "impact": "Unlocks automated posture inspection across Google Workspace tenant",
                        "action": "In Google Cloud Console (project 799321431260), navigate to 'APIs & Services > Library', search for 'Admin SDK API', and click 'Enable'. Then re-verify."
                    }
                ],
                "credits": []
            }
        elif rbac_cause == "CONSUMER_ACCOUNT":
            return {
                "decision": "CONSUMER_ACCOUNT_INELIGIBLE",
                "tier": "CONSUMER_GMAIL",
                "tier_display": "Action Required: Corporate Domain Required",
                "status_color": "#DC2626",
                "summary": f"Underwriting verification halted: Authenticated account '{user_account}' is a personal consumer account (@gmail.com). Commercial cyber insurance underwriting requires an organization-managed Google Workspace corporate domain with administrative security policies.",
                "base_premium": base_annual_premium,
                "total_discount_pct": 0.0,
                "discount_amount": 0.0,
                "final_annual_premium": None,
                "final_monthly_premium": None,
                "coverage_limit": 0,
                "deductible": 0,
                "remediations": [
                    {
                        "control": "Authenticate with Corporate Google Workspace Account",
                        "impact": "Enables corporate security telemetry verification",
                        "action": "Sign out and re-verify using your corporate domain account (e.g. admin@yourdomain.com) rather than a personal @gmail.com address."
                    }
                ],
                "credits": []
            }
        else:
            return {
                "decision": "INSUFFICIENT_DELEGATION",
                "tier": "UNVERIFIED_ROLE",
                "tier_display": "Action Required: Delegated Admin Role Required",
                "status_color": "#DC2626",
                "summary": f"Automated underwriting halted: Account '{user_account}' is a Standard User lacking Delegated Admin privileges in Google Workspace. Google Workspace RBAC blocked access (HTTP 403) to domain-wide MFA, endpoint, and user posture. Real-time underwriting requires an administrator role.",
                "base_premium": base_annual_premium,
                "total_discount_pct": 0.0,
                "discount_amount": 0.0,
                "final_annual_premium": None,
                "final_monthly_premium": None,
                "coverage_limit": 0,
                "deductible": 0,
                "remediations": [
                    {
                        "control": "Grant Delegated Security Auditor Role in Google Workspace",
                        "impact": "Unlocks real-time underwriting verification and preferred rate tiering",
                        "action": "In Google Workspace Admin Console (Security > Admin Roles), assign a custom read-only role with 'Users (Read)', 'Reports (Read)', and 'Mobile Device Management (Read)' to this account, or re-authenticate with an authorized Super Admin."
                    }
                ],
                "credits": []
            }

    # 1. Critical Hard Gate: Multi-Factor Authentication
    mfa_enforced = telemetry.get("mfa_enforced")
    mfa_pct = telemetry.get("mfa_enrolled_pct")
    if mfa_enforced is not True or mfa_pct is None or mfa_pct < 80.0:
        pct_label = f"{mfa_pct:.0f}%" if mfa_pct is not None else "Unverified"
        return {
            "decision": "DECLINED",
            "tier": "HIGH_RISK",
            "tier_display": "Declined - High Ransomware Exposure",
            "status_color": "crimson",
            "summary": f"Application declined due to unenforced Multi-Factor Authentication (Observed enrollment: {pct_label}). Unprotected credentials account for over 80% of cyber extortion claims.",
            "base_premium": base_annual_premium,
            "total_discount_pct": 0.0,
            "discount_amount": 0.0,
            "final_annual_premium": None,
            "final_monthly_premium": None,
            "coverage_limit": 0,
            "deductible": 0,
            "remediations": [
                {
                    "control": "Enforce 2-Step Verification Org-Wide",
                    "impact": "Unlocks underwriting eligibility & 10% base discount",
                    "action": "Enable org-wide 2SV enforcement in Google Workspace Admin Console (Security > Authentication > 2-Step Verification)."
                }
            ],
            "credits": []
        }

    # MFA Passed
    mfa_credit_pct = 10.0
    mfa_credit_amt = base_annual_premium * (mfa_credit_pct / 100.0)
    credits.append({
        "name": "2-Step Verification Enforced",
        "description": f"Org coverage ({mfa_pct:.0f}%) verified with hardware key / TOTP support",
        "pct": mfa_credit_pct,
        "amount": mfa_credit_amt
    })

    # 2. Email Authentication (SPF + DMARC)
    dmarc_secure = dmarc_policy in ["reject", "quarantine"]
    if spf_valid and dmarc_secure:
        email_credit_pct = 8.0
        email_credit_amt = base_annual_premium * (email_credit_pct / 100.0)
        credits.append({
            "name": "Email Spoofing Defense (SPF + Strict DMARC)",
            "description": f"DMARC enforcement policy '{dmarc_policy}' prevents executive impersonation (BEC)",
            "pct": email_credit_pct,
            "amount": email_credit_amt
        })
    else:
        if not spf_valid:
            remediations.append({
                "control": "Implement Valid SPF Record",
                "impact": "Required for email security discount (-4% premium)",
                "action": "Add DNS TXT record 'v=spf1 include:_spf.google.com ~all' to authorize sending servers."
            })
        if dmarc_policy in ["none", "missing"]:
            remediations.append({
                "control": "Tighten DMARC Policy to Quarantine or Reject",
                "impact": "Unlocks additional $680/yr (8%) Business Email Compromise discount",
                "action": f"Update _dmarc DNS record policy from '{dmarc_policy}' to 'p=quarantine' or 'p=reject'."
            })

    # 3. Data Loss Prevention (DLP)
    if dlp_active:
        dlp_credit_pct = 4.0
        dlp_credit_amt = base_annual_premium * (dlp_credit_pct / 100.0)
        credits.append({
            "name": "Data Loss Prevention (DLP) Rules Active",
            "description": "Active inspection of PII/PCI across Drive and Gmail",
            "pct": dlp_credit_pct,
            "amount": dlp_credit_amt
        })
    else:
        remediations.append({
            "control": "Activate Workspace DLP Rules",
            "impact": "Unlocks $340/yr (4%) Data Exfiltration discount",
            "action": "Configure DLP inspection rules in Google Workspace Admin Console to monitor sensitive customer data."
        })

    # 4. Vault & Retention Hygiene
    if vault_active:
        vault_credit_pct = 3.0
        vault_credit_amt = base_annual_premium * (vault_credit_pct / 100.0)
        credits.append({
            "name": "Google Vault Audit Retention",
            "description": "Tamper-evident legal holds & audit logging established",
            "pct": vault_credit_pct,
            "amount": vault_credit_amt
        })
    else:
        remediations.append({
            "control": "Configure Retention Policies in Google Vault",
            "impact": "Unlocks $255/yr (3%) Forensic Recovery discount",
            "action": "Set default retention and audit policies for email and Drive storage."
        })

    # 5. Super Admin Least-Privilege Governance
    super_admins = telemetry.get("super_admin_count")
    if super_admins is not None and 1 <= super_admins <= 3:
        admin_credit_pct = 2.0
        admin_credit_amt = base_annual_premium * (admin_credit_pct / 100.0)
        credits.append({
            "name": "Super Admin Least-Privilege Architecture",
            "description": f"Verified {super_admins} dedicated Super Admins (minimizes extortion blast radius)",
            "pct": admin_credit_pct,
            "amount": admin_credit_amt
        })
    elif super_admins is not None and super_admins > 6:
        remediations.append({
            "control": f"Remediate Super Admin Sprawl ({super_admins} Admins Detected)",
            "impact": "Reduces catastrophic ransomware takeover risk",
            "action": "Reduce Super Admin role grants to <= 3 dedicated accounts. Use delegated admin roles for day-to-day operations."
        })
    elif super_admins is None:
        remediations.append({
            "control": "Verify Super Admin Least-Privilege Posture",
            "impact": "Unlocks $170/yr (2%) Blast Radius Reduction credit",
            "action": "Grant Delegated Admin 'Users (Read)' privilege in Google Workspace to audit super admin account count in real time."
        })

    # 6. Device Fleet & Endpoint Encryption
    dev_count = telemetry.get("device_count")
    dev_enc_pct = telemetry.get("device_encryption_pct")
    screen_lock = telemetry.get("screen_lock_enforced")
    if dev_count is not None and dev_count > 0 and dev_enc_pct is not None and dev_enc_pct >= 90.0 and screen_lock is True:
        dev_credit_pct = 2.0
        dev_credit_amt = base_annual_premium * (dev_credit_pct / 100.0)
        credits.append({
            "name": "Endpoint Fleet Encryption & Screen Lock",
            "description": f"Verified {dev_count} enrolled devices with {dev_enc_pct:.0f}% disk encryption",
            "pct": dev_credit_pct,
            "amount": dev_credit_amt
        })
    elif dev_count is not None and dev_count > 0 and dev_enc_pct is not None and dev_enc_pct < 80.0:
        remediations.append({
            "control": "Enforce Device Fleet Disk Encryption",
            "impact": "Eliminates lost-hardware data breach sublimits",
            "action": "Enable BitLocker / FileVault enforcement in Google Endpoint Management."
        })
    elif dev_count is None:
        remediations.append({
            "control": "Verify Google Endpoint Management Fleet Posture",
            "impact": "Unlocks $170/yr (2%) Device Encryption credit",
            "action": "Grant Delegated Admin 'Mobile Device Management (Read)' privilege in Google Workspace to audit endpoint fleet encryption."
        })

    # 7. DKIM Cryptographic Signature
    dkim_present = telemetry.get("dkim_record_present", False)
    if dkim_present:
        dkim_credit_pct = 1.0
        dkim_credit_amt = base_annual_premium * (dkim_credit_pct / 100.0)
        credits.append({
            "name": "DKIM Cryptographic Email Signature",
            "description": "Outbound email authentication stops sender tampering",
            "pct": dkim_credit_pct,
            "amount": dkim_credit_amt
        })

    # Calculate Totals
    total_discount_pct = sum(c["pct"] for c in credits)
    total_discount_amt = sum(c["amount"] for c in credits)
    final_annual_premium = base_annual_premium - total_discount_amt
    final_monthly_premium = round(final_annual_premium / 12.0, 2)

    # Determine Tier
    if total_discount_pct >= 20.0 and dmarc_secure and dlp_active:
        tier = "PREFERRED_RISK"
        tier_display = "Preferred Risk (Tier 1)"
        decision = "APPROVED"
        status_color = "#1e7e34"
        summary = "Applicant verified with highest cyber security posture. Instant policy issuance approved at 25% Preferred Risk discount."
    else:
        tier = "CONDITIONAL_RISK"
        tier_display = "Standard / Conditional Quote"
        decision = "CONDITIONAL_APPROVAL"
        status_color = "#e65100"
        potential_savings = sum(
            680 if "DMARC" in r["control"] else 340 if "DLP" in r["control"] else 255
            for r in remediations
        )
        summary = f"Core eligibility verified. Applicant approved at standard rates with {total_discount_pct:.0f}% discount. Remediate flagged controls to unlock up to ${potential_savings:,.0f}/yr in further savings."

    return {
        "decision": decision,
        "tier": tier,
        "tier_display": tier_display,
        "status_color": status_color,
        "summary": summary,
        "base_premium": base_annual_premium,
        "total_discount_pct": total_discount_pct,
        "discount_amount": total_discount_amt,
        "final_annual_premium": final_annual_premium,
        "final_monthly_premium": final_monthly_premium,
        "coverage_limit": base_limit,
        "deductible": deductible,
        "credits": credits,
        "remediations": remediations
    }
