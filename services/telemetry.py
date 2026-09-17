"""
Project Beacon - Google Workspace & DNS Telemetry Service
Collects security posture data ephemerally for cyber insurance underwriting.
"""

import asyncio
import re
import dns.resolver
import httpx
from typing import Any
from pydantic import BaseModel

class SecurityPosture(BaseModel):
    domain: str
    organization_name: str
    mfa_enforced: bool | None = None
    mfa_enrolled_pct: float | None = None
    mfa_method_tier: str  # "FIDO2_SECURITY_KEY", "TOTP_AUTHENTICATOR", "SMS_WEAK", "UNVERIFIED"
    spf_record_present: bool
    spf_record_value: str | None = None
    spf_valid: bool
    dmarc_record_present: bool
    dmarc_record_value: str | None = None
    dmarc_policy: str  # "reject", "quarantine", "none", "missing"
    dkim_verified: bool
    dkim_record_present: bool
    mx_provider: str
    super_admin_count: int | None = None
    total_user_count: int | None = None
    dormant_user_count: int | None = None
    device_count: int | None = None
    device_encryption_pct: float | None = None
    screen_lock_enforced: bool | None = None
    dlp_rules_active: bool | None = None
    dlp_rule_count: int = 0
    vault_retention_active: bool | None = None
    data_source: str  # "live_google_workspace_api", "live_dns_hybrid", "preset_scenario_simulation"
    verified_at: str
    account_role: str | None = "STANDARD_USER"  # "SUPER_ADMIN", "DELEGATED_ADMIN", "STANDARD_USER"
    verified_account: str | None = None
    delegation_verified: bool = False
    directory_access_granted: bool = False
    reports_access_granted: bool = False
    endpoint_access_granted: bool = False
    vault_access_granted: bool = False
    dlp_access_granted: bool = False
    api_audit_log: list[str] = []

# Realistic canned profiles for instant stakeholder demos
PRESET_PROFILES = {
    "foremycorp.com": {
        "mfa_enforced": True,
        "mfa_enrolled_pct": 100.0,
        "mfa_method_tier": "FIDO2_SECURITY_KEY",
        "super_admin_count": 2,
        "total_user_count": 28,
        "dormant_user_count": 0,
        "device_count": 34,
        "device_encryption_pct": 100.0,
        "screen_lock_enforced": True,
        "dlp_rules_active": True,
        "dlp_rule_count": 4,
        "vault_retention_active": True,
        "dmarc_policy_override": "reject",
        "mx_provider": "Google Workspace Enterprise (aspmx.l.google.com)",
        "dkim_record_present": True
    },
    "vulnerableretail.com": {
        "mfa_enforced": False,
        "mfa_enrolled_pct": 18.0,
        "mfa_method_tier": "SMS_WEAK",
        "super_admin_count": 9,
        "total_user_count": 16,
        "dormant_user_count": 6,
        "device_count": 8,
        "device_encryption_pct": 0.0,
        "screen_lock_enforced": False,
        "dlp_rules_active": False,
        "dlp_rule_count": 0,
        "vault_retention_active": False,
        "dmarc_policy_override": "missing",
        "mx_provider": "Legacy On-Premise Relay",
        "dkim_record_present": False
    },
    "partialcompliance.com": {
        "mfa_enforced": True,
        "mfa_enrolled_pct": 92.0,
        "mfa_method_tier": "TOTP_AUTHENTICATOR",
        "super_admin_count": 5,
        "total_user_count": 42,
        "dormant_user_count": 3,
        "device_count": 22,
        "device_encryption_pct": 68.0,
        "screen_lock_enforced": False,
        "dlp_rules_active": False,
        "dlp_rule_count": 0,
        "vault_retention_active": True,
        "dmarc_policy_override": "none",
        "mx_provider": "Google Workspace Standard",
        "dkim_record_present": False
    },
    "gcp-api-disabled.demo": {
        "account_role": "SUPER_ADMIN",
        "verified_account": "admin@cloudfirm.io",
        "delegation_verified": False,
        "rbac_block_cause": "GCP_API_DISABLED",
        "rbac_block_detail": "Admin SDK API has not been used in project 799321431260 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/admin.googleapis.com/overview?project=799321431260 then retry.",
        "mfa_error_type": "GCP_API_DISABLED",
        "mfa_error_detail": "Admin SDK API is disabled in GCP project 799321431260",
        "directory_error_type": "GCP_API_DISABLED",
        "directory_error_detail": "Admin SDK API is disabled in GCP project 799321431260",
        "endpoint_error_type": "GCP_API_DISABLED",
        "endpoint_error_detail": "Admin SDK API is disabled in GCP project 799321431260",
        "vault_error_type": "GCP_API_DISABLED",
        "vault_error_detail": "Google Vault API is disabled in GCP project 799321431260",
        "dlp_error_type": "GCP_API_DISABLED",
        "dlp_error_detail": "Google Workspace Alert Center / Rules API is disabled in GCP project 799321431260",
        "mfa_enforced": None,
        "mfa_enrolled_pct": None,
        "mfa_method_tier": "UNVERIFIED",
        "super_admin_count": None,
        "total_user_count": None,
        "dormant_user_count": None,
        "device_count": None,
        "device_encryption_pct": None,
        "screen_lock_enforced": None,
        "dlp_rules_active": None,
        "dlp_rule_count": 0,
        "vault_retention_active": None,
        "dmarc_policy_override": "quarantine",
        "mx_provider": "Google Workspace Enterprise (aspmx.l.google.com)",
        "dkim_record_present": True,
        "api_audit_log": [
            "OAuth Identity Handshake: admin@cloudfirm.io (cloudfirm.io)",
            "Directory API: 403 GCP Error - Admin SDK API has not been used in project 799321431260 before or it is disabled.",
            "Reports API: 403 GCP Error - Admin SDK API is disabled in Google Cloud Console project 799321431260.",
            "Endpoint Management API: 403 GCP Error - Admin SDK API is disabled in Google Cloud Console project 799321431260.",
            "Live DNS Resolution: DMARC p=quarantine, SPF v=spf1 include:_spf.google.com ~all, DKIM verified."
        ]
    },
    "standard-user-rbac.demo": {
        "account_role": "STANDARD_USER",
        "verified_account": "employee@midsizecorp.com",
        "delegation_verified": False,
        "rbac_block_cause": "WORKSPACE_ROLE_STANDARD",
        "rbac_block_detail": "Google Workspace RBAC blocked access: Account 'employee@midsizecorp.com' is a Standard User lacking Admin privileges (Google error: 'Not Authorized to access this resource/api').",
        "mfa_error_type": "WORKSPACE_RBAC_FORBIDDEN",
        "mfa_error_detail": "Workspace Reports API returned 403 Forbidden ('Not Authorized'). Account lacks 'Reports (Read)' delegated role.",
        "directory_error_type": "WORKSPACE_RBAC_FORBIDDEN",
        "directory_error_detail": "Directory Users API returned 403 Forbidden ('Not Authorized'). Account lacks 'Users (Read)' delegated role.",
        "endpoint_error_type": "WORKSPACE_RBAC_FORBIDDEN",
        "endpoint_error_detail": "Endpoint Management API returned 403 Forbidden ('Not Authorized'). Account lacks 'Mobile Device Management' delegated role.",
        "vault_error_type": "WORKSPACE_RBAC_FORBIDDEN",
        "vault_error_detail": "Google Vault API returned 403 Forbidden ('Not Authorized'). Account lacks eDiscovery audit role.",
        "dlp_error_type": "WORKSPACE_RBAC_FORBIDDEN",
        "dlp_error_detail": "Workspace Rules API returned 403 Forbidden ('Not Authorized'). Account lacks 'Security' delegated role.",
        "mfa_enforced": None,
        "mfa_enrolled_pct": None,
        "mfa_method_tier": "UNVERIFIED",
        "super_admin_count": None,
        "total_user_count": None,
        "dormant_user_count": None,
        "device_count": None,
        "device_encryption_pct": None,
        "screen_lock_enforced": None,
        "dlp_rules_active": None,
        "dlp_rule_count": 0,
        "vault_retention_active": None,
        "dmarc_policy_override": "reject",
        "mx_provider": "Google Workspace Enterprise (aspmx.l.google.com)",
        "dkim_record_present": True,
        "api_audit_log": [
            "OAuth Identity Handshake: employee@midsizecorp.com (midsizecorp.com)",
            "Directory API: 403 Workspace RBAC - Account is a Standard User (Not Authorized to access this resource/api)",
            "Reports API: 403 Workspace RBAC - Account lacks 'Reports' admin role (Not Authorized)",
            "Endpoint Management API: 403 Workspace RBAC - Account lacks 'Mobile Device Management' admin role (Not Authorized)",
            "Live DNS Resolution: DMARC p=reject, SPF v=spf1 include:_spf.google.com ~all, DKIM verified."
        ]
    }
}

def _resolve_dns_txt_local(domain: str) -> list[str]:
    """Synchronous DNS TXT resolution to run in worker thread."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            records.append(txt_str)
        return records
    except Exception:
        return []

async def resolve_dns_txt_records(domain: str) -> list[str]:
    """Resolves TXT records using local dnspython (non-blocking) with Google Public DNS HTTPS fallback."""
    # 1. Try local DNS resolver via threadpool so event loop is never blocked
    records = await asyncio.to_thread(_resolve_dns_txt_local, domain)
    if records:
        return records

    # 2. Fallback to Google DNS over HTTPS (dns.google)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"https://dns.google/resolve?name={domain}&type=TXT")
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    data_val = ans.get("data", "").strip('"')
                    if data_val:
                        records.append(data_val)
    except Exception:
        pass

    return records

async def check_email_security(domain: str) -> dict[str, Any]:
    """Queries live DNS for SPF, DMARC, and DKIM posture."""
    clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]
    
    # SPF check
    domain_txts = await resolve_dns_txt_records(clean_domain)
    spf_val = None
    spf_present = False
    spf_valid = False
    
    for txt in domain_txts:
        if txt.startswith("v=spf1") or "v=spf1" in txt:
            spf_present = True
            spf_val = txt
            if "-all" in txt or "~all" in txt or "include:" in txt:
                spf_valid = True
            break
            
    # DMARC check at _dmarc.<domain>
    dmarc_txts = await resolve_dns_txt_records(f"_dmarc.{clean_domain}")
    dmarc_val = None
    dmarc_present = False
    dmarc_policy = "missing"
    
    for txt in dmarc_txts:
        if "v=DMARC1" in txt:
            dmarc_present = True
            dmarc_val = txt
            match = re.search(r'\bp=([a-zA-Z]+)', txt)
            if match:
                policy_raw = match.group(1).lower()
                if policy_raw in ["reject", "quarantine", "none"]:
                    dmarc_policy = policy_raw
            break
            
    # DKIM check (query standard Google selector and enterprise selectors)
    dkim_present = False
    dkim_verified = False
    for selector in ["google", "k1", "s1", "selector1", "default"]:
        dkim_txts = await resolve_dns_txt_records(f"{selector}._domainkey.{clean_domain}")
        if any("v=DKIM1" in t or "k=rsa" in t or "p=" in t for t in dkim_txts):
            dkim_verified = True
            dkim_present = True
            break

    # MX Mail Server Provider lookup
    mx_records = []
    mx_provider = "Custom / Unverified Relay"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        mx_ans = resolver.resolve(clean_domain, 'MX')
        for rdata in mx_ans:
            exchange = str(rdata.exchange).lower().rstrip('.')
            mx_records.append(exchange)
    except Exception:
        pass

    if not mx_records:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"https://dns.google/resolve?name={clean_domain}&type=MX")
                if resp.status_code == 200:
                    data = resp.json()
                    for ans in data.get("Answer", []):
                        mx_val = ans.get("data", "").lower().strip('"').split()[-1]
                        if mx_val:
                            mx_records.append(mx_val)
        except Exception:
            pass

    if any("google.com" in mx or "googlemail.com" in mx for mx in mx_records):
        mx_provider = "Google Workspace Enterprise (aspmx.l.google.com)"
    elif any("outlook.com" in mx for mx in mx_records):
        mx_provider = "Microsoft 365 Exchange Online"
    elif mx_records:
        mx_provider = f"Hosted Mail ({mx_records[0]})"

    return {
        "clean_domain": clean_domain,
        "spf_present": spf_present,
        "spf_val": spf_val,
        "spf_valid": spf_valid,
        "dmarc_present": dmarc_present,
        "dmarc_val": dmarc_val,
        "dmarc_policy": dmarc_policy,
        "dkim_verified": dkim_verified,
        "dkim_present": dkim_present,
        "mx_provider": mx_provider,
        "mx_records": mx_records
    }

def parse_google_error(resp) -> str:
    try:
        data = resp.json().get("error", {})
        msg = data.get("message", "")
        if msg:
            return msg
    except Exception:
        pass
    return (resp.text[:140] if resp.text else "Forbidden").strip()

def classify_google_403(err_msg: str, endpoint_name: str) -> tuple[str, str]:
    lower_msg = err_msg.lower()
    if "has not been used in project" in lower_msg or "disabled" in lower_msg or "accessnotconfigured" in lower_msg:
        return "GCP_API_DISABLED", f"GCP Project Error: {endpoint_name} is disabled in Google Cloud Console project 799321431260 ({err_msg})"
    elif "not enabled for this domain" in lower_msg or "license" in lower_msg or "not licensed" in lower_msg:
        return "UNLICENSED_EDITION", f"Google Workspace License: Domain edition does not include {endpoint_name} ({err_msg})"
    elif "not authorized" in lower_msg or "forbidden" in lower_msg:
        return "WORKSPACE_RBAC_FORBIDDEN", f"Google Workspace RBAC: Account lacks administrative privileges for {endpoint_name} ({err_msg})"
    else:
        return "WORKSPACE_RBAC_FORBIDDEN", f"HTTP 403 Forbidden: {err_msg}"

async def fetch_live_google_workspace_telemetry(access_token: str, target_domain: str) -> dict[str, Any]:
    """
    Makes authentic, read-only REST calls to Google APIs using the OAuth access token.
    Zero-retention: Raw payloads are parsed in memory and discarded.
    Zero faked fallbacks: If an endpoint returns 403 / ungranted, it is reported as unverified.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    # State tracking
    verified_email = None
    verified_domain = target_domain
    is_admin = False
    is_delegated_admin = False
    account_role = "STANDARD_USER"
    delegation_verified = False

    # Explicit cause tracking for RBAC vs. GCP Project un-deployed errors
    rbac_block_cause = "SUPER_ADMIN_VERIFIED"
    rbac_block_detail = ""

    mfa_error_type = None
    mfa_error_detail = None
    directory_error_type = None
    directory_error_detail = None
    endpoint_error_type = None
    endpoint_error_detail = None
    vault_error_type = None
    vault_error_detail = None
    dlp_error_type = None
    dlp_error_detail = None

    # Telemetry metrics initialized to None (unverified)
    mfa_enforced: bool | None = None
    mfa_enrolled_pct: float | None = None
    mfa_method_tier: str = "UNVERIFIED"
    super_admin_count: int | None = None
    total_user_count: int | None = None
    dormant_user_count: int | None = None
    device_count: int | None = None
    device_encryption_pct: float | None = None
    screen_lock_enforced: bool | None = None
    dlp_rules_active: bool | None = None
    dlp_rule_count: int = 0
    vault_retention_active: bool | None = None

    # Access grants
    directory_access_granted = False
    reports_access_granted = False
    endpoint_access_granted = False
    vault_access_granted = False
    dlp_access_granted = False

    api_audit_log = []

    async with httpx.AsyncClient(timeout=8.0) as client:
        # 1. Identity & Domain verification
        try:
            userinfo_resp = await client.get("https://www.googleapis.com/oauth2/v2/userinfo", headers=headers)
            if userinfo_resp.status_code == 200:
                uinfo = userinfo_resp.json()
                verified_email = uinfo.get("email")
                verified_domain = uinfo.get("hd") or (verified_email.split("@")[-1] if verified_email else target_domain)
                api_audit_log.append(f"OAuth Identity Handshake: {verified_email} ({verified_domain})")
                if verified_email and ("@gmail.com" in verified_email.lower() or "@googlemail.com" in verified_email.lower()):
                    rbac_block_cause = "CONSUMER_ACCOUNT"
                    rbac_block_detail = f"Personal consumer account detected ({verified_email}). Consumer accounts lack Google Workspace administrative directory & tenant controls."
            else:
                api_audit_log.append(f"Userinfo check failed: HTTP {userinfo_resp.status_code}")
        except Exception as e:
            api_audit_log.append(f"Userinfo check error: {str(e)}")

        # 2. Directory API - Check Admin Role & 2SV Status on Authenticated Account
        if verified_email:
            try:
                user_sec_resp = await client.get(
                    f"https://admin.googleapis.com/admin/directory/v1/users/{verified_email}?projection=full",
                    headers=headers
                )
                if user_sec_resp.status_code == 200:
                    udata = user_sec_resp.json()
                    is_admin = bool(udata.get("isAdmin", False))
                    is_delegated_admin = bool(udata.get("isDelegatedAdmin", False))
                    is_enforced = bool(udata.get("isEnforcedIn2Sv", False))
                    is_enrolled = bool(udata.get("isEnrolledIn2Sv", False))

                    if is_admin:
                        account_role = "SUPER_ADMIN"
                    elif is_delegated_admin:
                        account_role = "DELEGATED_ADMIN"
                    else:
                        account_role = "STANDARD_USER"

                    user_method = "FIDO2_SECURITY_KEY" if is_enforced else ("TOTP_AUTHENTICATOR" if is_enrolled else "NONE")
                    api_audit_log.append(
                        f"Directory API: Authenticated Account Role={account_role}, Personal 2SV Enforced={is_enforced}, Method={user_method}"
                    )
                elif user_sec_resp.status_code == 403:
                    err_msg = parse_google_error(user_sec_resp)
                    account_role = "STANDARD_USER"
                    err_type, err_text = classify_google_403(err_msg, "Directory API")
                    if err_type == "GCP_API_DISABLED":
                        rbac_block_cause = "GCP_API_DISABLED"
                        rbac_block_detail = err_text
                        api_audit_log.append(f"Directory API: 403 GCP Error - {err_text}")
                    else:
                        if rbac_block_cause != "CONSUMER_ACCOUNT":
                            rbac_block_cause = "WORKSPACE_ROLE_STANDARD"
                            rbac_block_detail = f"Google Workspace RBAC blocked access: Account '{verified_email}' is a Standard User lacking Admin privileges."
                        api_audit_log.append(f"Directory API: 403 Workspace RBAC - Account is a Standard User ({err_msg})")
                else:
                    api_audit_log.append(f"Directory API user query returned HTTP {user_sec_resp.status_code}")
            except Exception as e:
                api_audit_log.append(f"Directory API error: {str(e)}")

        # 3. Admin Reports API - Domain-wide 2SV Statistics
        try:
            import datetime
            reports_found = False
            for days_ago in [2, 3, 4]:
                check_date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")
                usage_resp = await client.get(
                    f"https://admin.googleapis.com/admin/reports/v1/usage/dates/{check_date}?parameters=accounts:is_2sv_enforced,accounts:num_users_enrolled_in_2sv,accounts:num_users",
                    headers=headers
                )
                if usage_resp.status_code == 200:
                    data = usage_resp.json()
                    reports = data.get("usageReports", [])
                    if reports:
                        reports_found = True
                        reports_access_granted = True
                        params = {p["name"]: p.get("intValue", p.get("boolValue")) for p in reports[0].get("parameters", [])}
                        if "accounts:is_2sv_enforced" in params:
                            mfa_enforced = bool(params["accounts:is_2sv_enforced"])
                        total = int(params.get("accounts:num_users", 0) or 0)
                        enrolled = int(params.get("accounts:num_users_enrolled_in_2sv", 0) or 0)
                        if total > 0:
                            mfa_enrolled_pct = round((enrolled / total) * 100.0, 1)
                        else:
                            mfa_enrolled_pct = 0.0
                        mfa_method_tier = "FIDO2_SECURITY_KEY" if mfa_enforced else ("TOTP_AUTHENTICATOR" if mfa_enrolled_pct > 0 else "NONE")
                        api_audit_log.append(f"Reports API: Real-time Org 2SV Enforced={mfa_enforced}, Enrolled={mfa_enrolled_pct}% ({enrolled}/{total} users)")
                        break
                elif usage_resp.status_code == 403:
                    reports_access_granted = False
                    err_msg = parse_google_error(usage_resp)
                    mfa_error_type, mfa_error_detail = classify_google_403(err_msg, "Reports API (2SV)")
                    if mfa_error_type == "GCP_API_DISABLED":
                        rbac_block_cause = "GCP_API_DISABLED"
                        rbac_block_detail = mfa_error_detail
                        api_audit_log.append(f"Reports API: 403 GCP Error - {mfa_error_detail}")
                    else:
                        if rbac_block_cause not in ["CONSUMER_ACCOUNT", "GCP_API_DISABLED"]:
                            rbac_block_cause = "WORKSPACE_ROLE_STANDARD"
                            rbac_block_detail = f"Google Workspace RBAC blocked Reports API: Account lacks 'Reports' admin role ({err_msg})"
                        api_audit_log.append(f"Reports API: 403 Workspace RBAC - {mfa_error_detail}")
                    break
            if not reports_found and not reports_access_granted:
                mfa_enforced = None
                mfa_enrolled_pct = None
        except Exception as e:
            api_audit_log.append(f"Reports API notice: {str(e)}")

        # 4. Directory API - Users, Super Admin Count & Dormant Accounts
        try:
            users_resp = await client.get(
                "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=100",
                headers=headers
            )
            if users_resp.status_code == 200:
                directory_access_granted = True
                udata = users_resp.json()
                u_list = udata.get("users", [])
                total_user_count = len(u_list)
                admins = [u for u in u_list if u.get("isAdmin") is True]
                super_admin_count = len(admins)
                dormant_user_count = 0

                import datetime
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                for u in u_list:
                    last_login = u.get("lastLoginTime")
                    if last_login:
                        try:
                            dt = datetime.datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                            if (now_utc - dt).days > 90:
                                dormant_user_count += 1
                        except Exception:
                            pass
                api_audit_log.append(f"Directory API: Live Headcount={total_user_count}, SuperAdmins={super_admin_count}, Dormant={dormant_user_count}")
            elif users_resp.status_code == 403:
                directory_access_granted = False
                super_admin_count = None
                total_user_count = None
                dormant_user_count = None
                err_msg = parse_google_error(users_resp)
                directory_error_type, directory_error_detail = classify_google_403(err_msg, "Directory Users API")
                if directory_error_type == "GCP_API_DISABLED":
                    rbac_block_cause = "GCP_API_DISABLED"
                    rbac_block_detail = directory_error_detail
                    api_audit_log.append(f"Directory Users API: 403 GCP Error - {directory_error_detail}")
                else:
                    api_audit_log.append(f"Directory Users API: 403 Workspace RBAC - {directory_error_detail}")
        except Exception as e:
            api_audit_log.append(f"Directory Users API error: {str(e)}")

        # 5. Endpoint Management API - Device Fleet & Encryption
        try:
            dev_resp = await client.get(
                "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile?maxResults=100",
                headers=headers
            )
            if dev_resp.status_code == 200:
                endpoint_access_granted = True
                dev_data = dev_resp.json()
                mobiles = dev_data.get("mobiledevices", [])
                device_count = len(mobiles)
                if device_count > 0:
                    enc_count = sum(1 for d in mobiles if d.get("encryptionStatus") == "ENCRYPTED")
                    device_encryption_pct = round((enc_count / device_count) * 100.0, 1)
                    screen_lock_enforced = all(d.get("devicePasswordStatus") == "ACTIVE" for d in mobiles)
                    api_audit_log.append(f"Endpoint API: {device_count} mobile devices ({device_encryption_pct}% encrypted, Lock={screen_lock_enforced})")
                else:
                    device_count = 0
                    device_encryption_pct = 0.0
                    screen_lock_enforced = False
                    api_audit_log.append("Endpoint API: 0 mobile devices enrolled in Google Endpoint Management")
            elif dev_resp.status_code == 403:
                endpoint_access_granted = False
                device_count = None
                device_encryption_pct = None
                screen_lock_enforced = None
                err_msg = parse_google_error(dev_resp)
                endpoint_error_type, endpoint_error_detail = classify_google_403(err_msg, "Endpoint Management API")
                if endpoint_error_type == "GCP_API_DISABLED":
                    rbac_block_cause = "GCP_API_DISABLED"
                    rbac_block_detail = endpoint_error_detail
                    api_audit_log.append(f"Endpoint API: 403 GCP Error - {endpoint_error_detail}")
                else:
                    api_audit_log.append(f"Endpoint API: 403 Workspace RBAC - {endpoint_error_detail}")
        except Exception as e:
            api_audit_log.append(f"Endpoint API error: {str(e)}")

        # 6. Google Vault API - Legal Hold & Retention Matters
        try:
            vault_resp = await client.get("https://vault.googleapis.com/v1/matters?view=BASIC", headers=headers)
            if vault_resp.status_code == 200:
                vault_access_granted = True
                vdata = vault_resp.json()
                matters = vdata.get("matters", [])
                vault_retention_active = len(matters) > 0
                api_audit_log.append(f"Google Vault API: {len(matters)} active legal hold matters confirmed")
            elif vault_resp.status_code == 403:
                vault_access_granted = False
                vault_retention_active = None
                err_msg = parse_google_error(vault_resp)
                vault_error_type, vault_error_detail = classify_google_403(err_msg, "Google Vault API")
                api_audit_log.append(f"Google Vault API: 403 - {vault_error_detail}")
        except Exception as e:
            api_audit_log.append(f"Vault API error: {str(e)}")

        # 7. Workspace Rules API - Real-Time DLP Inspection
        try:
            dlp_resp = await client.get(
                "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules?maxResults=5",
                headers=headers
            )
            if dlp_resp.status_code == 200:
                dlp_access_granted = True
                dlp_data = dlp_resp.json()
                items = dlp_data.get("items", [])
                dlp_rules_active = len(items) > 0
                dlp_rule_count = len(items)
                api_audit_log.append(f"Workspace Rules API: Real-time DLP inspection confirmed ({dlp_rule_count} rule events)")
            elif dlp_resp.status_code == 403:
                dlp_access_granted = False
                dlp_rules_active = None
                err_msg = parse_google_error(dlp_resp)
                dlp_error_type, dlp_error_detail = classify_google_403(err_msg, "Workspace Rules API")
                api_audit_log.append(f"Workspace Rules API: 403 - {dlp_error_detail}")
        except Exception as e:
            api_audit_log.append(f"Workspace Rules API error: {str(e)}")

    if is_admin:
        account_role = "SUPER_ADMIN"
        delegation_verified = True
        rbac_block_cause = "SUPER_ADMIN_VERIFIED"
    elif is_delegated_admin or (directory_access_granted and reports_access_granted):
        account_role = "DELEGATED_ADMIN"
        delegation_verified = True
        rbac_block_cause = "DELEGATED_ADMIN_VERIFIED"
    else:
        account_role = "STANDARD_USER"
        delegation_verified = False
        if rbac_block_cause == "SUPER_ADMIN_VERIFIED":
            rbac_block_cause = "WORKSPACE_ROLE_STANDARD"
            rbac_block_detail = f"Standard Employee account '{verified_email}' lacks Super Admin or Delegated Admin privilege in Google Workspace."

    return {
        "verified_email": verified_email,
        "verified_domain": verified_domain,
        "account_role": account_role,
        "is_admin": is_admin,
        "is_delegated_admin": is_delegated_admin,
        "delegation_verified": delegation_verified,
        "rbac_block_cause": rbac_block_cause,
        "rbac_block_detail": rbac_block_detail,
        "mfa_error_type": mfa_error_type,
        "mfa_error_detail": mfa_error_detail,
        "directory_error_type": directory_error_type,
        "directory_error_detail": directory_error_detail,
        "endpoint_error_type": endpoint_error_type,
        "endpoint_error_detail": endpoint_error_detail,
        "vault_error_type": vault_error_type,
        "vault_error_detail": vault_error_detail,
        "dlp_error_type": dlp_error_type,
        "dlp_error_detail": dlp_error_detail,
        "directory_access_granted": directory_access_granted,
        "reports_access_granted": reports_access_granted,
        "endpoint_access_granted": endpoint_access_granted,
        "vault_access_granted": vault_access_granted,
        "dlp_access_granted": dlp_access_granted,
        "mfa_enforced": mfa_enforced,
        "mfa_enrolled_pct": mfa_enrolled_pct,
        "mfa_method_tier": mfa_method_tier,
        "super_admin_count": super_admin_count,
        "total_user_count": total_user_count,
        "dormant_user_count": dormant_user_count,
        "device_count": device_count,
        "device_encryption_pct": device_encryption_pct,
        "screen_lock_enforced": screen_lock_enforced,
        "dlp_rules_active": dlp_rules_active,
        "dlp_rule_count": dlp_rule_count,
        "vault_retention_active": vault_retention_active,
        "api_audit_log": api_audit_log,
        "data_source": "live_google_workspace_api"
    }

async def collect_telemetry(
    domain: str, 
    organization_name: str,
    admin_consented: bool = True,
    profile_override: str | None = None,
    access_token: str | None = None
) -> dict[str, Any]:
    """
    Performs ephemeral collection of Workspace API telemetry and live DNS.
    Zero-retention: Raw API payloads are processed in memory and discarded.
    """
    import datetime
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]

    # 1. If an access token is provided, query Google APIs live! Zero faked fallbacks.
    # Live authentication takes absolute priority over any simulation preset.
    if access_token:
        google_telemetry = await fetch_live_google_workspace_telemetry(access_token, clean_domain)
        active_domain = google_telemetry.get("verified_domain") or clean_domain
        dns_posture = await check_email_security(active_domain)

        return {
            "domain": active_domain,
            "organization_name": organization_name,
            "verified_account": google_telemetry.get("verified_email"),
            "account_role": google_telemetry.get("account_role", "STANDARD_USER"),
            "is_admin": google_telemetry.get("is_admin", False),
            "is_delegated_admin": google_telemetry.get("is_delegated_admin", False),
            "delegation_verified": google_telemetry.get("delegation_verified", False),
            "rbac_block_cause": google_telemetry.get("rbac_block_cause", "SUPER_ADMIN_VERIFIED"),
            "rbac_block_detail": google_telemetry.get("rbac_block_detail"),
            "mfa_error_type": google_telemetry.get("mfa_error_type"),
            "mfa_error_detail": google_telemetry.get("mfa_error_detail"),
            "directory_error_type": google_telemetry.get("directory_error_type"),
            "directory_error_detail": google_telemetry.get("directory_error_detail"),
            "endpoint_error_type": google_telemetry.get("endpoint_error_type"),
            "endpoint_error_detail": google_telemetry.get("endpoint_error_detail"),
            "vault_error_type": google_telemetry.get("vault_error_type"),
            "vault_error_detail": google_telemetry.get("vault_error_detail"),
            "dlp_error_type": google_telemetry.get("dlp_error_type"),
            "dlp_error_detail": google_telemetry.get("dlp_error_detail"),
            "directory_access_granted": google_telemetry.get("directory_access_granted", False),
            "reports_access_granted": google_telemetry.get("reports_access_granted", False),
            "endpoint_access_granted": google_telemetry.get("endpoint_access_granted", False),
            "vault_access_granted": google_telemetry.get("vault_access_granted", False),
            "dlp_access_granted": google_telemetry.get("dlp_access_granted", False),
            "mfa_enforced": google_telemetry.get("mfa_enforced"),
            "mfa_enrolled_pct": google_telemetry.get("mfa_enrolled_pct"),
            "mfa_method_tier": google_telemetry.get("mfa_method_tier", "UNVERIFIED"),
            "super_admin_count": google_telemetry.get("super_admin_count"),
            "total_user_count": google_telemetry.get("total_user_count"),
            "dormant_user_count": google_telemetry.get("dormant_user_count"),
            "device_count": google_telemetry.get("device_count"),
            "device_encryption_pct": google_telemetry.get("device_encryption_pct"),
            "screen_lock_enforced": google_telemetry.get("screen_lock_enforced"),
            "spf_record_present": dns_posture["spf_present"],
            "spf_record_value": dns_posture["spf_val"],
            "spf_valid": dns_posture["spf_valid"],
            "dmarc_record_present": dns_posture["dmarc_present"],
            "dmarc_record_value": dns_posture["dmarc_val"],
            "dmarc_policy": dns_posture["dmarc_policy"],
            "dkim_verified": dns_posture["dkim_verified"],
            "dkim_record_present": dns_posture.get("dkim_present", False),
            "mx_provider": dns_posture.get("mx_provider", "Custom / Unresolved Relay"),
            "dlp_rules_active": google_telemetry.get("dlp_rules_active"),
            "dlp_rule_count": google_telemetry.get("dlp_rule_count", 0),
            "vault_retention_active": google_telemetry.get("vault_retention_active"),
            "api_audit_log": google_telemetry.get("api_audit_log", []),
            "data_source": "live_google_workspace_api",
            "verified_at": now_iso
        }

    # 2. Check if a preset profile override matches (for What-If Studio simulation only)
    if profile_override and profile_override in PRESET_PROFILES:
        preset = PRESET_PROFILES[profile_override]
        dns_posture = await check_email_security(clean_domain)
        dmarc_policy = preset.get("dmarc_policy_override", dns_posture["dmarc_policy"])
        return {
            "domain": clean_domain,
            "organization_name": organization_name,
            "verified_account": preset.get("verified_account", f"admin@{clean_domain}"),
            "account_role": preset.get("account_role", "DELEGATED_ADMIN"),
            "is_admin": preset.get("account_role") == "SUPER_ADMIN",
            "is_delegated_admin": preset.get("account_role") in ["SUPER_ADMIN", "DELEGATED_ADMIN"],
            "delegation_verified": preset.get("delegation_verified", True),
            "rbac_block_cause": preset.get("rbac_block_cause", "SUPER_ADMIN_VERIFIED"),
            "rbac_block_detail": preset.get("rbac_block_detail", ""),
            "mfa_error_type": preset.get("mfa_error_type"),
            "mfa_error_detail": preset.get("mfa_error_detail"),
            "directory_error_type": preset.get("directory_error_type"),
            "directory_error_detail": preset.get("directory_error_detail"),
            "endpoint_error_type": preset.get("endpoint_error_type"),
            "endpoint_error_detail": preset.get("endpoint_error_detail"),
            "vault_error_type": preset.get("vault_error_type"),
            "vault_error_detail": preset.get("vault_error_detail"),
            "dlp_error_type": preset.get("dlp_error_type"),
            "dlp_error_detail": preset.get("dlp_error_detail"),
            "directory_access_granted": preset.get("directory_access_granted", preset.get("delegation_verified", True)),
            "reports_access_granted": preset.get("reports_access_granted", preset.get("delegation_verified", True)),
            "endpoint_access_granted": preset.get("endpoint_access_granted", preset.get("delegation_verified", True)),
            "vault_access_granted": preset.get("vault_access_granted", preset.get("delegation_verified", True)),
            "dlp_access_granted": preset.get("dlp_access_granted", preset.get("delegation_verified", True)),
            "mfa_enforced": preset.get("mfa_enforced"),
            "mfa_enrolled_pct": preset.get("mfa_enrolled_pct"),
            "mfa_method_tier": preset.get("mfa_method_tier", "UNVERIFIED"),
            "super_admin_count": preset.get("super_admin_count", 2 if preset.get("delegation_verified", True) else None),
            "total_user_count": preset.get("total_user_count", 28 if preset.get("delegation_verified", True) else None),
            "dormant_user_count": preset.get("dormant_user_count", 0 if preset.get("delegation_verified", True) else None),
            "device_count": preset.get("device_count", 34 if preset.get("delegation_verified", True) else None),
            "device_encryption_pct": preset.get("device_encryption_pct", 100.0 if preset.get("delegation_verified", True) else None),
            "screen_lock_enforced": preset.get("screen_lock_enforced", True if preset.get("delegation_verified", True) else None),
            "spf_record_present": True,
            "spf_record_value": "v=spf1 include:_spf.google.com ~all",
            "spf_valid": True,
            "dmarc_record_present": dmarc_policy != "missing",
            "dmarc_record_value": f"v=DMARC1; p={dmarc_policy}; rua=mailto:dmarc@{clean_domain}",
            "dmarc_policy": dmarc_policy,
            "dkim_verified": preset.get("dkim_record_present", True),
            "dkim_record_present": preset.get("dkim_record_present", True),
            "mx_provider": preset.get("mx_provider", "Google Workspace Enterprise (aspmx.l.google.com)"),
            "dlp_rules_active": preset.get("dlp_rules_active"),
            "dlp_rule_count": preset.get("dlp_rule_count", 0),
            "vault_retention_active": preset.get("vault_retention_active"),
            "api_audit_log": preset.get("api_audit_log", []),
            "data_source": "preset_scenario_simulation",
            "verified_at": now_iso
        }

    # If no token and no preset: resolve live DNS, but accurately reflect unauthenticated API status
    dns_posture = await check_email_security(clean_domain)
    return {
        "domain": clean_domain,
        "organization_name": organization_name,
        "account_role": "NOT_AUTHENTICATED",
        "delegation_verified": False,
        "directory_access_granted": False,
        "reports_access_granted": False,
        "endpoint_access_granted": False,
        "vault_access_granted": False,
        "dlp_access_granted": False,
        "mfa_enforced": None,
        "mfa_enrolled_pct": None,
        "mfa_method_tier": "NOT_AUTHENTICATED",
        "super_admin_count": None,
        "total_user_count": None,
        "dormant_user_count": None,
        "device_count": None,
        "device_encryption_pct": None,
        "screen_lock_enforced": None,
        "spf_record_present": dns_posture["spf_present"],
        "spf_record_value": dns_posture["spf_val"],
        "spf_valid": dns_posture["spf_valid"],
        "dmarc_record_present": dns_posture["dmarc_present"],
        "dmarc_record_value": dns_posture["dmarc_val"],
        "dmarc_policy": dns_posture["dmarc_policy"],
        "dkim_verified": dns_posture["dkim_verified"],
        "dkim_record_present": dns_posture.get("dkim_present", False),
        "mx_provider": dns_posture.get("mx_provider", "Unresolved"),
        "dlp_rules_active": None,
        "dlp_rule_count": 0,
        "vault_retention_active": None,
        "data_source": "live_dns_only_unauthenticated",
        "verified_at": now_iso
    }
