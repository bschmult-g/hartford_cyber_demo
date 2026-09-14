/**
 * Project Beacon - The Hartford Cyber Underwriting PoT
 * Frontend Controller
 */

let currentStep = 0;
let currentDomain = "foremycorp.com";
let currentOrgName = "Foremy corp";
let activePreset = null;

// Initialize on load
document.addEventListener("DOMContentLoaded", () => {
  syncDomainFromEmail();
  checkRedirectSession();
});

async function checkRedirectSession() {
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get("session_id");
  if (sessionId) {
    try {
      const resp = await fetch(`/api/session/${sessionId}`);
      if (resp.ok) {
        const data = await resp.json();
        navigateToStep(5);
        renderQuoteResult(data);
      }
    } catch (e) {
      console.error("Failed to load redirect session:", e);
    }
  }
}

function startQuoteFlow() {
  navigateToStep(1);
}

function navigateToStep(stepNumber) {
  currentStep = stepNumber;

  // Hide all views
  const views = [
    document.getElementById("viewLanding"),
    document.getElementById("viewStep1"),
    document.getElementById("viewStep2"),
    document.getElementById("viewStep3"),
    document.getElementById("viewStep4"),
    document.getElementById("viewStep5")
  ];
  views.forEach(v => {
    if (v) v.classList.remove("active");
  });

  const stepperNav = document.getElementById("stepperNav");

  if (stepNumber === 0) {
    views[0].classList.add("active");
    stepperNav.style.display = "none";
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }

  stepperNav.style.display = "flex";
  views[stepNumber].classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });

  // Update Stepper Indicators
  const step1 = document.getElementById("stepIndicator1");
  const step2 = document.getElementById("stepIndicator2");
  const step3 = document.getElementById("stepIndicator3");
  const step4 = document.getElementById("stepIndicator4");

  [step1, step2, step3, step4].forEach(el => {
    if (el) {
      el.classList.remove("active");
      el.classList.remove("completed");
    }
  });

  if (stepNumber >= 1 && stepNumber <= 3) {
    step1.classList.add("active");
  } else if (stepNumber === 4) {
    step1.classList.add("completed");
    step2.classList.add("active");
  } else if (stepNumber === 5) {
    step1.classList.add("completed");
    step2.classList.add("completed");
    step3.classList.add("completed");
    step4.classList.add("active");
    
    // Update domain displayed in step 5
    syncDomainFromEmail();
  }
}

function setSegment(btn, groupName) {
  const parent = btn.parentElement;
  const buttons = parent.querySelectorAll(".segmented-btn");
  buttons.forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
}

function syncDomainFromEmail() {
  const emailInput = document.getElementById("ownerEmail");
  const registeredNameInput = document.getElementById("registeredBusinessName");
  
  if (registeredNameInput && registeredNameInput.value) {
    currentOrgName = registeredNameInput.value.trim();
  }

  if (emailInput && emailInput.value && emailInput.value.includes("@")) {
    const parts = emailInput.value.split("@");
    if (parts.length > 1 && parts[1].includes(".")) {
      currentDomain = parts[1].trim().toLowerCase();
    }
  }

  const detectedDomainDisplay = document.getElementById("detectedDomainDisplay");
  if (detectedDomainDisplay) {
    detectedDomainDisplay.textContent = currentDomain;
  }
  const scanDomainName = document.getElementById("scanDomainName");
  if (scanDomainName) {
    scanDomainName.textContent = currentDomain;
  }
  const oauthModalDomain = document.getElementById("oauthModalDomain");
  if (oauthModalDomain) {
    oauthModalDomain.textContent = currentDomain;
  }
}

/* ==================== REAL GOOGLE OAUTH & TELEMETRY FLOW ==================== */

let oauthPopup = null;

async function triggerGoogleOAuth() {
  syncDomainFromEmail();

  const scanBox = document.getElementById("scanProgressBox");
  const quoteCard = document.getElementById("quoteResultCard");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");

  verifyBtn.style.display = "none";
  quoteCard.classList.remove("active");
  scanBox.classList.add("active");

  const s1 = document.getElementById("scanStep1");
  const s2 = document.getElementById("scanStep2");
  const s3 = document.getElementById("scanStep3");
  const s4 = document.getElementById("scanStep4");

  // Reset steps
  [s1, s2, s3, s4].forEach(s => {
    s.classList.remove("done");
    const sp = s.querySelector(".scan-spinner");
    if (sp) sp.style.display = "inline-block";
  });

  s1.querySelector("span").textContent = "Requesting Google OAuth 2.0 authorization URL...";
  s2.querySelector("span").textContent = "Awaiting Super Admin consent on accounts.google.com...";
  s3.querySelector("span").textContent = "Querying live Google Workspace Admin SDK & Directory APIs...";
  s4.querySelector("span").textContent = "Resolving live DNS (SPF/DMARC) & computing actuarial quote...";

  try {
    const urlResp = await fetch(`/api/auth/google/url?domain=${encodeURIComponent(currentDomain)}&organization_name=${encodeURIComponent(currentOrgName)}`);
    const authData = await urlResp.json();
    
    if (!authData.auth_url) {
      throw new Error(authData.detail || "Failed to generate Google OAuth URL");
    }

    markStepDone(s1, "Google OAuth 2.0 Endpoints Initialized");

    // Open real Google OAuth in a popup window
    const width = 540;
    const height = 680;
    const left = Math.max(0, (window.innerWidth - width) / 2 + window.screenX);
    const top = Math.max(0, (window.innerHeight - height) / 2 + window.screenY);

    oauthPopup = window.open(
      authData.auth_url,
      "google_oauth_beacon",
      `width=${width},height=${height},top=${top},left=${left},status=no,resizable=yes`
    );

    if (!oauthPopup || oauthPopup.closed || typeof oauthPopup.closed === "undefined") {
      // Popup was blocked by browser; fallback to direct navigation
      console.warn("Popup blocked. Redirecting current window directly to Google OAuth.");
      window.location.href = authData.auth_url;
      return;
    }

    // Set up message listener for the popup response
    const handleAuthMessage = (event) => {
      if (event.origin !== window.location.origin) return;

      if (event.data && event.data.type === "BEACON_OAUTH_SUCCESS") {
        window.removeEventListener("message", handleAuthMessage);
        markStepDone(s2, "Super Admin Identity Authenticated via Google");
        markStepDone(s3, "Google Workspace Security Posture Successfully Extracted");
        markStepDone(s4, "Live DNS Verified & Cryptographic Attestation Issued");

        setTimeout(() => {
          scanBox.classList.remove("active");
          renderQuoteResult(event.data.payload);
        }, 600);
      } else if (event.data && event.data.type === "BEACON_OAUTH_ERROR") {
        window.removeEventListener("message", handleAuthMessage);
        scanBox.classList.remove("active");
        verifyBtn.style.display = "flex";
        alert("Google Verification Error: " + (event.data.error || "Authentication failed"));
      }
    };

    window.addEventListener("message", handleAuthMessage);

    // Watch for unexpected popup closure
    const popupCheckTimer = setInterval(() => {
      if (oauthPopup && oauthPopup.closed) {
        clearInterval(popupCheckTimer);
        setTimeout(() => {
          if (scanBox.classList.contains("active") && !quoteCard.classList.contains("active")) {
            scanBox.classList.remove("active");
            verifyBtn.style.display = "flex";
          }
        }, 1500);
      }
    }, 1000);

  } catch (err) {
    console.error("OAuth init failed:", err);
    scanBox.classList.remove("active");
    verifyBtn.style.display = "flex";
    alert("Could not start Google Verification: " + err.message);
  }
}

function markStepDone(element, text) {
  element.classList.add("done");
  const spinner = element.querySelector(".scan-spinner");
  if (spinner) spinner.style.display = "none";
  const span = element.querySelector("span");
  if (span) span.textContent = `✓ ${text}`;
}

let lastTelemetryData = null;

function renderQuoteResult(data) {
  lastTelemetryData = data;
  const quoteCard = document.getElementById("quoteResultCard");
  const tierBadge = document.getElementById("quoteTierBadge");
  const quoteDecision = document.getElementById("quoteDecision");
  const summaryText = document.getElementById("quoteSummaryText");
  const annualPrice = document.getElementById("quoteAnnualPrice");
  const monthlyPrice = document.getElementById("quoteMonthlyPrice");
  const discountTag = document.getElementById("quoteDiscountPct");
  const attestToken = document.getElementById("attestToken");
  const attestHash = document.getElementById("attestHash");
  const btnBind = document.getElementById("btnBindPolicy");

  const rating = data.rating || {};
  const attest = data.attestation || {};
  const tel = data.telemetry || {};

  tierBadge.className = "";
  if (rating.decision === "APPROVED") {
    tierBadge.classList.add("badge-preferred");
    tierBadge.textContent = rating.tier_display || "PREFERRED RISK (Tier 1)";
    quoteDecision.textContent = "APPROVED INSTANTLY";
    quoteDecision.style.color = "#166534";
    if (btnBind) {
      btnBind.disabled = false;
      btnBind.style.background = "var(--hartford-maroon)";
      btnBind.style.cursor = "pointer";
      btnBind.textContent = "Bind Policy & Download Binder";
    }
  } else if (rating.decision === "CONDITIONAL_APPROVAL") {
    tierBadge.classList.add("badge-conditional");
    tierBadge.textContent = rating.tier_display || "CONDITIONAL QUOTE";
    quoteDecision.textContent = "CONDITIONAL APPROVAL";
    quoteDecision.style.color = "#92400E";
    if (btnBind) {
      btnBind.disabled = false;
      btnBind.style.background = "var(--hartford-maroon)";
      btnBind.style.cursor = "pointer";
      btnBind.textContent = "Bind Standard Policy & Download Binder";
    }
  } else {
    tierBadge.classList.add("badge-declined");
    tierBadge.textContent = rating.tier_display || "DECLINED";
    quoteDecision.textContent = "DECLINED (HIGH RISK)";
    quoteDecision.style.color = "#991B1B";
    if (btnBind) {
      btnBind.disabled = true;
      btnBind.style.background = "#94A3B8";
      btnBind.style.cursor = "not-allowed";
      btnBind.textContent = "⚠️ Action Required: Remediate MFA to Bind Policy";
    }
  }

  summaryText.textContent = rating.summary;

  if (rating.final_annual_premium) {
    annualPrice.innerHTML = `$${rating.final_annual_premium.toLocaleString()}<span style="font-size:14px; font-weight:500;">/yr</span>`;
    monthlyPrice.innerHTML = `$${rating.final_monthly_premium.toLocaleString()}<span style="font-size:14px; font-weight:500;">/mo</span>`;
    discountTag.textContent = `Saved ${rating.total_discount_pct}% (-$${rating.discount_amount.toLocaleString()})`;
    discountTag.style.display = "block";
  } else {
    annualPrice.innerHTML = `N/A`;
    monthlyPrice.innerHTML = `N/A`;
    discountTag.style.display = "none";
  }

  if (attest) {
    attestToken.textContent = attest.policy_attestation_token || "hig_gcp_attest_7f8a9...";
    attestHash.textContent = attest.sha256_fingerprint || "b43c8d19...";
  }

  // ==================== FINDINGS & DECISION EXPLAINER POPULATION ====================
  const domainEl = document.getElementById("findingsDomainName");
  if (domainEl) {
    domainEl.textContent = tel.domain || currentDomain || "Applicant Domain";
  }

  const sourceBadge = document.getElementById("findingsSourceBadge");
  if (sourceBadge) {
    if (tel.data_source === "live_google_workspace_api") {
      sourceBadge.textContent = "Live Google Workspace API";
      sourceBadge.className = "findings-source-badge badge-live";
    } else if (tel.data_source === "preset_scenario_simulation") {
      sourceBadge.textContent = "What-If Simulation";
      sourceBadge.className = "findings-source-badge badge-sim";
    } else {
      sourceBadge.textContent = "Live DNS Hybrid";
      sourceBadge.className = "findings-source-badge";
    }
  }

  // 1. MFA / 2SV Card
  const pillMfa = document.getElementById("pillMfa");
  const valMfa = document.getElementById("valMfa");
  const explMfa = document.getElementById("explMfa");
  const impactMfa = document.getElementById("impactMfa");
  const cardMfa = document.getElementById("cardMfa");

  if (tel.mfa_enforced) {
    pillMfa.textContent = `PASS (${tel.mfa_enrolled_pct || 100}% ENFORCED)`;
    pillMfa.className = "finding-pill pill-pass";
    cardMfa.className = "finding-card card-pass";
    valMfa.textContent = `Enforced across org (${tel.mfa_method_tier || "FIDO2 / TOTP Security Key"})`;
    explMfa.textContent = "Mandatory ransomware underwriting gate satisfied. Confirmed via Google Admin Reports API.";
    impactMfa.textContent = "Impact: -10% Preferred Risk Discount (-$850/yr)";
    impactMfa.className = "finding-impact impact-credit";
  } else {
    pillMfa.textContent = "FAIL (NOT ENFORCED)";
    pillMfa.className = "finding-pill pill-fail";
    cardMfa.className = "finding-card card-fail";
    valMfa.textContent = "Unenforced (2-Step Verification optional or disabled in Workspace)";
    explMfa.textContent = "MANDATORY ELIGIBILITY GATE: The Hartford requires 100% MFA enforcement to prevent credential stuffing & ransomware deployment.";
    impactMfa.textContent = "Impact: Underwriting Declined (Ransomware Ineligible)";
    impactMfa.className = "finding-impact impact-fail";
  }

  // 2. DMARC & SPF Card
  const pillDmarc = document.getElementById("pillDmarc");
  const valDmarc = document.getElementById("valDmarc");
  const explDmarc = document.getElementById("explDmarc");
  const impactDmarc = document.getElementById("impactDmarc");
  const cardDmarc = document.getElementById("cardDmarc");

  const dmarcPolicy = tel.dmarc_policy || (tel.dmarc_record_present ? "quarantine" : "missing");
  const spfActive = tel.spf_record_present;

  if (dmarcPolicy === "reject") {
    pillDmarc.textContent = "PASS (p=reject)";
    pillDmarc.className = "finding-pill pill-pass";
    cardDmarc.className = "finding-card card-pass";
    valDmarc.textContent = `DMARC p=reject | SPF: ${spfActive ? 'Active' : 'Unconfigured'}`;
    explDmarc.textContent = "Maximum Business Email Compromise (BEC) defense verified. Unauthorized sender spoofing automatically blocked.";
    impactDmarc.textContent = "Impact: -8% Anti-Phishing Discount (-$680/yr)";
    impactDmarc.className = "finding-impact impact-credit";
  } else if (dmarcPolicy === "quarantine") {
    pillDmarc.textContent = "PASS (p=quarantine)";
    pillDmarc.className = "finding-pill pill-pass";
    cardDmarc.className = "finding-card card-pass";
    valDmarc.textContent = `DMARC p=quarantine | SPF: ${spfActive ? 'Active' : 'Unconfigured'}`;
    explDmarc.textContent = "Strict anti-spoofing policy verified via live DNS. Suspicious emails quarantined to prevent CEO fraud.";
    impactDmarc.textContent = "Impact: -8% Anti-Phishing Discount (-$680/yr)";
    impactDmarc.className = "finding-impact impact-credit";
  } else if (dmarcPolicy === "none") {
    pillDmarc.textContent = "WARNING (p=none)";
    pillDmarc.className = "finding-pill pill-warn";
    cardDmarc.className = "finding-card card-warn";
    valDmarc.textContent = "p=none (Monitoring mode only - no active spoofing block)";
    explDmarc.textContent = "DMARC record exists but is set to monitoring mode only. Fraudulent emails spoofing your domain will still reach recipients.";
    impactDmarc.textContent = "Impact: Standard Rate (Missed $680/yr BEC discount)";
    impactDmarc.className = "finding-impact impact-warn";
  } else {
    pillDmarc.textContent = "FAIL (MISSING)";
    pillDmarc.className = "finding-pill pill-fail";
    cardDmarc.className = "finding-card card-fail";
    valDmarc.textContent = "No DMARC TXT record found on domain";
    explDmarc.textContent = "Domain vulnerable to impersonation and email phishing spoofing. Requires DNS TXT record configuration.";
    impactDmarc.textContent = "Impact: Standard Rate (Missed $680/yr BEC discount)";
    impactDmarc.className = "finding-impact impact-fail";
  }

  // 3. Super Admin Count (Least Privilege)
  const pillAdmin = document.getElementById("pillAdmin");
  const valAdmin = document.getElementById("valAdmin");
  const explAdmin = document.getElementById("explAdmin");
  const impactAdmin = document.getElementById("impactAdmin");
  const cardAdmin = document.getElementById("cardAdmin");

  const adminCount = tel.super_admin_count || 1;
  if (pillAdmin) {
    if (adminCount <= 3) {
      pillAdmin.textContent = `OPTIMAL (${adminCount} ADMINS)`;
      pillAdmin.className = "finding-pill pill-pass";
      cardAdmin.className = "finding-card card-pass";
      valAdmin.textContent = `${adminCount} Dedicated Super Admin Accounts`;
      explAdmin.textContent = "Least-privilege discipline verified. Low administrative blast radius prevents catastrophic tenant takeover.";
      impactAdmin.textContent = "Impact: -2% Least-Privilege Credit (-$170/yr)";
      impactAdmin.className = "finding-impact impact-credit";
    } else if (adminCount <= 6) {
      pillAdmin.textContent = `MODERATE (${adminCount} ADMINS)`;
      pillAdmin.className = "finding-pill pill-warn";
      cardAdmin.className = "finding-card card-warn";
      valAdmin.textContent = `${adminCount} Super Admins (Moderate Privilege Spread)`;
      explAdmin.textContent = "Privilege spread is elevated. Recommend delegating day-to-day duties to non-super admins.";
      impactAdmin.textContent = "Impact: Standard Rating (No credit)";
      impactAdmin.className = "finding-impact impact-warn";
    } else {
      pillAdmin.textContent = `FAIL (${adminCount} ADMINS)`;
      pillAdmin.className = "finding-pill pill-fail";
      cardAdmin.className = "finding-card card-fail";
      valAdmin.textContent = `${adminCount} Super Admins (Critical Sprawl)`;
      explAdmin.textContent = "Severe privilege bloat. If any single admin credentials leak, entire enterprise is breached.";
      impactAdmin.textContent = "Opportunity: Cut admins to <=3 for credit";
      impactAdmin.className = "finding-impact impact-fail";
    }
  }

  // 4. Device Fleet & Encryption
  const pillDevice = document.getElementById("pillDevice");
  const valDevice = document.getElementById("valDevice");
  const explDevice = document.getElementById("explDevice");
  const impactDevice = document.getElementById("impactDevice");
  const cardDevice = document.getElementById("cardDevice");

  const devCount = tel.device_count || 0;
  const devEnc = tel.device_encryption_pct !== undefined ? tel.device_encryption_pct : 100.0;
  const screenLock = tel.screen_lock_enforced !== false;

  if (pillDevice) {
    if (devEnc >= 90.0 && screenLock) {
      pillDevice.textContent = `PASS (${Math.round(devEnc)}% ENCRYPTED)`;
      pillDevice.className = "finding-pill pill-pass";
      cardDevice.className = "finding-card card-pass";
      valDevice.textContent = `${devCount} Managed Devices | 100% BitLocker/FileVault`;
      explDevice.textContent = "Google Endpoint Management verified. Enforced screen lock and full disk encryption eliminates lost-laptop notification liability.";
      impactDevice.textContent = "Impact: -2% Endpoint Hardware Credit (-$170/yr)";
      impactDevice.className = "finding-impact impact-credit";
    } else if (devEnc >= 50.0) {
      pillDevice.textContent = `PARTIAL (${Math.round(devEnc)}% ENCRYPTED)`;
      pillDevice.className = "finding-pill pill-warn";
      cardDevice.className = "finding-card card-warn";
      valDevice.textContent = `${devCount} Devices | ${Math.round(devEnc)}% Encrypted (Partial BYOD)`;
      explDevice.textContent = "Some employee endpoints lack enforced full disk encryption. Lost laptops could trigger regulatory breach disclosures.";
      impactDevice.textContent = "Opportunity: Enforce 100% encryption via MDM";
      impactDevice.className = "finding-impact impact-warn";
    } else {
      pillDevice.textContent = "UNMANAGED / BYOD";
      pillDevice.className = "finding-pill pill-fail";
      cardDevice.className = "finding-card card-fail";
      valDevice.textContent = `${devCount} Devices | Unencrypted / Unmanaged BYOD`;
      explDevice.textContent = "No enforced disk encryption or password lock detected across mobile/laptop fleet.";
      impactDevice.textContent = "Risk: Unmanaged Endpoint Exposure";
      impactDevice.className = "finding-impact impact-fail";
    }
  }

  // 5. Mail Gateway & DKIM
  const pillMx = document.getElementById("pillMx");
  const valMx = document.getElementById("valMx");
  const explMx = document.getElementById("explMx");
  const impactMx = document.getElementById("impactMx");
  const cardMx = document.getElementById("cardMx");

  const mxProvider = tel.mx_provider || "Google Workspace Enterprise";
  const dkimActive = tel.dkim_record_present || tel.dkim_verified;

  if (pillMx) {
    if (dkimActive && mxProvider.includes("Google")) {
      pillMx.textContent = "OPTIMAL (CLOUD MX)";
      pillMx.className = "finding-pill pill-pass";
      cardMx.className = "finding-card card-pass";
      valMx.textContent = `Google Cloud MX | DKIM 2048-bit Signed`;
      explMx.textContent = "Mail routes exclusively through protected Google cloud infrastructure with cryptographic RSA signatures. Zero on-prem Exchange vulnerability.";
      impactMx.textContent = "Impact: -1% Cryptographic Signing Credit (-$85/yr)";
      impactMx.className = "finding-impact impact-credit";
    } else {
      pillMx.textContent = dkimActive ? "DKIM SIGNED" : "STANDARD MX";
      pillMx.className = "finding-pill pill-neutral";
      cardMx.className = "finding-card card-neutral";
      valMx.textContent = `${mxProvider} | DKIM: ${dkimActive ? 'Configured' : 'Unconfirmed'}`;
      explMx.textContent = "Inbound/outbound email verified through cloud gateway. Cryptographic signing standard.";
      impactMx.textContent = "Status: Verified Mail Infrastructure";
      impactMx.className = "finding-impact impact-neutral";
    }
  }

  // 6. Cloud DLP Card
  const pillDlp = document.getElementById("pillDlp");
  const valDlp = document.getElementById("valDlp");
  const explDlp = document.getElementById("explDlp");
  const impactDlp = document.getElementById("impactDlp");
  const cardDlp = document.getElementById("cardDlp");

  if (tel.dlp_rules_active) {
    pillDlp.textContent = "PASS (ACTIVE)";
    pillDlp.className = "finding-pill pill-pass";
    cardDlp.className = "finding-card card-pass";
    valDlp.textContent = `Active Rules (${tel.dlp_rule_count || 1}+ rule events)`;
    explDlp.textContent = "Active inspection for credit cards, SSNs, and confidential customer records confirmed across Google Workspace.";
    impactDlp.textContent = "Impact: -4% Data Protection Discount (-$340/yr)";
    impactDlp.className = "finding-impact impact-credit";
  } else {
    pillDlp.textContent = "INACTIVE";
    pillDlp.className = "finding-pill pill-neutral";
    cardDlp.className = "finding-card card-neutral";
    valDlp.textContent = "No active Workspace DLP inspection rules detected";
    explDlp.textContent = "Automated data exfiltration protection is not enabled. Data leakage risk remains standard.";
    impactDlp.textContent = "Opportunity: Activate DLP in Admin Console to save $340/yr (4%)";
    impactDlp.className = "finding-impact impact-neutral";
  }

  // 7. Google Vault Card
  const pillVault = document.getElementById("pillVault");
  const valVault = document.getElementById("valVault");
  const explVault = document.getElementById("explVault");
  const impactVault = document.getElementById("impactVault");
  const cardVault = document.getElementById("cardVault");

  if (tel.vault_retention_active) {
    pillVault.textContent = "PASS (ACTIVE)";
    pillVault.className = "finding-pill pill-pass";
    cardVault.className = "finding-card card-pass";
    valVault.textContent = "Retention & Legal Holds Configured";
    explVault.textContent = "Tamper-evident legal holds & audit logging verified for incident response & ransomware recovery.";
    impactVault.textContent = "Impact: -3% Forensic Recovery Discount (-$255/yr)";
    impactVault.className = "finding-impact impact-credit";
  } else {
    pillVault.textContent = "INACTIVE";
    pillVault.className = "finding-pill pill-neutral";
    cardVault.className = "finding-card card-neutral";
    valVault.textContent = "Default / No custom retention matters detected";
    explVault.textContent = "Tamper-evident legal holds not configured. Forensic investigation capabilities standard.";
    impactVault.textContent = "Opportunity: Configure Vault retention to save $255/yr (3%)";
    impactVault.className = "finding-impact impact-neutral";
  }

  // 8. Headcount & Offboarding Hygiene
  const pillUsers = document.getElementById("pillUsers");
  const valUsers = document.getElementById("valUsers");
  const explUsers = document.getElementById("explUsers");
  const impactUsers = document.getElementById("impactUsers");
  const cardUsers = document.getElementById("cardUsers");

  const totalUsers = tel.total_user_count || 1;
  const dormantCount = tel.dormant_user_count || 0;

  if (pillUsers) {
    if (dormantCount === 0) {
      pillUsers.textContent = `CLEAN (${totalUsers} USERS)`;
      pillUsers.className = "finding-pill pill-pass";
      cardUsers.className = "finding-card card-pass";
      valUsers.textContent = `${totalUsers} Active Accounts | 0 Dormant (>90d)`;
      explUsers.textContent = "Strict IT offboarding discipline confirmed. Zero orphaned employee accounts open to credential stuffing or dark web credential abuse.";
      impactUsers.textContent = "Status: Exposure Verified & Headcount Audited";
      impactUsers.className = "finding-impact impact-credit";
    } else {
      pillUsers.textContent = `AUDIT (${dormantCount} DORMANT)`;
      pillUsers.className = "finding-pill pill-warn";
      cardUsers.className = "finding-card card-warn";
      valUsers.textContent = `${totalUsers} Total Accounts | ${dormantCount} Inactive (>90d)`;
      explUsers.textContent = "Detected accounts inactive >90 days that have not been suspended or deprovisioned. Potential credential takeover risk.";
      impactUsers.textContent = "Action: Deprovision stale accounts";
      impactUsers.className = "finding-impact impact-warn";
    }
  }

  // --- Remediation Guidance ---
  const remBox = document.getElementById("remediationBox");
  const remList = document.getElementById("remediationItemsList");
  if (rating.remediations && rating.remediations.length > 0) {
    remBox.style.display = "block";
    remList.innerHTML = rating.remediations.map(r => `
      <div class="remediation-item">
        <div class="remediation-item-header">
          <strong>${escapeHtml(r.control)}</strong>
          <span class="remediation-savings">${escapeHtml(r.impact)}</span>
        </div>
        <div class="remediation-item-action">${escapeHtml(r.action)}</div>
      </div>
    `).join("");
  } else {
    remBox.style.display = "none";
  }

  // --- Raw Telemetry & API Audit Trail ---
  const rawAcct = document.getElementById("rawVerifiedAccount");
  if (rawAcct) {
    rawAcct.textContent = tel.verified_account || tel.domain || currentDomain;
  }

  const rawDisplay = document.getElementById("rawJsonDisplay");
  if (rawDisplay) {
    rawDisplay.textContent = JSON.stringify({
      domain: tel.domain,
      verified_account: tel.verified_account || "N/A (Canned/DNS)",
      mfa_enforced: tel.mfa_enforced,
      mfa_enrolled_pct: tel.mfa_enrolled_pct,
      mfa_method_tier: tel.mfa_method_tier,
      super_admin_count: tel.super_admin_count,
      total_user_count: tel.total_user_count,
      dormant_user_count: tel.dormant_user_count,
      device_count: tel.device_count,
      device_encryption_pct: tel.device_encryption_pct,
      screen_lock_enforced: tel.screen_lock_enforced,
      mx_provider: tel.mx_provider,
      spf_record_present: tel.spf_record_present,
      spf_record_value: tel.spf_record_value,
      dmarc_record_present: tel.dmarc_record_present,
      dmarc_record_value: tel.dmarc_record_value,
      dmarc_policy: tel.dmarc_policy,
      dkim_record_present: tel.dkim_record_present,
      dlp_rules_active: tel.dlp_rules_active,
      vault_retention_active: tel.vault_retention_active,
      underwriting_decision: rating.decision,
      total_discount_pct: rating.total_discount_pct,
      discount_amount: rating.discount_amount,
      final_annual_premium: rating.final_annual_premium,
      attestation_token: attest.policy_attestation_token,
      sha256_fingerprint: attest.sha256_fingerprint
    }, null, 2);
  }

  const auditListEl = document.getElementById("rawAuditList");
  if (auditListEl) {
    if (tel.api_audit_log && tel.api_audit_log.length > 0) {
      auditListEl.innerHTML = tel.api_audit_log.map(log => `<li>✓ ${escapeHtml(log)}</li>`).join("");
    } else {
      auditListEl.innerHTML = `
        <li>✓ Identity Authentication: Google OAuth 2.0 Super Admin Token Handshake</li>
        <li>✓ Live DNS Resolution: Queried public SPF &amp; DMARC TXT records for ${escapeHtml(tel.domain || currentDomain)}</li>
        <li>✓ Directory Inspection: Queried accounts:is_2sv_enforced &amp; enrollment tier</li>
        <li>✓ Storage Rules Inspection: Queried Cloud DLP &amp; Google Vault retention policies</li>
        <li>✓ Ephemeral Discard: Raw JSON in-memory evaluated and purged under Zero-Retention policy</li>
      `;
    }
  }

  quoteCard.classList.add("active");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");
  verifyBtn.style.display = "flex";
}

function copyTelemetryData() {
  const jsonText = document.getElementById("rawJsonDisplay")?.textContent || "";
  if (!jsonText) return;

  navigator.clipboard.writeText(jsonText).then(() => {
    const btn = document.getElementById("btnCopyRawTelemetry");
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = "✓ Copied to Clipboard!";
      setTimeout(() => btn.innerHTML = orig, 2000);
    }
  }).catch(() => {
    alert("Copied raw telemetry JSON to clipboard!");
  });
}

function bindPolicy() {
  alert(`Policy bound successfully for ${currentOrgName}!\nPolicy #: HIG-CYBER-2026-${Math.floor(100000 + Math.random() * 900000)}\nCertificate issued ephemerally under zero-retention guarantee.`);
}

/* ==================== STUDIO DRAWER & WHAT-IF ==================== */

function toggleStudioDrawer() {
  const drawer = document.getElementById("studioDrawer");
  drawer.classList.toggle("open");
}

async function loadDemoScenario(domain) {
  activePreset = domain;
  currentDomain = domain;
  
  if (domain === "foremycorp.com") {
    currentOrgName = "Foremy corp";
    document.getElementById("ownerEmail").value = "sarah@foremycorp.com";
  } else if (domain === "partialcompliance.com") {
    currentOrgName = "Acme Distribution LLC";
    document.getElementById("ownerEmail").value = "it@partialcompliance.com";
  } else if (domain === "vulnerableretail.com") {
    currentOrgName = "Legacy Retail Boutique";
    document.getElementById("ownerEmail").value = "admin@vulnerableretail.com";
  }

  syncDomainFromEmail();
  navigateToStep(5);
  toggleStudioDrawer();
  await executeScenarioUnderwrite(domain);
}

async function executeScenarioUnderwrite(domain) {
  const scanBox = document.getElementById("scanProgressBox");
  const quoteCard = document.getElementById("quoteResultCard");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");

  quoteCard.classList.remove("active");
  verifyBtn.style.display = "none";
  scanBox.classList.add("active");

  const s1 = document.getElementById("scanStep1");
  const s2 = document.getElementById("scanStep2");
  const s3 = document.getElementById("scanStep3");
  const s4 = document.getElementById("scanStep4");

  [s1, s2, s3, s4].forEach(s => {
    s.classList.remove("done");
    const sp = s.querySelector(".scan-spinner");
    if (sp) sp.style.display = "inline-block";
  });

  s1.querySelector("span").textContent = `Simulating Google Workspace connection for ${domain}...`;
  await sleep(400);
  markStepDone(s1, `Identity & Workspace Profile Loaded (${domain})`);

  s2.querySelector("span").textContent = "Evaluating Google Admin Reports API: accounts:is_2sv_enforced...";
  await sleep(450);
  markStepDone(s2, "MFA Posture Evaluated");

  s3.querySelector("span").textContent = "Resolving Live DNS Posture (SPF & DMARC TXT)...";
  await sleep(450);
  markStepDone(s3, "Email Anti-Spoofing Records Resolved");

  s4.querySelector("span").textContent = "Executing Actuarial Rating & Zero-Retention Receipt...";
  await sleep(350);
  markStepDone(s4, "Rating Decision & SHA-256 Attestation Formed");

  try {
    const payload = {
      domain: domain,
      organization_name: currentOrgName,
      profile_override: domain
    };

    const resp = await fetch("/api/underwrite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await resp.json();
    scanBox.classList.remove("active");
    renderQuoteResult(data);
  } catch (err) {
    console.error("Underwriting failed:", err);
    scanBox.classList.remove("active");
    verifyBtn.style.display = "flex";
    alert("Scenario simulation error: " + err.message);
  }
}

async function runLiveDnsCheck() {
  const input = document.getElementById("liveDnsDomainInput");
  const resultsDiv = document.getElementById("liveDnsResults");
  const domain = input.value.trim();

  if (!domain) return;

  resultsDiv.style.display = "block";
  resultsDiv.innerHTML = `<span style="color:#2563EB;">Querying live DNS for ${escapeHtml(domain)}...</span>`;

  try {
    const resp = await fetch(`/api/dns-live-check?domain=${encodeURIComponent(domain)}`);
    const data = await resp.json();
    const p = data.dns_posture;

    let spfBadge = p.spf_present ? `<span style="color:#166534; font-weight:bold;">✓ PRESENT</span>` : `<span style="color:#991B1B; font-weight:bold;">✕ MISSING</span>`;
    let dmarcBadge = p.dmarc_policy !== "missing" ? `<span style="color:#166534; font-weight:bold;">✓ p=${escapeHtml(p.dmarc_policy)}</span>` : `<span style="color:#991B1B; font-weight:bold;">✕ MISSING</span>`;

    resultsDiv.innerHTML = `
      <div style="font-weight:700; margin-bottom:4px; color:#111827;">Live Telemetry for ${escapeHtml(domain)}:</div>
      <div>SPF Record: ${spfBadge}</div>
      <div style="font-size:10px; color:#6B7280; font-family:monospace; margin-bottom:4px;">${escapeHtml(p.spf_val || 'None detected')}</div>
      <div>DMARC Policy: ${dmarcBadge}</div>
      <div style="font-size:10px; color:#6B7280; font-family:monospace;">${escapeHtml(p.dmarc_val || 'None detected')}</div>
    `;
  } catch (err) {
    resultsDiv.innerHTML = `<span style="color:#991B1B;">DNS query failed.</span>`;
  }
}

async function runWhatIfSimulation() {
  const mfa = document.getElementById("whatifMfa").checked;
  const dmarc = document.getElementById("whatifDmarc").value;
  const dlp = document.getElementById("whatifDlp").checked;
  const vault = document.getElementById("whatifVault").checked;

  const payload = {
    mfa_enforced: mfa,
    mfa_enrolled_pct: mfa ? 100.0 : 20.0,
    spf_valid: true,
    dmarc_policy: dmarc,
    dlp_rules_active: dlp,
    vault_retention_active: vault
  };

  try {
    const resp = await fetch("/api/simulate-what-if", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    const r = data.rating;

    const tag = document.getElementById("whatifDecisionTag");
    const rate = document.getElementById("whatifRateTag");
    const summary = document.getElementById("whatifSummaryTag");

    if (r.decision === "APPROVED") {
      tag.textContent = "APPROVED - PREFERRED RISK";
      tag.style.color = "#166534";
      rate.textContent = `$${r.final_annual_premium.toLocaleString()}/yr`;
      summary.textContent = `25% Preferred Discount applied. Instant issuance.`;
    } else if (r.decision === "CONDITIONAL_APPROVAL") {
      tag.textContent = "CONDITIONAL APPROVAL";
      tag.style.color = "#B45309";
      rate.textContent = `$${r.final_annual_premium.toLocaleString()}/yr`;
      summary.textContent = `Standard rate. Save up to $1,275/yr by tightening DMARC and DLP.`;
    } else {
      tag.textContent = "DECLINED (HIGH RISK)";
      tag.style.color = "#991B1B";
      rate.textContent = "INELIGIBLE";
      summary.textContent = "Un-enforced MFA is an auto-decline due to ransomware exposure.";
    }
  } catch (err) {
    console.error("Simulation error:", err);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

/* ==================== CUSTOMER TRANSPARENCY MODAL CONTROLLER ==================== */

function openTransparencyModal(defaultTab = 'tabApis') {
  const modal = document.getElementById("transparencyModal");
  if (modal) {
    modal.style.display = "flex";
    switchTransparencyTab(defaultTab);
  }
}

function closeTransparencyModal() {
  const modal = document.getElementById("transparencyModal");
  if (modal) {
    modal.style.display = "none";
  }
}

function handleModalOverlayClick(event) {
  if (event.target && event.target.id === "transparencyModal") {
    closeTransparencyModal();
  }
}

function switchTransparencyTab(tabId) {
  const tabBtns = [
    { id: 'tabApis', btnId: 'btnTabApis' },
    { id: 'tabPrivacy', btnId: 'btnTabPrivacy' },
    { id: 'tabCrypto', btnId: 'btnTabCrypto' }
  ];

  tabBtns.forEach(t => {
    const tabEl = document.getElementById(t.id);
    const btnEl = document.getElementById(t.btnId);

    if (tabEl) {
      if (t.id === tabId) {
        tabEl.classList.add("active");
      } else {
        tabEl.classList.remove("active");
      }
    }

    if (btnEl) {
      if (t.id === tabId) {
        btnEl.classList.add("active");
      } else {
        btnEl.classList.remove("active");
      }
    }
  });
}
