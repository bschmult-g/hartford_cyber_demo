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

function navigateToHome() {
  if (typeof closeTransparencyModal === "function") {
    closeTransparencyModal();
  }
  const drawer = document.getElementById("studioDrawer");
  if (drawer && drawer.classList.contains("open")) {
    drawer.classList.remove("open");
  }
  navigateToStep(0);
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

    // Retain clean results layout if verification data already exists
    const precheckView = document.getElementById("step5PrecheckView");
    const resultsView = document.getElementById("step5ResultsView");
    if (lastTelemetryData) {
      if (precheckView) precheckView.style.display = "none";
      if (resultsView) resultsView.style.display = "block";
      const quoteCard = document.getElementById("quoteResultCard");
      if (quoteCard) quoteCard.classList.add("active");
    } else {
      if (precheckView) precheckView.style.display = "block";
      if (resultsView) resultsView.style.display = "none";
      const verifyBtn = document.getElementById("btnTriggerGoogleVerify");
      if (verifyBtn) verifyBtn.style.display = "flex";
    }
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
  const uwPanel = document.getElementById("underwriterIntelPanel");
  if (uwPanel) uwPanel.style.display = "none";

  const precheckView = document.getElementById("step5PrecheckView");
  if (precheckView) precheckView.style.display = "block";
  const resultsView = document.getElementById("step5ResultsView");
  if (resultsView) resultsView.style.display = "none";

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

/**
 * Distinguishes the exact root cause when a Google API returns 403 or unverified status:
 * 1. GCP_API_DISABLED: The Admin SDK API is disabled in Google Cloud Console project 799321431260
 * 2. WORKSPACE_RBAC_FORBIDDEN: Standard Employee account in Google Workspace lacking Delegated Admin privileges
 * 3. CONSUMER_ACCOUNT: Personal @gmail.com account lacking an enterprise domain
 * 4. UNLICENSED_EDITION: The Google Workspace edition does not license this module
 * 5. NOT_AUTHENTICATED: Session unauthenticated, only public DNS queried
 */
function formatControlUnverified(errorType, errorDetail, defaultApiName, defaultPerm) {
  if (errorType === "GCP_API_DISABLED") {
    return {
      pillText: "GCP API DISABLED (403)",
      pillClass: "finding-pill pill-warn",
      cardClass: "finding-card card-warn",
      valText: `GCP Project Config: ${defaultApiName} Disabled`,
      explText: `Google Cloud Project 799321431260 has not enabled ${defaultApiName} in Google Cloud Console. Google API returned HTTP 403: "${errorDetail || 'accessNotConfigured'}". Underwriting verification is paused pending cloud API enablement, not an applicant policy decline.`,
      impactText: "Fix: Enable Admin SDK API in Google Cloud Console",
      impactClass: "finding-impact impact-warn"
    };
  } else if (errorType === "CONSUMER_ACCOUNT") {
    return {
      pillText: "CONSUMER ACCOUNT",
      pillClass: "finding-pill pill-fail",
      cardClass: "finding-card card-fail",
      valText: "Personal @gmail.com (No Tenant)",
      explText: `Personal consumer accounts lack a Google Workspace organizational directory. Cannot query enterprise ${defaultApiName} policies on personal accounts.`,
      impactText: "Requirement: Corporate Google Workspace Domain",
      impactClass: "finding-impact impact-fail"
    };
  } else if (errorType === "UNLICENSED_EDITION") {
    return {
      pillText: "UNLICENSED (403)",
      pillClass: "finding-pill pill-neutral",
      cardClass: "finding-card card-neutral",
      valText: "Unlicensed in Workspace Edition",
      explText: `Google Workspace API returned: "${errorDetail || 'Feature not licensed'}". The applicant's Google Workspace subscription edition does not include this enterprise module.`,
      impactText: "Status: Ineligible for Enterprise Credit",
      impactClass: "finding-impact impact-neutral"
    };
  } else if (errorType === "NOT_AUTHENTICATED") {
    return {
      pillText: "NOT AUTHENTICATED",
      pillClass: "finding-pill pill-neutral",
      cardClass: "finding-card card-neutral",
      valText: "Workspace Telemetry Not Queried",
      explText: "Applicant has not authenticated with Google Workspace. Only public DNS signals (SPF, DMARC, MX) were resolved.",
      impactText: "Status: Standard DNS Rate (No Workspace Credits)",
      impactClass: "finding-impact impact-neutral"
    };
  } else {
    // WORKSPACE_RBAC_FORBIDDEN (Standard Employee / Not Authorized)
    return {
      pillText: "WORKSPACE RBAC GATE (403)",
      pillClass: "finding-pill pill-fail",
      cardClass: "finding-card card-fail",
      valText: "Blocked by Google Workspace RBAC (HTTP 403)",
      explText: `Account authenticated successfully, but Google returned HTTP 403 Forbidden ("Not Authorized to access this resource/api"). In Google Workspace, standard employee accounts cannot read domain-wide security controls without Delegated Admin privileges.`,
      impactText: `Action Required: Grant '${defaultPerm}' Delegated Role`,
      impactClass: "finding-impact impact-fail"
    };
  }
}

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

  // Clean up screen: transition to verified results dashboard mode
  const precheckView = document.getElementById("step5PrecheckView");
  if (precheckView) precheckView.style.display = "none";
  const resultsView = document.getElementById("step5ResultsView");
  if (resultsView) resultsView.style.display = "block";
  const resultsDomainHeader = document.getElementById("resultsDomainHeader");
  if (resultsDomainHeader) resultsDomainHeader.textContent = tel.domain || currentDomain;
  if (quoteCard) quoteCard.classList.add("active");

  tierBadge.className = "tier-badge";
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
  } else if (rating.decision === "GCP_CONFIGURATION_REQUIRED") {
    tierBadge.classList.add("badge-conditional");
    tierBadge.textContent = rating.tier_display || "ACTION REQUIRED: GCP API DISABLED (403)";
    quoteDecision.textContent = "GCP API NOT ENABLED (403)";
    quoteDecision.style.color = "#D97706";
    if (btnBind) {
      btnBind.disabled = true;
      btnBind.style.background = "#D97706";
      btnBind.style.cursor = "not-allowed";
      btnBind.textContent = "🔧 Enable Admin SDK API in Google Cloud Console";
    }
  } else if (rating.decision === "CONSUMER_ACCOUNT_INELIGIBLE") {
    tierBadge.classList.add("badge-declined");
    tierBadge.textContent = rating.tier_display || "ACTION REQUIRED: CORPORATE DOMAIN";
    quoteDecision.textContent = "CONSUMER GMAIL INELIGIBLE";
    quoteDecision.style.color = "#DC2626";
    if (btnBind) {
      btnBind.disabled = true;
      btnBind.style.background = "#DC2626";
      btnBind.style.cursor = "not-allowed";
      btnBind.textContent = "🔒 Corporate Google Workspace Domain Required";
    }
  } else if (rating.decision === "INSUFFICIENT_DELEGATION") {
    tierBadge.classList.add("badge-declined");
    tierBadge.textContent = rating.tier_display || "ACTION REQUIRED: DELEGATED ADMIN ROLE (403)";
    quoteDecision.textContent = "INSUFFICIENT WORKSPACE ROLE (403)";
    quoteDecision.style.color = "#DC2626";
    if (btnBind) {
      btnBind.disabled = true;
      btnBind.style.background = "#DC2626";
      btnBind.style.cursor = "not-allowed";
      btnBind.textContent = "🔒 Delegated Admin Role Required in Google Workspace";
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
    const tok = attest.policy_attestation_token || "—";
    const hsh = attest.sha256_fingerprint || "—";
    if (attestToken) attestToken.textContent = tok;
    if (attestHash) attestHash.textContent = hsh;
    const attestTokenFull = document.getElementById("attestTokenFull");
    if (attestTokenFull) attestTokenFull.textContent = tok;
    const attestHashFull = document.getElementById("attestHashFull");
    if (attestHashFull) attestHashFull.textContent = hsh;
  }

  // Calculate passed controls for Executive Hero KPI
  let passedControls = 0;
  if (tel.mfa_enforced) passedControls++;
  if (tel.dmarc_policy === "reject" || tel.dmarc_policy === "quarantine") passedControls++;
  if (tel.super_admin_count !== null && tel.super_admin_count !== undefined && tel.super_admin_count <= 3) passedControls++;
  if (tel.device_encryption_pct !== null && tel.device_encryption_pct !== undefined && tel.device_encryption_pct >= 90.0) passedControls++;
  if (tel.dkim_record_present || tel.dkim_verified) passedControls++;
  if (tel.dlp_rules_active) passedControls++;
  if (tel.vault_retention_active) passedControls++;
  if (tel.dormant_user_count === 0 && tel.total_user_count > 0) passedControls++;

  const kpiControls = document.getElementById("kpiControlsCount");
  const kpiControlsTag = document.getElementById("kpiControlsTag");
  if (kpiControls) {
    if (rating.decision === "GCP_CONFIGURATION_REQUIRED") {
      kpiControls.textContent = "GCP API Paused";
      if (kpiControlsTag) {
        kpiControlsTag.textContent = "API Disabled (403)";
        kpiControlsTag.className = "kpi-tag kpi-tag-crit";
      }
    } else if (rating.decision === "INSUFFICIENT_DELEGATION") {
      kpiControls.textContent = "RBAC Blocked";
      if (kpiControlsTag) {
        kpiControlsTag.textContent = "Standard User (403)";
        kpiControlsTag.className = "kpi-tag kpi-tag-crit";
      }
    } else if (rating.decision === "CONSUMER_ACCOUNT_INELIGIBLE") {
      kpiControls.textContent = "Personal Gmail";
      if (kpiControlsTag) {
        kpiControlsTag.textContent = "No Tenant";
        kpiControlsTag.className = "kpi-tag kpi-tag-crit";
      }
    } else {
      kpiControls.textContent = `${passedControls} of 8 Passed`;
      if (kpiControlsTag) {
        if (passedControls === 8) {
          kpiControlsTag.textContent = "100% Verified";
          kpiControlsTag.className = "kpi-tag kpi-tag-pass";
        } else if (passedControls >= 5) {
          kpiControlsTag.textContent = "Sufficient Defense";
          kpiControlsTag.className = "kpi-tag kpi-tag-opt";
        } else {
          kpiControlsTag.textContent = "Gaps Detected";
          kpiControlsTag.className = "kpi-tag kpi-tag-crit";
        }
      }
    }
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

  // Live Delegation Status Banner
  const delegationBanner = document.getElementById("delegationBanner");
  const delegationAccount = document.getElementById("delegationAccount");
  const delegationSubtitle = document.getElementById("delegationSubtitle");
  const delegationPill = document.getElementById("delegationPill");
  const delegationIcon = document.getElementById("delegationIcon");

  if (delegationBanner) {
    const acct = tel.verified_account || "Unknown Account";
    const role = tel.account_role || "STANDARD_USER";
    const rbacCause = tel.rbac_block_cause;

    if (delegationAccount) delegationAccount.textContent = acct;

    if (role === "SUPER_ADMIN" && tel.delegation_verified) {
      if (delegationIcon) delegationIcon.textContent = "👑";
      if (delegationSubtitle) delegationSubtitle.innerHTML = "Google Workspace RBAC: <strong>Super Admin Verified</strong> (Direct administrative authority across tenant)";
      if (delegationPill) {
        delegationPill.textContent = "SUPER ADMIN";
        delegationPill.className = "finding-pill pill-pass";
      }
      delegationBanner.style.background = "#F0FDF4";
      delegationBanner.style.borderColor = "#BBF7D0";
    } else if (role === "DELEGATED_ADMIN" && tel.delegation_verified) {
      if (delegationIcon) delegationIcon.textContent = "🛡️";
      if (delegationSubtitle) delegationSubtitle.innerHTML = "Google Workspace RBAC: <strong>Delegated Admin Verified</strong> (Least-privilege read-only security auditor role)";
      if (delegationPill) {
        delegationPill.textContent = "DELEGATED ADMIN";
        delegationPill.className = "finding-pill pill-pass";
      }
      delegationBanner.style.background = "#F0FDF4";
      delegationBanner.style.borderColor = "#BBF7D0";
    } else if (rbacCause === "GCP_API_DISABLED") {
      // 1. CLEARLY DISTINGUISH GCP PROJECT RESOURCE DEPLOYMENT ISSUE (API DISABLED)
      if (delegationIcon) delegationIcon.textContent = "🔧";
      if (delegationSubtitle) {
        delegationSubtitle.innerHTML = `<strong style="color:#B45309;">Google Cloud Project Config (HTTP 403):</strong> The Admin SDK API is disabled in Google Cloud Console project <code>799321431260</code>. Underwriting is paused pending cloud API enablement, <em>not an applicant policy decline</em>.`;
      }
      if (delegationPill) {
        delegationPill.textContent = "GCP API DISABLED (403)";
        delegationPill.className = "finding-pill pill-warn";
      }
      delegationBanner.style.background = "#FFFBEB";
      delegationBanner.style.borderColor = "#FDE68A";
    } else if (rbacCause === "CONSUMER_ACCOUNT") {
      // 2. CLEARLY DISTINGUISH CONSUMER GMAIL
      if (delegationIcon) delegationIcon.textContent = "👤";
      if (delegationSubtitle) {
        delegationSubtitle.innerHTML = `<strong style="color:#B91C1C;">Consumer Gmail Account:</strong> Authenticated with a personal account (<code>${escapeHtml(acct)}</code>). Commercial cyber insurance underwriting requires an organization-managed Google Workspace corporate tenant.`;
      }
      if (delegationPill) {
        delegationPill.textContent = "CONSUMER GMAIL";
        delegationPill.className = "finding-pill pill-fail";
      }
      delegationBanner.style.background = "#FEF2F2";
      delegationBanner.style.borderColor = "#FECACA";
    } else if (role === "NOT_AUTHENTICATED") {
      if (delegationIcon) delegationIcon.textContent = "🌐";
      if (delegationSubtitle) delegationSubtitle.textContent = "Unauthenticated Session: Public DNS Only (Workspace Telemetry Not Queried)";
      if (delegationPill) {
        delegationPill.textContent = "UNAUTHENTICATED";
        delegationPill.className = "finding-pill pill-neutral";
      }
      delegationBanner.style.background = "#F8FAFC";
      delegationBanner.style.borderColor = "#E2E8F0";
    } else {
      // 3. CLEARLY DISTINGUISH WORKSPACE RBAC AUTHORIZATION GATE
      if (delegationIcon) delegationIcon.textContent = "🔒";
      if (delegationSubtitle) {
        delegationSubtitle.innerHTML = `<strong style="color:#B91C1C;">Google Workspace RBAC Authorization Gate (HTTP 403):</strong> Account <code>${escapeHtml(acct)}</code> authenticated, but is a <em>Standard Employee</em> lacking Delegated Admin privileges in Google Workspace. Domain-wide security posture cannot be read without administrative delegation.`;
      }
      if (delegationPill) {
        delegationPill.textContent = "WORKSPACE RBAC GATE (403)";
        delegationPill.className = "finding-pill pill-fail";
      }
      delegationBanner.style.background = "#FEF2F2";
      delegationBanner.style.borderColor = "#FECACA";
    }
  }

  // Default error cause if control-specific error is not populated
  const defaultErrType = tel.account_role === "NOT_AUTHENTICATED" ? "NOT_AUTHENTICATED" : (tel.rbac_block_cause || "WORKSPACE_ROLE_STANDARD");

  // 1. MFA / 2SV Card
  const pillMfa = document.getElementById("pillMfa");
  const valMfa = document.getElementById("valMfa");
  const explMfa = document.getElementById("explMfa");
  const impactMfa = document.getElementById("impactMfa");
  const cardMfa = document.getElementById("cardMfa");

  if (tel.mfa_enforced === null || tel.mfa_enrolled_pct === null || tel.mfa_enrolled_pct === undefined) {
    const unv = formatControlUnverified(tel.mfa_error_type || defaultErrType, tel.mfa_error_detail || tel.rbac_block_detail, "Admin Reports API", "Reports (Read)");
    pillMfa.textContent = unv.pillText;
    pillMfa.className = unv.pillClass;
    cardMfa.className = unv.cardClass;
    valMfa.textContent = unv.valText;
    explMfa.textContent = unv.explText;
    impactMfa.textContent = unv.impactText;
    impactMfa.className = unv.impactClass;
  } else if (tel.mfa_enforced) {
    pillMfa.textContent = `PASS (${tel.mfa_enrolled_pct}% ENFORCED)`;
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
    valMfa.textContent = `Unenforced (${tel.mfa_enrolled_pct || 0}% Enrolled in Workspace)`;
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

  const dmarcPolicy = tel.dmarc_policy || "missing";
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

  const adminCount = tel.super_admin_count;
  if (pillAdmin) {
    if (adminCount === null || adminCount === undefined) {
      const unv = formatControlUnverified(tel.directory_error_type || defaultErrType, tel.directory_error_detail || tel.rbac_block_detail, "Directory Users API", "Users (Read)");
      pillAdmin.textContent = unv.pillText;
      pillAdmin.className = unv.pillClass;
      cardAdmin.className = unv.cardClass;
      valAdmin.textContent = unv.valText;
      explAdmin.textContent = unv.explText;
      impactAdmin.textContent = unv.impactText;
      impactAdmin.className = unv.impactClass;
    } else if (adminCount <= 3) {
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

  const devCount = tel.device_count;
  const devEnc = tel.device_encryption_pct;
  const screenLock = tel.screen_lock_enforced;

  if (pillDevice) {
    if (devCount === null || devCount === undefined) {
      const unv = formatControlUnverified(tel.endpoint_error_type || defaultErrType, tel.endpoint_error_detail || tel.rbac_block_detail, "Endpoint Management API", "Mobile Device Management");
      pillDevice.textContent = unv.pillText;
      pillDevice.className = unv.pillClass;
      cardDevice.className = unv.cardClass;
      valDevice.textContent = unv.valText;
      explDevice.textContent = unv.explText;
      impactDevice.textContent = unv.impactText;
      impactDevice.className = unv.impactClass;
    } else if (devCount === 0) {
      pillDevice.textContent = "0 ENROLLED DEVICES";
      pillDevice.className = "finding-pill pill-neutral";
      cardDevice.className = "finding-card card-neutral";
      valDevice.textContent = "0 Devices in Google Endpoint Management";
      explDevice.textContent = "No mobile or laptop endpoints enrolled in Google Endpoint Management.";
      impactDevice.textContent = "Status: No Enrolled Endpoint Credit";
      impactDevice.className = "finding-impact impact-neutral";
    } else if (devEnc >= 90.0 && screenLock) {
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

  const mxProvider = tel.mx_provider || "Unresolved Mail Provider";
  const dkimActive = tel.dkim_record_present || tel.dkim_verified;

  if (pillMx) {
    if (dkimActive && mxProvider.includes("Google")) {
      pillMx.textContent = "OPTIMAL (CLOUD MX)";
      pillMx.className = "finding-pill pill-pass";
      cardMx.className = "finding-card card-pass";
      valMx.textContent = `Google Cloud MX | DKIM Signed`;
      explMx.textContent = "Mail routes exclusively through protected Google cloud infrastructure with cryptographic RSA signatures. Zero on-prem Exchange vulnerability.";
      impactMx.textContent = "Impact: -1% Cryptographic Signing Credit (-$85/yr)";
      impactMx.className = "finding-impact impact-credit";
    } else if (dkimActive) {
      pillMx.textContent = "PASS (DKIM SIGNED)";
      pillMx.className = "finding-pill pill-pass";
      cardMx.className = "finding-card card-pass";
      valMx.textContent = `${mxProvider} | DKIM Signed`;
      explMx.textContent = "Inbound/outbound email verified through mail gateway with cryptographic RSA signatures.";
      impactMx.textContent = "Impact: -1% Cryptographic Signing Credit (-$85/yr)";
      impactMx.className = "finding-impact impact-credit";
    } else {
      pillMx.textContent = "STANDARD MX";
      pillMx.className = "finding-pill pill-neutral";
      cardMx.className = "finding-card card-neutral";
      valMx.textContent = `${mxProvider} | DKIM: Unconfirmed`;
      explMx.textContent = "Inbound/outbound email verified through mail gateway. Cryptographic DKIM signing unconfirmed.";
      impactMx.textContent = "Status: Standard Mail Delivery";
      impactMx.className = "finding-impact impact-neutral";
    }
  }

  // 6. Cloud DLP Card
  const pillDlp = document.getElementById("pillDlp");
  const valDlp = document.getElementById("valDlp");
  const explDlp = document.getElementById("explDlp");
  const impactDlp = document.getElementById("impactDlp");
  const cardDlp = document.getElementById("cardDlp");

  if (tel.dlp_rules_active === null || tel.dlp_rules_active === undefined) {
    const unv = formatControlUnverified(tel.dlp_error_type || defaultErrType, tel.dlp_error_detail || tel.rbac_block_detail, "Workspace Rules API", "Security & Compliance");
    pillDlp.textContent = unv.pillText;
    pillDlp.className = unv.pillClass;
    cardDlp.className = unv.cardClass;
    valDlp.textContent = unv.valText;
    explDlp.textContent = unv.explText;
    impactDlp.textContent = unv.impactText;
    impactDlp.className = unv.impactClass;
  } else if (tel.dlp_rules_active) {
    pillDlp.textContent = "PASS (ACTIVE)";
    pillDlp.className = "finding-pill pill-pass";
    cardDlp.className = "finding-card card-pass";
    valDlp.textContent = `Active Rules (${tel.dlp_rule_count || 0} rule events)`;
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

  if (tel.vault_retention_active === null || tel.vault_retention_active === undefined) {
    const unv = formatControlUnverified(tel.vault_error_type || defaultErrType, tel.vault_error_detail || tel.rbac_block_detail, "Google Vault API", "eDiscovery / Vault");
    pillVault.textContent = unv.pillText;
    pillVault.className = unv.pillClass;
    cardVault.className = unv.cardClass;
    valVault.textContent = unv.valText;
    explVault.textContent = unv.explText;
    impactVault.textContent = unv.impactText;
    impactVault.className = unv.impactClass;
  } else if (tel.vault_retention_active) {
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

  const totalUsers = tel.total_user_count;
  const dormantCount = tel.dormant_user_count;

  if (pillUsers) {
    if (totalUsers === null || totalUsers === undefined) {
      const unv = formatControlUnverified(tel.directory_error_type || defaultErrType, tel.directory_error_detail || tel.rbac_block_detail, "Directory Users API", "Users (Read)");
      pillUsers.textContent = unv.pillText;
      pillUsers.className = unv.pillClass;
      cardUsers.className = unv.cardClass;
      valUsers.textContent = unv.valText;
      explUsers.textContent = unv.explText;
      impactUsers.textContent = unv.impactText;
      impactUsers.className = unv.impactClass;
    } else if (dormantCount === 0) {
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
      verified_account: tel.verified_account || "N/A",
      account_role: tel.account_role || "UNKNOWN",
      delegation_verified: tel.delegation_verified || false,
      rbac_block_cause: tel.rbac_block_cause || "NONE",
      rbac_block_detail: tel.rbac_block_detail || "None",
      error_diagnostics: {
        mfa_error: { type: tel.mfa_error_type, detail: tel.mfa_error_detail },
        directory_error: { type: tel.directory_error_type, detail: tel.directory_error_detail },
        endpoint_error: { type: tel.endpoint_error_type, detail: tel.endpoint_error_detail },
        vault_error: { type: tel.vault_error_type, detail: tel.vault_error_detail },
        dlp_error: { type: tel.dlp_error_type, detail: tel.dlp_error_detail }
      },
      directory_access_granted: tel.directory_access_granted || false,
      reports_access_granted: tel.reports_access_granted || false,
      endpoint_access_granted: tel.endpoint_access_granted || false,
      vault_access_granted: tel.vault_access_granted || false,
      dlp_access_granted: tel.dlp_access_granted || false,
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
      auditListEl.innerHTML = tel.api_audit_log.map(log => {
        const isGcp = log.includes("403 GCP Error") || log.includes("GCP_API_DISABLED");
        const isRbac = log.includes("403 Workspace RBAC") || log.includes("Standard User") || log.includes("Not Authorized");
        const isErr = isGcp || isRbac || log.includes("failed") || log.includes("error");
        
        let icon = "✓";
        let color = "#166534";
        let bg = "#F0FDF4";
        let border = "#BBF7D0";

        if (isGcp) {
          icon = "🔧";
          color = "#B45309";
          bg = "#FFFBEB";
          border = "#FDE68A";
        } else if (isRbac) {
          icon = "🔒";
          color = "#B91C1C";
          bg = "#FEF2F2";
          border = "#FECACA";
        } else if (isErr) {
          icon = "⚠️";
          color = "#991B1B";
          bg = "#FEF2F2";
          border = "#FECACA";
        }

        return `<li style="list-style:none; margin-bottom:6px; padding:6px 10px; border-radius:6px; background:${bg}; border:1px solid ${border}; color:${color}; font-size:11px; font-family:monospace;">
          <span style="font-weight:700; margin-right:6px;">${icon}</span>${escapeHtml(log)}
        </li>`;
      }).join("");
    } else {
      auditListEl.innerHTML = `
        <li style="list-style:none; margin-bottom:6px; padding:6px 10px; border-radius:6px; background:#F8FAFC; border:1px solid #E2E8F0; color:#64748B; font-size:11px; font-family:monospace;">
          ℹ️ Public DNS Resolution only: Queried SPF, DMARC, and MX records for ${escapeHtml(tel.domain || currentDomain)}. Direct Google Workspace Admin API telemetry was not executed for this unauthenticated session.
        </li>
      `;
    }
  }

  quoteCard.classList.add("active");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");
  if (verifyBtn) verifyBtn.style.display = "none";

  // Activate default Security Controls tab
  switchResultsTab('tabSecurityControls');

  // Underwriter Threat Intelligence Correlation Panel
  const uwPanel = document.getElementById("underwriterIntelPanel");
  if (uwPanel) {
    uwPanel.style.display = "block";
    const sectorSelect = document.getElementById("uwSectorSelect");
    const chosenSector = sectorSelect ? sectorSelect.value : "legal_accounting";
    runUnderwriterSectorAssessment(chosenSector);
  }
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
  const uwPanel = document.getElementById("underwriterIntelPanel");
  if (uwPanel) uwPanel.style.display = "none";

  const precheckView = document.getElementById("step5PrecheckView");
  if (precheckView) precheckView.style.display = "block";
  const resultsView = document.getElementById("step5ResultsView");
  if (resultsView) resultsView.style.display = "none";

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
    { id: 'tabCrypto', btnId: 'btnTabCrypto' },
    { id: 'tabThreatIntel', btnId: 'btnTabThreatIntel' }
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

  if (tabId === 'tabThreatIntel') {
    const modalSelect = document.getElementById("modalSectorSelect");
    const initialSector = modalSelect ? modalSelect.value : "legal_accounting";
    switchModalThreatSector(initialSector);
  }
}

/* ==================== UNDERWRITER THREAT INTEL ENGINE (MANDIANT API) ==================== */

let cachedThreatSectors = null;

async function loadThreatIntelSectors() {
  if (cachedThreatSectors) return cachedThreatSectors;
  try {
    const resp = await fetch("/api/threat-intel/sectors");
    const data = await resp.json();
    if (data.status === "success" || data.status === "ok") {
      cachedThreatSectors = data.sectors;
      return cachedThreatSectors;
    }
  } catch (err) {
    console.error("Failed to fetch threat intel sectors:", err);
  }
  return null;
}

async function switchModalThreatSector(sectorKey) {
  const sectors = await loadThreatIntelSectors();
  if (!sectors) return;
  const s = Array.isArray(sectors) ? sectors.find(item => item.id === sectorKey) : sectors[sectorKey];
  if (!s) return;

  const nameEl = document.getElementById("modalSectorName");
  const badgeEl = document.getElementById("modalSectorThreatLevel");
  const sumEl = document.getElementById("modalSectorSummary");
  const actEl = document.getElementById("modalSectorActors");
  const campEl = document.getElementById("modalSectorCampaign");

  const threatScore = s.threat_score || s.hazard_score || 75;
  const threatLevel = s.threat_level || s.hazard_level || "ELEVATED";

  if (nameEl) nameEl.textContent = s.display_name || s.sector_name || sectorKey;
  if (badgeEl) {
    badgeEl.textContent = `${threatLevel} (${threatScore}/100)`;
    badgeEl.className = threatScore >= 80 ? "uw-threat-badge-crit" : "uw-threat-badge-elev";
  }
  if (sumEl) sumEl.textContent = s.mandiant_intel_summary || s.summary || "";
  if (actEl) actEl.textContent = (s.active_threat_actors || []).join(", ");
  if (campEl) campEl.textContent = s.trending_campaigns || s.trending_campaign || "";
}

function handleUnderwriterSectorChange(sectorKey) {
  runUnderwriterSectorAssessment(sectorKey);
}

async function runUnderwriterSectorAssessment(sectorKey) {
  if (!lastTelemetryData || !lastTelemetryData.telemetry) return;
  const tel = lastTelemetryData.telemetry;

  try {
    const resp = await fetch("/api/threat-intel/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        industry_key: sectorKey,
        telemetry: tel
      })
    });
    const data = await resp.json();
    if ((data.status === "success" || data.status === "ok") && data.assessment) {
      renderUnderwriterAssessment(data.assessment);
    }
  } catch (err) {
    console.error("Failed to run underwriter threat assessment:", err);
  }
}

function renderUnderwriterAssessment(assessment) {
  const sec = assessment.sector || {};
  const threatScore = sec.threat_score || sec.hazard_score || 75;
  const threatLevel = sec.threat_level || sec.hazard_level || "ELEVATED";

  // 1. Sector Threat Banner
  const hazardEl = document.getElementById("uwStatHazard");
  if (hazardEl) {
    const badgeClass = threatScore >= 80 ? "uw-threat-badge-crit" : "uw-threat-badge-elev";
    hazardEl.innerHTML = `<span class="${badgeClass}">${threatLevel} (${threatScore}/100)</span>`;
  }

  const actorsEl = document.getElementById("uwStatActors");
  if (actorsEl) {
    actorsEl.textContent = (sec.active_threat_actors || []).join(", ") || "General Cybercrime Cartels";
  }

  const velocityEl = document.getElementById("uwStatVelocity");
  if (velocityEl) {
    const campaignText = sec.trending_campaigns || sec.trending_campaign || "Active Campaign Surge";
    velocityEl.innerHTML = `<strong style="color:#C2410C;">${assessment.campaign_velocity || "Active Surge"}</strong><br/><span style="color:#475569; font-weight:500; font-size:11px; line-height:1.3; display:inline-block; margin-top:2px;">${escapeHtml(campaignText)}</span>`;
  }

  // 2. Vector Scorecards
  const scorecardList = document.getElementById("uwScorecardList");
  const scorecards = assessment.vector_scorecards || assessment.scorecards || [];
  if (scorecardList && scorecards.length > 0) {
    scorecardList.innerHTML = scorecards.map(sc => {
      let icon = "⚠️";
      let pillClass = sc.badge_class || "pill-warn";
      if (sc.status === "VERIFIED_NEUTRALIZED" || sc.status === "MITIGATED" || sc.status === "ADEQUATELY_DEFENDED") {
        icon = "✅";
        if (!sc.badge_class) pillClass = "pill-pass";
      } else if (sc.status === "CRITICAL_EXPOSURE" || sc.status === "HIGH_BLAST_RADIUS" || sc.status === "UNMANAGED_BYOD") {
        icon = "🚨";
        if (!sc.badge_class) pillClass = "pill-fail";
      } else if (sc.status === "UNVERIFIED") {
        icon = "🔒";
        if (!sc.badge_class) pillClass = "pill-fail";
      }

      const displayLabel = sc.status_label || sc.status || "Evaluated";

      return `
        <div class="uw-scorecard-row">
          <div class="uw-scorecard-top">
            <div class="uw-scorecard-vector">
              <span>${icon}</span>
              <span>${escapeHtml(sc.vector_name)}</span>
              <span class="uw-scorecard-prev">${sc.prevalence_pct}% sector prevalence</span>
            </div>
            <span class="finding-pill ${pillClass}">${escapeHtml(displayLabel)}</span>
          </div>
          <div class="uw-scorecard-evidence">
            <strong style="color:#0F172A;">Verified Evidence:</strong> <span style="color:#334155;">${escapeHtml(sc.evidence)}</span>
          </div>
          <div class="uw-scorecard-underwriter">
            <strong>Mandiant / Underwriter Context:</strong> ${escapeHtml(sc.underwriter_note || sc.underwriter_rationale || "")}
          </div>
        </div>
      `;
    }).join("");
  }

  // 3. Verdict Card & Fit Score
  const sublimitActionEl = document.getElementById("uwSublimitAction");
  if (sublimitActionEl) {
    const actionText = assessment.sublimit_action || assessment.sublimit_recommendation || "Standard Terms Apply";
    sublimitActionEl.textContent = actionText;
    if (actionText.includes("WAIVED")) {
      sublimitActionEl.style.color = "#166534";
    } else if (actionText.includes("APPLIED") || actionText.includes("RESTRICTIVE")) {
      sublimitActionEl.style.color = "#DC2626";
    } else {
      sublimitActionEl.style.color = "#92400E";
    }
  }

  const verdictRecEl = document.getElementById("uwVerdictRec");
  if (verdictRecEl) {
    verdictRecEl.textContent = assessment.underwriter_recommendation || assessment.underwriter_guidance || "";
  }

  const fitScore = assessment.posture_fit_score !== undefined ? assessment.posture_fit_score : (assessment.threat_defense_fit_score || 0);
  const fitScoreEl = document.getElementById("uwFitScore");
  const verdictCard = document.getElementById("uwVerdictCard");
  if (fitScoreEl && verdictCard) {
    fitScoreEl.textContent = `${fitScore}/100`;
    verdictCard.className = "uw-verdict-card";

    if (fitScore >= 80) {
      fitScoreEl.style.color = "#166534";
    } else if (fitScore >= 50) {
      verdictCard.classList.add("verdict-warn");
      fitScoreEl.style.color = "#D97706";
    } else {
      verdictCard.classList.add("verdict-crit");
      fitScoreEl.style.color = "#DC2626";
    }
  }

  // Update Hero KPI Chip
  const kpiThreat = document.getElementById("kpiThreatScore");
  const kpiThreatTag = document.getElementById("kpiThreatTag");
  if (kpiThreat) {
    kpiThreat.textContent = `${fitScore} / 100`;
    if (kpiThreatTag) {
      if (fitScore >= 80) {
        kpiThreatTag.textContent = "Optimal Defense";
        kpiThreatTag.className = "kpi-tag kpi-tag-opt";
      } else if (fitScore >= 50) {
        kpiThreatTag.textContent = "Moderate Defense";
        kpiThreatTag.className = "kpi-tag kpi-tag-warn";
      } else {
        kpiThreatTag.textContent = "Deficient Defense";
        kpiThreatTag.className = "kpi-tag kpi-tag-crit";
      }
    }
  }
}

/* ==================== STEP 5 RESULTS DASHBOARD CONTROLLERS ==================== */

function switchResultsTab(tabId) {
  const tabBtns = document.querySelectorAll(".results-tab-btn");
  const tabPanes = document.querySelectorAll(".results-tab-pane");

  tabBtns.forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  tabPanes.forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });
}

function openTraditionalModal() {
  const modal = document.getElementById("traditionalComparisonModal");
  if (modal) modal.style.display = "flex";
}

function closeTraditionalModal() {
  const modal = document.getElementById("traditionalComparisonModal");
  if (modal) modal.style.display = "none";
}

function resetStep5ToPrecheck() {
  const precheckView = document.getElementById("step5PrecheckView");
  if (precheckView) precheckView.style.display = "block";
  const resultsView = document.getElementById("step5ResultsView");
  if (resultsView) resultsView.style.display = "none";

  const quoteCard = document.getElementById("quoteResultCard");
  if (quoteCard) quoteCard.classList.remove("active");

  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");
  if (verifyBtn) verifyBtn.style.display = "flex";

  const scanBox = document.getElementById("scanProgressBox");
  if (scanBox) scanBox.classList.remove("active");
}

function retriggerVerification() {
  resetStep5ToPrecheck();
  triggerGoogleOAuth();
}
